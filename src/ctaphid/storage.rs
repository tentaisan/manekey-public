use crate::ctaphid::credential::{CredentialRecord, RECORD_LEN, V5_RECORD_LEN, V6_RECORD_LEN};

pub const FLASH_SECTOR_SIZE: usize = if cfg!(feature = "storage-page-1k") {
    1024
} else {
    4096
};

pub const STORAGE_PAGE_COUNT: usize = 2;

const PAGE_MAGIC: [u8; 4] = *b"FDS2";
const PAGE_FORMAT_VERSION: u8 = 7;
const V6_PAGE_FORMAT_VERSION: u8 = 6;
const V5_PAGE_FORMAT_VERSION: u8 = 5;
const PAGE_MAGIC_OFFSET: usize = 0;
const PAGE_VERSION_OFFSET: usize = 4;
const PAGE_SEQUENCE_OFFSET: usize = 8;
const PAGE_CHECKSUM_OFFSET: usize = 12;
const PAGE_HEADER_LEN: usize = 20;

pub const STORAGE_PAGE_COMMIT_MARKER: [u8; 4] = *b"CMIT";

pub const STORAGE_PAGE_COMMIT_OFFSET: usize = 16;

/// Marks bytes in memory only; does not validate a page or establish durable persistence.
pub fn mark_storage_page_committed(page: &mut [u8]) -> Result<(), StorageError> {
    let end = STORAGE_PAGE_COMMIT_OFFSET
        .checked_add(STORAGE_PAGE_COMMIT_MARKER.len())
        .ok_or(StorageError::WriteFailed)?;
    let marker = page
        .get_mut(STORAGE_PAGE_COMMIT_OFFSET..end)
        .ok_or(StorageError::WriteFailed)?;
    marker.copy_from_slice(&STORAGE_PAGE_COMMIT_MARKER);
    Ok(())
}

const PAGE_COMMIT_MARKER: [u8; 4] = STORAGE_PAGE_COMMIT_MARKER;
const PAGE_COMMIT_OFFSET: usize = STORAGE_PAGE_COMMIT_OFFSET;

pub const MAX_RECORDS: usize = (FLASH_SECTOR_SIZE - PAGE_HEADER_LEN) / RECORD_LEN;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StorageError {
    ReadFailed,

    WriteFailed,
}

/// Page media contract; adapters own write/commit ordering, durability, exclusion and protection.
pub trait StorageBackend {
    fn read_page(
        &mut self,
        page: usize,
        buf: &mut [u8; FLASH_SECTOR_SIZE],
    ) -> Result<(), StorageError>;

    fn write_page(
        &mut self,
        page: usize,
        buf: &[u8; FLASH_SECTOR_SIZE],
    ) -> Result<(), StorageError>;

    fn commit_page(&mut self, page: usize) -> Result<(), StorageError>;

    fn clear_pages(&mut self) -> Result<(), StorageError>;
}

/// RAM-only pages without persistence or hardware credential isolation.
pub struct StubStorage {
    pages: [[u8; FLASH_SECTOR_SIZE]; STORAGE_PAGE_COUNT],
}

impl StubStorage {
    pub const fn new() -> Self {
        Self {
            pages: [[0xff; FLASH_SECTOR_SIZE]; STORAGE_PAGE_COUNT],
        }
    }
}

impl StorageBackend for StubStorage {
    fn read_page(
        &mut self,
        page: usize,
        buf: &mut [u8; FLASH_SECTOR_SIZE],
    ) -> Result<(), StorageError> {
        let source = self.pages.get(page).ok_or(StorageError::ReadFailed)?;
        buf.copy_from_slice(source);
        Ok(())
    }

    fn write_page(
        &mut self,
        page: usize,
        buf: &[u8; FLASH_SECTOR_SIZE],
    ) -> Result<(), StorageError> {
        let target = self.pages.get_mut(page).ok_or(StorageError::WriteFailed)?;
        *target = [0xff; FLASH_SECTOR_SIZE];

        target.copy_from_slice(buf);
        Ok(())
    }

    fn commit_page(&mut self, page: usize) -> Result<(), StorageError> {
        let target = self.pages.get_mut(page).ok_or(StorageError::WriteFailed)?;
        mark_storage_page_committed(target)
    }

    fn clear_pages(&mut self) -> Result<(), StorageError> {
        self.pages = [[0xff; FLASH_SECTOR_SIZE]; STORAGE_PAGE_COUNT];
        Ok(())
    }
}

#[derive(Clone, Copy)]
enum PageSource {
    Empty,
    LegacyV5,
    PreviousCommitted(usize),
    Committed(usize),
}

struct PageState {
    source: PageSource,
    sequence: u32,
}

/// Plaintext CRC journal with legacy decoding; no inherent authentication or rollback protection.
pub struct Storage<B: StorageBackend> {
    backend: B,
    page: [u8; FLASH_SECTOR_SIZE],
}

impl<B: StorageBackend> Storage<B> {
    pub const fn new(backend: B) -> Self {
        Self {
            backend,
            page: [0xff; FLASH_SECTOR_SIZE],
        }
    }

    /// Convenience lookup; absence, invalid records and storage errors all return None.
    pub fn load_record(&mut self, index: usize) -> Option<CredentialRecord> {
        if index >= MAX_RECORDS {
            return None;
        }

        self.load_active_page().ok()?;
        CredentialRecord::decode(self.record_bytes(index))
    }

    /// Returns storage errors separately instead of collapsing them to None.
    pub fn load_record_checked(
        &mut self,
        index: usize,
    ) -> Result<Option<CredentialRecord>, StorageError> {
        if index >= MAX_RECORDS {
            return Err(StorageError::ReadFailed);
        }
        let state = self.load_active_page()?;
        if matches!(state.source, PageSource::Empty) {
            for page in 0..STORAGE_PAGE_COUNT {
                self.backend.read_page(page, &mut self.page)?;
                if self.page.iter().any(|byte| *byte != 0xff) {
                    return Err(StorageError::ReadFailed);
                }
            }
            return Ok(None);
        }
        let bytes = self.record_bytes(index);
        let record = CredentialRecord::decode(bytes);
        if record.is_none() && bytes.iter().any(|byte| *byte != 0xff) {
            return Err(StorageError::ReadFailed);
        }
        Ok(record)
    }

    pub fn save_record(
        &mut self,
        index: usize,
        record: &CredentialRecord,
    ) -> Result<(), StorageError> {
        if index >= MAX_RECORDS {
            return Err(StorageError::WriteFailed);
        }

        let state = self.load_active_page()?;
        record.encode(self.record_bytes_mut(index));

        self.commit_page(state)
    }

    pub fn delete_record(&mut self, index: usize) -> Result<bool, StorageError> {
        if index >= MAX_RECORDS {
            return Err(StorageError::WriteFailed);
        }

        let state = self.load_active_page()?;
        if CredentialRecord::decode(self.record_bytes(index)).is_none() {
            return Ok(false);
        }
        self.record_bytes_mut(index).fill(0xff);

        self.commit_page(state)?;
        Ok(true)
    }

    fn commit_page(&mut self, state: PageState) -> Result<(), StorageError> {
        let target_page = match state.source {
            PageSource::Committed(0) => 1,
            PageSource::Committed(1)
            | PageSource::PreviousCommitted(1)
            | PageSource::Empty
            | PageSource::LegacyV5 => 0,
            PageSource::PreviousCommitted(0) => 1,
            PageSource::Committed(_) => return Err(StorageError::WriteFailed),
            PageSource::PreviousCommitted(_) => return Err(StorageError::WriteFailed),
        };
        let sequence = state.sequence.wrapping_add(1);

        write_page_header(&mut self.page, sequence);
        self.backend.write_page(target_page, &self.page)?;
        self.backend.commit_page(target_page)?;

        Ok(())
    }

    pub fn first_empty_record_index(&mut self) -> Option<usize> {
        for index in 0..MAX_RECORDS {
            if self.load_record(index).is_none() {
                return Some(index);
            }
        }

        None
    }

    /// Clears through the backend; this is not a physical secure-erase guarantee.
    pub fn debug_clear(&mut self) -> Result<(), StorageError> {
        self.backend.clear_pages()?;
        self.page = [0xff; FLASH_SECTOR_SIZE];
        Ok(())
    }

    fn load_active_page(&mut self) -> Result<PageState, StorageError> {
        self.backend.read_page(0, &mut self.page)?;
        let page_zero = validate_page(&self.page);
        let v6_page_zero = validate_v6_page(&self.page);
        let v5_page_zero = validate_v5_page(&self.page);

        self.backend.read_page(1, &mut self.page)?;
        let page_one = validate_page(&self.page);
        let v6_page_one = validate_v6_page(&self.page);
        let v5_page_one = validate_v5_page(&self.page);

        let current = match (page_zero, page_one) {
            (Some(sequence_zero), Some(sequence_one))
                if sequence_is_newer(sequence_one, sequence_zero) =>
            {
                Some(PageState {
                    source: PageSource::Committed(1),
                    sequence: sequence_one,
                })
            }
            (Some(sequence_zero), _) => {
                self.backend.read_page(0, &mut self.page)?;
                Some(PageState {
                    source: PageSource::Committed(0),
                    sequence: sequence_zero,
                })
            }
            (_, Some(sequence_one)) => Some(PageState {
                source: PageSource::Committed(1),
                sequence: sequence_one,
            }),
            (None, None) => None,
        };
        if let Some(state) = current {
            return Ok(state);
        }

        let v6 = newest_page(v6_page_zero, v6_page_one);
        if let Some((page, sequence)) = v6 {
            self.backend.read_page(page, &mut self.page)?;
            self.migrate_v6_records(PAGE_HEADER_LEN)?;
            return Ok(PageState {
                source: PageSource::PreviousCommitted(page),
                sequence,
            });
        }

        let v5 = match (v5_page_zero, v5_page_one) {
            (Some(sequence_zero), Some(sequence_one))
                if sequence_is_newer(sequence_one, sequence_zero) =>
            {
                Some((1, sequence_one))
            }
            (Some(sequence_zero), _) => Some((0, sequence_zero)),
            (_, Some(sequence_one)) => Some((1, sequence_one)),
            (None, None) => None,
        };
        if let Some((page, sequence)) = v5 {
            self.backend.read_page(page, &mut self.page)?;
            self.migrate_v5_records(PAGE_HEADER_LEN)?;
            return Ok(PageState {
                source: PageSource::PreviousCommitted(page),
                sequence,
            });
        }

        if is_v5_legacy_page(&self.page) {
            self.migrate_v5_records(0)?;
            return Ok(PageState {
                source: PageSource::LegacyV5,
                sequence: 0,
            });
        }

        self.page = [0xff; FLASH_SECTOR_SIZE];
        Ok(PageState {
            source: PageSource::Empty,
            sequence: 0,
        })
    }

    fn migrate_v5_records(&mut self, source_offset: usize) -> Result<(), StorageError> {
        let legacy_slots = (FLASH_SECTOR_SIZE - source_offset) / V5_RECORD_LEN;
        for index in MAX_RECORDS..legacy_slots {
            let start = source_offset + index * V5_RECORD_LEN;
            let legacy: &[u8; V5_RECORD_LEN] = self.page[start..start + V5_RECORD_LEN]
                .try_into()
                .expect("legacy record is within one storage page");
            if CredentialRecord::decode_v5(legacy).is_some() {
                return Err(StorageError::ReadFailed);
            }
        }

        for index in (0..MAX_RECORDS).rev() {
            let start = source_offset + index * V5_RECORD_LEN;
            let mut encoded = [0u8; V5_RECORD_LEN];
            encoded.copy_from_slice(&self.page[start..start + V5_RECORD_LEN]);
            let record = CredentialRecord::decode_v5(&encoded);
            self.record_bytes_mut(index).fill(0xff);
            if let Some(record) = record {
                record.encode(self.record_bytes_mut(index));
            }
        }
        let used_end = record_offset(MAX_RECORDS);
        self.page[used_end..].fill(0xff);
        self.page[..PAGE_HEADER_LEN].fill(0xff);
        Ok(())
    }

    fn migrate_v6_records(&mut self, source_offset: usize) -> Result<(), StorageError> {
        for index in (0..MAX_RECORDS).rev() {
            let start = source_offset + index * V6_RECORD_LEN;
            let mut encoded = [0u8; V6_RECORD_LEN];
            encoded.copy_from_slice(&self.page[start..start + V6_RECORD_LEN]);
            let record = CredentialRecord::decode_v6(&encoded);
            self.record_bytes_mut(index).fill(0xff);
            if let Some(record) = record {
                record.encode(self.record_bytes_mut(index));
            }
        }
        let used_end = record_offset(MAX_RECORDS);
        self.page[used_end..].fill(0xff);
        self.page[..PAGE_HEADER_LEN].fill(0xff);
        Ok(())
    }

    fn record_bytes(&self, index: usize) -> &[u8; RECORD_LEN] {
        self.page[record_offset(index)..record_offset(index) + RECORD_LEN]
            .try_into()
            .expect("record offset is bounded by MAX_RECORDS")
    }

    fn record_bytes_mut(&mut self, index: usize) -> &mut [u8; RECORD_LEN] {
        (&mut self.page[record_offset(index)..record_offset(index) + RECORD_LEN])
            .try_into()
            .expect("record offset is bounded by MAX_RECORDS")
    }
}

fn record_offset(index: usize) -> usize {
    PAGE_HEADER_LEN + index * RECORD_LEN
}

fn sequence_is_newer(candidate: u32, current: u32) -> bool {
    candidate != current && candidate.wrapping_sub(current) < (1 << 31)
}

fn newest_page(page_zero: Option<u32>, page_one: Option<u32>) -> Option<(usize, u32)> {
    match (page_zero, page_one) {
        (Some(sequence_zero), Some(sequence_one))
            if sequence_is_newer(sequence_one, sequence_zero) =>
        {
            Some((1, sequence_one))
        }
        (Some(sequence_zero), _) => Some((0, sequence_zero)),
        (_, Some(sequence_one)) => Some((1, sequence_one)),
        (None, None) => None,
    }
}

fn write_page_header(page: &mut [u8; FLASH_SECTOR_SIZE], sequence: u32) {
    page[..PAGE_HEADER_LEN].fill(0xff);
    page[PAGE_MAGIC_OFFSET..PAGE_MAGIC_OFFSET + PAGE_MAGIC.len()].copy_from_slice(&PAGE_MAGIC);
    page[PAGE_VERSION_OFFSET] = PAGE_FORMAT_VERSION;
    page[PAGE_SEQUENCE_OFFSET..PAGE_SEQUENCE_OFFSET + 4].copy_from_slice(&sequence.to_be_bytes());
    let checksum = page_checksum(sequence, &page[PAGE_HEADER_LEN..]);
    page[PAGE_CHECKSUM_OFFSET..PAGE_CHECKSUM_OFFSET + 4].copy_from_slice(&checksum.to_be_bytes());
}

fn validate_page(page: &[u8; FLASH_SECTOR_SIZE]) -> Option<u32> {
    validate_page_version(page, PAGE_FORMAT_VERSION)
}

fn validate_v6_page(page: &[u8; FLASH_SECTOR_SIZE]) -> Option<u32> {
    validate_page_version(page, V6_PAGE_FORMAT_VERSION)
}

fn validate_v5_page(page: &[u8; FLASH_SECTOR_SIZE]) -> Option<u32> {
    validate_page_version(page, V5_PAGE_FORMAT_VERSION)
}

fn validate_page_version(page: &[u8; FLASH_SECTOR_SIZE], version: u8) -> Option<u32> {
    if page[PAGE_MAGIC_OFFSET..PAGE_MAGIC_OFFSET + PAGE_MAGIC.len()] != PAGE_MAGIC
        || page[PAGE_VERSION_OFFSET] != version
        || page[PAGE_COMMIT_OFFSET..PAGE_COMMIT_OFFSET + PAGE_COMMIT_MARKER.len()]
            != PAGE_COMMIT_MARKER
    {
        return None;
    }

    let sequence = u32::from_be_bytes(
        page[PAGE_SEQUENCE_OFFSET..PAGE_SEQUENCE_OFFSET + 4]
            .try_into()
            .expect("fixed sequence range"),
    );
    let stored_checksum = u32::from_be_bytes(
        page[PAGE_CHECKSUM_OFFSET..PAGE_CHECKSUM_OFFSET + 4]
            .try_into()
            .expect("fixed checksum range"),
    );

    (page_checksum_for_version(version, sequence, &page[PAGE_HEADER_LEN..]) == stored_checksum)
        .then_some(sequence)
}

fn is_v5_legacy_page(page: &[u8; FLASH_SECTOR_SIZE]) -> bool {
    CredentialRecord::decode_v5(
        page[..V5_RECORD_LEN]
            .try_into()
            .expect("legacy record-sized prefix"),
    )
    .is_some()
}

fn page_checksum(sequence: u32, payload: &[u8]) -> u32 {
    page_checksum_for_version(PAGE_FORMAT_VERSION, sequence, payload)
}

fn page_checksum_for_version(version: u8, sequence: u32, payload: &[u8]) -> u32 {
    let mut crc = 0xffff_ffffu32;
    crc = crc32_update(crc, version);
    for byte in sequence.to_be_bytes() {
        crc = crc32_update(crc, byte);
    }
    for &byte in payload {
        crc = crc32_update(crc, byte);
    }
    !crc
}

fn crc32_update(mut crc: u32, byte: u8) -> u32 {
    crc ^= byte as u32;
    for _ in 0..8 {
        crc = if crc & 1 == 0 {
            crc >> 1
        } else {
            (crc >> 1) ^ 0xedb8_8320
        };
    }
    crc
}

pub type DefaultStorage = Storage<StubStorage>;

impl DefaultStorage {
    pub fn stub() -> Self {
        Self::new(StubStorage::new())
    }
}
