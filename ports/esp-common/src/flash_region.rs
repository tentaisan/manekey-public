use esp_bootloader_esp_idf::partitions::{PARTITION_TABLE_MAX_LEN, read_partition_table};
use esp_storage::FlashStorage;
use manekey::ctaphid::storage::{
    STORAGE_PAGE_COMMIT_MARKER, STORAGE_PAGE_COMMIT_OFFSET, StorageError,
};
use manekey::storage_region::FixedPageRegion;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EspFlashStorageSource {
    Partition,
    Fallback,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
/// Flash bounds, not ownership/authentication; board layout must reserve nonoverlapping erasable regions.
pub struct EspFlashRegion {
    pub base: u32,
    pub len: u32,
    pub source: EspFlashStorageSource,
}

impl EspFlashRegion {
    pub fn contains_range(self, offset: usize, len: usize) -> bool {
        FixedPageRegion::new(self.base as usize, 1, self.len as usize).contains_range(offset, len)
    }

    pub fn page_range(
        self,
        page: usize,
        page_size: usize,
        page_count: usize,
    ) -> Result<(u32, u32), StorageError> {
        if page_size == 0 || page_count == 0 {
            return Err(StorageError::ReadFailed);
        }
        let page_size_u32 = u32::try_from(page_size).map_err(|_| StorageError::ReadFailed)?;
        let pages = FixedPageRegion::new(self.base as usize, page_size, page_count);
        let start = pages
            .page_offset_for_len(page, page_size)
            .filter(|offset| self.contains_range(*offset, page_size))
            .ok_or(StorageError::ReadFailed)?;
        let start = u32::try_from(start).map_err(|_| StorageError::ReadFailed)?;
        let region_end = self
            .base
            .checked_add(self.len)
            .ok_or(StorageError::ReadFailed)?;
        let end = start
            .checked_add(page_size_u32)
            .filter(|end| *end <= region_end)
            .ok_or(StorageError::ReadFailed)?;
        Ok((start, end))
    }

    pub fn page_offset(
        self,
        page: usize,
        page_size: usize,
        page_count: usize,
    ) -> Result<u32, StorageError> {
        self.page_range(page, page_size, page_count)
            .map(|(start, _)| start)
    }
}

/// Missing or unreadable partition metadata selects caller-provided fallback; caller validates that layout.
pub fn find_region_or_fallback<'d>(
    flash: &mut FlashStorage<'d>,
    partition_label: &str,
    min_len: u32,
    fallback_base: u32,
    fallback_len: u32,
) -> EspFlashRegion {
    find_partition_region(flash, partition_label, min_len).unwrap_or(EspFlashRegion {
        base: fallback_base,
        len: fallback_len,
        source: EspFlashStorageSource::Fallback,
    })
}

pub fn find_partition_region<'d>(
    flash: &mut FlashStorage<'d>,
    partition_label: &str,
    min_len: u32,
) -> Option<EspFlashRegion> {
    if !crate::board::FLASH_PARTITION_PROBE_ENABLED {
        return None;
    }
    let mut table = [0u8; PARTITION_TABLE_MAX_LEN];
    let partition_table = read_partition_table(flash, &mut table).ok()?;
    let partition = partition_table
        .iter()
        .find(|entry| entry.label_as_str() == partition_label)?;
    if partition.len() < min_len || partition.is_read_only() {
        return None;
    }
    Some(EspFlashRegion {
        base: partition.offset(),
        len: partition.len(),
        source: EspFlashStorageSource::Partition,
    })
}

pub fn page_offset(
    region: EspFlashRegion,
    page: usize,
    page_size: usize,
    page_count: usize,
) -> Result<u32, StorageError> {
    region.page_offset(page, page_size, page_count)
}

pub fn read_page<'d, const PAGE_SIZE: usize, const PAGE_COUNT: usize>(
    flash: &mut FlashStorage<'d>,
    region: EspFlashRegion,
    page: usize,
    buf: &mut [u8; PAGE_SIZE],
) -> Result<(), StorageError> {
    flash
        .read(region.page_offset(page, PAGE_SIZE, PAGE_COUNT)?, buf)
        .map_err(|_| StorageError::ReadFailed)
}

pub fn write_page<'d, const PAGE_SIZE: usize, const PAGE_COUNT: usize>(
    flash: &mut FlashStorage<'d>,
    region: EspFlashRegion,
    page: usize,
    buf: &[u8; PAGE_SIZE],
) -> Result<(), StorageError> {
    let (start, end) = region
        .page_range(page, PAGE_SIZE, PAGE_COUNT)
        .map_err(|_| StorageError::WriteFailed)?;
    flash
        .erase(start, end)
        .map_err(|_| StorageError::WriteFailed)?;
    flash
        .write(start, buf)
        .map_err(|_| StorageError::WriteFailed)
}

/// Writes a separate commit marker, not a power-loss durability guarantee.
pub fn commit_page<'d, const PAGE_SIZE: usize, const PAGE_COUNT: usize>(
    flash: &mut FlashStorage<'d>,
    region: EspFlashRegion,
    page: usize,
) -> Result<(), StorageError> {
    STORAGE_PAGE_COMMIT_OFFSET
        .checked_add(STORAGE_PAGE_COMMIT_MARKER.len())
        .filter(|end| *end <= PAGE_SIZE)
        .ok_or(StorageError::WriteFailed)?;
    let (start, _) = region
        .page_range(page, PAGE_SIZE, PAGE_COUNT)
        .map_err(|_| StorageError::WriteFailed)?;
    let marker_offset = start
        .checked_add(
            u32::try_from(STORAGE_PAGE_COMMIT_OFFSET).map_err(|_| StorageError::WriteFailed)?,
        )
        .ok_or(StorageError::WriteFailed)?;
    flash
        .write(marker_offset, &STORAGE_PAGE_COMMIT_MARKER)
        .map_err(|_| StorageError::WriteFailed)
}

/// Erases caller-owned region length; not a physical secure-erasure guarantee.
pub fn clear_region<'d>(
    flash: &mut FlashStorage<'d>,
    region: EspFlashRegion,
    len: u32,
) -> Result<(), StorageError> {
    if len > region.len {
        return Err(StorageError::WriteFailed);
    }
    let end = region
        .base
        .checked_add(len)
        .ok_or(StorageError::WriteFailed)?;
    flash
        .erase(region.base, end)
        .map_err(|_| StorageError::WriteFailed)
}
