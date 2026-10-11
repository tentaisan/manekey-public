use super::*;

const PIN_PAGE_MAGIC: [u8; 4] = *b"PUV1";
const PIN_PAGE_FORMAT_VERSION: u8 = 1;
pub const PIN_PAGE_COMMIT_MARKER: [u8; 4] = *b"CMIT";
const PIN_PAGE_MAGIC_OFFSET: usize = 0;
const PIN_PAGE_VERSION_OFFSET: usize = 4;
const PIN_PAGE_SEQUENCE_OFFSET: usize = 8;
pub(super) const PIN_PAGE_CHECKSUM_OFFSET: usize = 12;
pub const PIN_PAGE_COMMIT_OFFSET: usize = 16;
const PIN_PAGE_HEADER_LEN: usize = 20;
const PIN_STATE_SET_OFFSET: usize = PIN_PAGE_HEADER_LEN;
const PIN_STATE_RETRIES_OFFSET: usize = PIN_PAGE_HEADER_LEN + 1;
const PIN_STATE_HASH_OFFSET: usize = PIN_PAGE_HEADER_LEN + 2;
const PIN_STATE_HASH_END: usize = PIN_STATE_HASH_OFFSET + 16;

/// Stores full pages then commits separately; adapters own durability, exclusion and confidentiality.
pub trait PinUvAuthPageBackend {
    fn read_pin_page(
        &mut self,
        page: usize,
        buf: &mut [u8; PIN_UV_AUTH_PAGE_SIZE],
    ) -> Result<(), PinStorageError>;

    fn write_pin_page(
        &mut self,
        page: usize,
        buf: &[u8; PIN_UV_AUTH_PAGE_SIZE],
    ) -> Result<(), PinStorageError>;

    fn commit_pin_page(&mut self, page: usize) -> Result<(), PinStorageError>;
}

#[derive(Clone, Copy)]
enum PinPageSource {
    Empty,
    Committed(usize),
}

struct PinPageState {
    source: PinPageSource,
    sequence: u32,
}

/// Plaintext CRC journal without rollback protection; no valid page currently loads PIN-unset state.
pub struct JournaledPinUvAuthStorage<B: PinUvAuthPageBackend> {
    pub(super) backend: B,
    page: [u8; PIN_UV_AUTH_PAGE_SIZE],
}

impl<B: PinUvAuthPageBackend> JournaledPinUvAuthStorage<B> {
    pub const fn new(backend: B) -> Self {
        Self {
            backend,
            page: [0xff; PIN_UV_AUTH_PAGE_SIZE],
        }
    }

    fn load_active_page(&mut self) -> Result<(PinPageState, PinUvAuthState), PinStorageError> {
        self.backend.read_pin_page(0, &mut self.page)?;
        let page_zero = validate_pin_page(&self.page);

        self.backend.read_pin_page(1, &mut self.page)?;
        let page_one = validate_pin_page(&self.page);

        match (page_zero, page_one) {
            (Some((sequence_zero, _)), Some((sequence_one, state_one)))
                if pin_sequence_is_newer(sequence_one, sequence_zero) =>
            {
                Ok((
                    PinPageState {
                        source: PinPageSource::Committed(1),
                        sequence: sequence_one,
                    },
                    state_one,
                ))
            }
            (Some((sequence_zero, state_zero)), _) => {
                self.backend.read_pin_page(0, &mut self.page)?;
                Ok((
                    PinPageState {
                        source: PinPageSource::Committed(0),
                        sequence: sequence_zero,
                    },
                    state_zero,
                ))
            }
            (_, Some((sequence_one, state_one))) => Ok((
                PinPageState {
                    source: PinPageSource::Committed(1),
                    sequence: sequence_one,
                },
                state_one,
            )),
            (None, None) => {
                self.page = [0xff; PIN_UV_AUTH_PAGE_SIZE];
                Ok((
                    PinPageState {
                        source: PinPageSource::Empty,
                        sequence: 0,
                    },
                    PinUvAuthState::new_unset(),
                ))
            }
        }
    }
}

impl<B: PinUvAuthPageBackend> PinUvAuthStateStorage for JournaledPinUvAuthStorage<B> {
    fn load_pin_state(&mut self) -> Result<PinUvAuthState, PinStorageError> {
        self.load_active_page().map(|(_, state)| state)
    }

    fn store_pin_state(&mut self, state: &PinUvAuthState) -> Result<(), PinStorageError> {
        let (page_state, _) = self.load_active_page()?;
        let target_page = match page_state.source {
            PinPageSource::Committed(0) => 1,
            PinPageSource::Committed(1) | PinPageSource::Empty => 0,
            PinPageSource::Committed(_) => return Err(PinStorageError::WriteFailed),
        };
        let sequence = page_state.sequence.wrapping_add(1);

        self.page = [0xff; PIN_UV_AUTH_PAGE_SIZE];
        encode_pin_state(&mut self.page, state);
        write_pin_page_header(&mut self.page, sequence);
        self.backend.write_pin_page(target_page, &self.page)?;
        self.backend.commit_pin_page(target_page)
    }
}

fn encode_pin_state(page: &mut [u8; PIN_UV_AUTH_PAGE_SIZE], state: &PinUvAuthState) {
    page[PIN_STATE_SET_OFFSET] = if state.pin_is_set() { 1 } else { 0 };
    page[PIN_STATE_RETRIES_OFFSET] = state.retries();
    if let Some(pin_hash) = state.pin_hash() {
        page[PIN_STATE_HASH_OFFSET..PIN_STATE_HASH_END].copy_from_slice(&pin_hash);
    }
}

fn decode_pin_state(page: &[u8; PIN_UV_AUTH_PAGE_SIZE]) -> Option<PinUvAuthState> {
    let retries = page[PIN_STATE_RETRIES_OFFSET];
    let pin_hash = match page[PIN_STATE_SET_OFFSET] {
        0 => None,
        1 => Some(
            page[PIN_STATE_HASH_OFFSET..PIN_STATE_HASH_END]
                .try_into()
                .expect("fixed PIN hash range"),
        ),
        _ => return None,
    };
    PinUvAuthState::from_stored(pin_hash, retries)
}

fn pin_sequence_is_newer(candidate: u32, current: u32) -> bool {
    candidate != current && candidate.wrapping_sub(current) < (1 << 31)
}

fn write_pin_page_header(page: &mut [u8; PIN_UV_AUTH_PAGE_SIZE], sequence: u32) {
    page[..PIN_PAGE_HEADER_LEN].fill(0xff);
    page[PIN_PAGE_MAGIC_OFFSET..PIN_PAGE_MAGIC_OFFSET + PIN_PAGE_MAGIC.len()]
        .copy_from_slice(&PIN_PAGE_MAGIC);
    page[PIN_PAGE_VERSION_OFFSET] = PIN_PAGE_FORMAT_VERSION;
    page[PIN_PAGE_SEQUENCE_OFFSET..PIN_PAGE_SEQUENCE_OFFSET + 4]
        .copy_from_slice(&sequence.to_be_bytes());
    let checksum = pin_page_checksum(sequence, &page[PIN_PAGE_HEADER_LEN..]);
    page[PIN_PAGE_CHECKSUM_OFFSET..PIN_PAGE_CHECKSUM_OFFSET + 4]
        .copy_from_slice(&checksum.to_be_bytes());
}

fn validate_pin_page(page: &[u8; PIN_UV_AUTH_PAGE_SIZE]) -> Option<(u32, PinUvAuthState)> {
    if page[PIN_PAGE_MAGIC_OFFSET..PIN_PAGE_MAGIC_OFFSET + PIN_PAGE_MAGIC.len()] != PIN_PAGE_MAGIC
        || page[PIN_PAGE_VERSION_OFFSET] != PIN_PAGE_FORMAT_VERSION
        || page[PIN_PAGE_COMMIT_OFFSET..PIN_PAGE_COMMIT_OFFSET + PIN_PAGE_COMMIT_MARKER.len()]
            != PIN_PAGE_COMMIT_MARKER
    {
        return None;
    }

    let sequence = u32::from_be_bytes(
        page[PIN_PAGE_SEQUENCE_OFFSET..PIN_PAGE_SEQUENCE_OFFSET + 4]
            .try_into()
            .expect("fixed PIN sequence range"),
    );
    let stored_checksum = u32::from_be_bytes(
        page[PIN_PAGE_CHECKSUM_OFFSET..PIN_PAGE_CHECKSUM_OFFSET + 4]
            .try_into()
            .expect("fixed PIN checksum range"),
    );

    (pin_page_checksum(sequence, &page[PIN_PAGE_HEADER_LEN..]) == stored_checksum)
        .then(|| decode_pin_state(page).map(|state| (sequence, state)))
        .flatten()
}

fn pin_page_checksum(sequence: u32, payload: &[u8]) -> u32 {
    let mut crc = 0xffff_ffffu32;
    crc = pin_crc32_update(crc, PIN_PAGE_FORMAT_VERSION);
    for byte in sequence.to_be_bytes() {
        crc = pin_crc32_update(crc, byte);
    }
    for &byte in payload {
        crc = pin_crc32_update(crc, byte);
    }
    !crc
}

fn pin_crc32_update(mut crc: u32, byte: u8) -> u32 {
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
