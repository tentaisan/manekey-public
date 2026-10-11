use super::PIN_RETRIES_MAX;

pub const COMPACT_PIN_UV_AUTH_SLOT_SIZE: usize = 256;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
/// Contains a PIN verifier; Copy/Debug can expose it and drop does not erase it.
pub struct PinUvAuthState {
    pin_hash: Option<[u8; 16]>,
    retries: u8,
}

impl PinUvAuthState {
    pub const fn new_unset() -> Self {
        Self {
            pin_hash: None,
            retries: PIN_RETRIES_MAX,
        }
    }

    pub(super) const fn from_stored(pin_hash: Option<[u8; 16]>, retries: u8) -> Option<Self> {
        if retries > PIN_RETRIES_MAX {
            return None;
        }
        Some(Self { pin_hash, retries })
    }

    pub fn pin_is_set(&self) -> bool {
        self.pin_hash.is_some()
    }

    pub fn retries(&self) -> u8 {
        self.retries
    }

    pub fn set_pin_hash(&mut self, pin_hash: [u8; 16]) {
        self.pin_hash = Some(pin_hash);
        self.retries = PIN_RETRIES_MAX;
    }

    pub fn decrement_retries(&mut self) {
        self.retries = self.retries.saturating_sub(1);
    }

    pub fn reset_retries(&mut self) {
        self.retries = PIN_RETRIES_MAX;
    }

    pub fn pin_hash(&self) -> Option<[u8; 16]> {
        self.pin_hash
    }
}

/// Plaintext compact PIN slot with CRC/commit metadata, not authentication or rollback protection.
pub struct CompactPinUvAuthSlot;

impl CompactPinUvAuthSlot {
    const MAGIC: [u8; 4] = *b"PUV2";
    const COMMIT_MARKER: [u8; 4] = *b"CMIT";
    const FORMAT_VERSION: u8 = 1;
    const MAGIC_OFFSET: usize = 0;
    const VERSION_OFFSET: usize = 4;
    const PIN_SET_OFFSET: usize = 5;
    const RETRIES_OFFSET: usize = 6;
    const SEQUENCE_OFFSET: usize = 8;
    const HASH_OFFSET: usize = 12;
    const HASH_END: usize = Self::HASH_OFFSET + 16;
    const CHECKSUM_OFFSET: usize = 28;
    const COMMIT_OFFSET: usize = 32;

    pub fn encode(
        slot: &mut [u8; COMPACT_PIN_UV_AUTH_SLOT_SIZE],
        sequence: u32,
        state: &PinUvAuthState,
    ) {
        *slot = [0xff; COMPACT_PIN_UV_AUTH_SLOT_SIZE];
        slot[Self::MAGIC_OFFSET..Self::MAGIC_OFFSET + Self::MAGIC.len()]
            .copy_from_slice(&Self::MAGIC);
        slot[Self::VERSION_OFFSET] = Self::FORMAT_VERSION;
        slot[Self::PIN_SET_OFFSET] = u8::from(state.pin_is_set());
        slot[Self::RETRIES_OFFSET] = state.retries();
        slot[Self::SEQUENCE_OFFSET..Self::SEQUENCE_OFFSET + 4]
            .copy_from_slice(&sequence.to_be_bytes());
        if let Some(pin_hash) = state.pin_hash() {
            slot[Self::HASH_OFFSET..Self::HASH_END].copy_from_slice(&pin_hash);
        }
        let checksum = Self::checksum(sequence, &slot[..Self::CHECKSUM_OFFSET]);
        slot[Self::CHECKSUM_OFFSET..Self::CHECKSUM_OFFSET + 4]
            .copy_from_slice(&checksum.to_be_bytes());
        slot[Self::COMMIT_OFFSET..Self::COMMIT_OFFSET + Self::COMMIT_MARKER.len()]
            .copy_from_slice(&Self::COMMIT_MARKER);
    }

    pub fn decode(slot: &[u8; COMPACT_PIN_UV_AUTH_SLOT_SIZE]) -> Option<(u32, PinUvAuthState)> {
        if slot[Self::MAGIC_OFFSET..Self::MAGIC_OFFSET + Self::MAGIC.len()] != Self::MAGIC
            || slot[Self::VERSION_OFFSET] != Self::FORMAT_VERSION
            || slot[Self::COMMIT_OFFSET..Self::COMMIT_OFFSET + Self::COMMIT_MARKER.len()]
                != Self::COMMIT_MARKER
        {
            return None;
        }

        let sequence = u32::from_be_bytes(
            slot[Self::SEQUENCE_OFFSET..Self::SEQUENCE_OFFSET + 4]
                .try_into()
                .ok()?,
        );
        let stored_checksum = u32::from_be_bytes(
            slot[Self::CHECKSUM_OFFSET..Self::CHECKSUM_OFFSET + 4]
                .try_into()
                .ok()?,
        );
        if stored_checksum != Self::checksum(sequence, &slot[..Self::CHECKSUM_OFFSET]) {
            return None;
        }

        let pin_hash = match slot[Self::PIN_SET_OFFSET] {
            0 => None,
            1 => Some(slot[Self::HASH_OFFSET..Self::HASH_END].try_into().ok()?),
            _ => return None,
        };
        PinUvAuthState::from_stored(pin_hash, slot[Self::RETRIES_OFFSET])
            .map(|state| (sequence, state))
    }

    pub fn newest(
        first: &[u8; COMPACT_PIN_UV_AUTH_SLOT_SIZE],
        second: &[u8; COMPACT_PIN_UV_AUTH_SLOT_SIZE],
    ) -> Option<(usize, u32, PinUvAuthState)> {
        let first = Self::decode(first);
        let second = Self::decode(second);
        match (first, second) {
            (Some((first_sequence, _)), Some((second_sequence, second_state)))
                if second_sequence != first_sequence
                    && second_sequence.wrapping_sub(first_sequence) < (1 << 31) =>
            {
                Some((1, second_sequence, second_state))
            }
            (Some((sequence, state)), _) => Some((0, sequence, state)),
            (_, Some((sequence, state))) => Some((1, sequence, state)),
            (None, None) => None,
        }
    }

    fn checksum(sequence: u32, bytes: &[u8]) -> u32 {
        let mut crc = 0xffff_ffffu32;
        crc = Self::crc32_update(crc, Self::FORMAT_VERSION);
        for byte in sequence.to_be_bytes() {
            crc = Self::crc32_update(crc, byte);
        }
        for &byte in bytes {
            crc = Self::crc32_update(crc, byte);
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
}
