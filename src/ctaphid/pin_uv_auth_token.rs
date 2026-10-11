use super::PERMISSION_LARGE_BLOB_WRITE;

pub const PIN_UV_AUTH_TOKEN_INITIAL_USAGE_MS: u64 = 30_000;

pub const PIN_UV_AUTH_TOKEN_MAX_USAGE_MS: u64 = 600_000;

/// Monotonic milliseconds; backwards time expires active timed tokens.
pub trait PinUvAuthTokenClock {
    fn now_ms(&self) -> u64;

    fn expires_tokens(&self) -> bool {
        true
    }
}

#[derive(Clone, Copy, Debug, Default)]
/// Compatibility clock that disables token expiry.
pub struct NoPinUvAuthTokenClock;

impl PinUvAuthTokenClock for NoPinUvAuthTokenClock {
    fn now_ms(&self) -> u64 {
        0
    }

    fn expires_tokens(&self) -> bool {
        false
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
/// Contains secret bytes; Copy/Debug/token() expose copies and drop does not erase them.
pub struct PinUvAuthTokenState {
    token: [u8; 32],
    protocol: u8,
    permissions: u8,
    rp_id_hash: Option<[u8; 32]>,
    user_present: bool,
    user_verified: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct PinUvAuthTokenUsage {
    issued_at_ms: u64,
    used: bool,
}

impl PinUvAuthTokenUsage {
    pub(super) const fn new(issued_at_ms: u64) -> Self {
        Self {
            issued_at_ms,
            used: false,
        }
    }

    pub(super) fn is_expired(self, now_ms: u64) -> bool {
        let Some(elapsed_ms) = now_ms.checked_sub(self.issued_at_ms) else {
            return true;
        };
        elapsed_ms >= PIN_UV_AUTH_TOKEN_MAX_USAGE_MS
            || (!self.used && elapsed_ms >= PIN_UV_AUTH_TOKEN_INITIAL_USAGE_MS)
    }

    pub(super) fn mark_used(&mut self) {
        self.used = true;
    }
}

impl PinUvAuthTokenState {
    pub const fn new(token: [u8; 32], permissions: u8, rp_id_hash: Option<[u8; 32]>) -> Self {
        Self::new_for_protocol(1, token, permissions, rp_id_hash)
    }

    pub(super) const fn new_for_protocol(
        protocol: u8,
        token: [u8; 32],
        permissions: u8,
        rp_id_hash: Option<[u8; 32]>,
    ) -> Self {
        Self {
            token,
            protocol,
            permissions,
            rp_id_hash,
            user_present: false,
            user_verified: true,
        }
    }

    pub fn token(&self) -> [u8; 32] {
        self.token
    }

    pub fn protocol(&self) -> u8 {
        self.protocol
    }

    /// Pass one operation bit; composite masks test any bit, not all bits.
    pub fn allows(&self, permission: u8, rp_id_hash: Option<[u8; 32]>) -> bool {
        self.permissions & permission != 0
            && self
                .rp_id_hash
                .map_or(true, |stored| rp_id_hash == Some(stored))
    }

    pub fn user_present(&self) -> bool {
        self.user_present
    }

    pub fn user_verified(&self) -> bool {
        self.user_verified
    }

    pub(super) fn clear_after_user_presence_operation(&mut self) {
        self.user_present = false;
        self.user_verified = false;
        self.permissions &= PERMISSION_LARGE_BLOB_WRITE;
    }
}
