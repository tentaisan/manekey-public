use super::crypto::{ClientPinCrypto, SoftwareClientPinCrypto};
use subtle::ConstantTimeEq;

pub(crate) fn with_client_pin_crypto<A: PinUvAuthProvider, R>(
    provider: &mut A,
    operation: impl FnOnce(&mut dyn ClientPinCrypto) -> R,
) -> R {
    let mut software = SoftwareClientPinCrypto;
    operation(provider.client_pin_crypto().unwrap_or(&mut software))
}

pub const PIN_RETRIES_MAX: u8 = 8;

pub const PIN_CONSECUTIVE_MISMATCHES_MAX: u8 = 3;

#[path = "pin_uv_auth_token.rs"]
mod token;
pub use token::*;

#[path = "pin_uv_auth_state.rs"]
mod state;
pub use state::*;

pub const PERMISSION_MAKE_CREDENTIAL: u8 = 0x01;

pub const PERMISSION_GET_ASSERTION: u8 = 0x02;

pub const PERMISSION_CREDENTIAL_MANAGEMENT: u8 = 0x04;

pub const PERMISSION_LARGE_BLOB_WRITE: u8 = 0x10;

pub const DEFAULT_PIN_UV_AUTH_TOKEN_PERMISSIONS: u8 =
    PERMISSION_MAKE_CREDENTIAL | PERMISSION_GET_ASSERTION;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PinVerification {
    Matched,

    Mismatched,

    AuthBlocked,

    Blocked,
}

/// Stores sensitive verifier/retry state; adapters own persistence, confidentiality and rollback policy.
pub trait PinUvAuthStateStorage {
    fn load_pin_state(&mut self) -> Result<PinUvAuthState, PinStorageError>;

    fn store_pin_state(&mut self, state: &PinUvAuthState) -> Result<(), PinStorageError>;
}

/// RAM-only PIN state, lost on restart; not persistent PIN protection.
pub struct VolatilePinUvAuthStorage {
    state: PinUvAuthState,
}

impl VolatilePinUvAuthStorage {
    pub const fn new() -> Self {
        Self {
            state: PinUvAuthState::new_unset(),
        }
    }
}

impl PinUvAuthStateStorage for VolatilePinUvAuthStorage {
    fn load_pin_state(&mut self) -> Result<PinUvAuthState, PinStorageError> {
        Ok(self.state)
    }

    fn store_pin_state(&mut self, state: &PinUvAuthState) -> Result<(), PinStorageError> {
        self.state = *state;
        Ok(())
    }
}

pub const PIN_UV_AUTH_PAGE_SIZE: usize = super::storage::FLASH_SECTOR_SIZE;

#[path = "pin_uv_auth_storage.rs"]
mod storage;

pub use storage::*;

/// PIN state/token provider; absent client_pin_crypto selects the software compatibility backend.
pub trait PinUvAuthProvider {
    fn client_pin_crypto(&mut self) -> Option<&mut dyn ClientPinCrypto> {
        None
    }

    fn supported_pin_protocols(&self) -> &'static [u8] {
        if self.supports_pin_setting() {
            &[1]
        } else {
            &[]
        }
    }

    fn pin_retries(&mut self) -> u8;

    fn store_key_agreement_private_key(&mut self, private_key: [u8; 32]);

    fn take_key_agreement_private_key(&mut self) -> Option<[u8; 32]>;

    fn store_backend_owned_key_agreement(&mut self);

    fn take_backend_owned_key_agreement(&mut self) -> bool;

    fn supports_pin_setting(&self) -> bool;

    fn pin_is_set(&mut self) -> bool;

    fn store_pin_hash(&mut self, pin_hash: [u8; 16]) -> Result<(), PinStorageError>;

    fn verify_pin_hash(&mut self, pin_hash: &[u8; 16]) -> Result<PinVerification, PinStorageError>;

    fn pin_uv_auth_token_state(&mut self) -> Option<PinUvAuthTokenState>;

    fn pin_uv_auth_token_state_for_protocol(
        &mut self,
        protocol: u8,
    ) -> Option<PinUvAuthTokenState> {
        self.pin_uv_auth_token_state()
            .filter(|state| state.protocol() == protocol)
    }

    fn pin_uv_auth_token_expired(&mut self, _protocol: u8) -> bool {
        false
    }

    fn mark_pin_uv_auth_token_used(&mut self, _protocol: u8) -> bool {
        true
    }

    fn clear_pin_uv_auth_token_after_user_presence(&mut self, _protocol: u8) {}

    fn store_pin_uv_auth_token(
        &mut self,
        token: [u8; 32],
        permissions: u8,
        rp_id_hash: Option<[u8; 32]>,
    );

    fn store_pin_uv_auth_token_for_protocol(
        &mut self,
        protocol: u8,
        token: [u8; 32],
        permissions: u8,
        rp_id_hash: Option<[u8; 32]>,
    ) -> Result<(), PinStorageError> {
        if protocol != 1 {
            return Err(PinStorageError::Unsupported);
        }
        self.store_pin_uv_auth_token(token, permissions, rp_id_hash);
        Ok(())
    }

    fn reset_pin_uv_auth_state(&mut self) -> Result<(), PinStorageError>;
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PinStorageError {
    Unsupported,

    ReadFailed,

    WriteFailed,
}

/// Validate saved state at startup; boolean PIN metadata cannot report storage-read errors.
/// Constructors without a token clock disable expiry. Reset does not guarantee secret-copy erasure.
pub struct StoredPinUvAuthProvider<
    S: PinUvAuthStateStorage,
    C: ClientPinCrypto = SoftwareClientPinCrypto,
    K: PinUvAuthTokenClock = NoPinUvAuthTokenClock,
> {
    storage: S,
    crypto: C,
    token_clock: K,
    key_agreement_private_key: Option<[u8; 32]>,
    backend_owned_key_agreement: bool,
    pin_uv_auth_token: [Option<PinUvAuthTokenState>; 2],
    pin_uv_auth_token_usage: [Option<PinUvAuthTokenUsage>; 2],
    consecutive_pin_mismatches: u8,
}

impl<S: PinUvAuthStateStorage> StoredPinUvAuthProvider<S> {
    pub const fn new(storage: S) -> Self {
        Self::new_with_crypto_and_clock(storage, SoftwareClientPinCrypto, NoPinUvAuthTokenClock)
    }
}

impl<S: PinUvAuthStateStorage, C: ClientPinCrypto> StoredPinUvAuthProvider<S, C> {
    pub const fn new_with_crypto(storage: S, crypto: C) -> Self {
        Self::new_with_crypto_and_clock(storage, crypto, NoPinUvAuthTokenClock)
    }
}

impl<S: PinUvAuthStateStorage, K: PinUvAuthTokenClock>
    StoredPinUvAuthProvider<S, SoftwareClientPinCrypto, K>
{
    pub const fn new_with_clock(storage: S, token_clock: K) -> Self {
        Self::new_with_crypto_and_clock(storage, SoftwareClientPinCrypto, token_clock)
    }
}

impl<S: PinUvAuthStateStorage, C: ClientPinCrypto, K: PinUvAuthTokenClock>
    StoredPinUvAuthProvider<S, C, K>
{
    pub const fn new_with_crypto_and_clock(storage: S, crypto: C, token_clock: K) -> Self {
        Self {
            storage,
            crypto,
            token_clock,
            key_agreement_private_key: None,
            backend_owned_key_agreement: false,
            pin_uv_auth_token: [None; 2],
            pin_uv_auth_token_usage: [None; 2],
            consecutive_pin_mismatches: 0,
        }
    }

    pub fn storage_mut(&mut self) -> &mut S {
        &mut self.storage
    }

    fn token_index(protocol: u8) -> Option<usize> {
        protocol
            .checked_sub(1)
            .map(usize::from)
            .filter(|&index| index < 2)
    }

    fn expire_token_if_needed(&mut self, index: usize) -> bool {
        if !self.token_clock.expires_tokens() {
            return false;
        }
        let expired = self.pin_uv_auth_token_usage[index]
            .is_some_and(|usage| usage.is_expired(self.token_clock.now_ms()));
        if expired {
            self.pin_uv_auth_token[index] = None;
        }
        expired
    }

    fn store_token(
        &mut self,
        protocol: u8,
        state: PinUvAuthTokenState,
    ) -> Result<(), PinStorageError> {
        let index = Self::token_index(protocol).ok_or(PinStorageError::Unsupported)?;
        self.pin_uv_auth_token[index] = Some(state);
        self.pin_uv_auth_token_usage[index] =
            Some(PinUvAuthTokenUsage::new(self.token_clock.now_ms()));
        Ok(())
    }
}

impl<S: PinUvAuthStateStorage, C: ClientPinCrypto, K: PinUvAuthTokenClock> PinUvAuthProvider
    for StoredPinUvAuthProvider<S, C, K>
{
    fn client_pin_crypto(&mut self) -> Option<&mut dyn ClientPinCrypto> {
        Some(&mut self.crypto)
    }
    fn pin_retries(&mut self) -> u8 {
        self.storage
            .load_pin_state()
            .map_or(0, |state| state.retries())
    }

    fn store_key_agreement_private_key(&mut self, private_key: [u8; 32]) {
        self.key_agreement_private_key = Some(private_key);
        self.backend_owned_key_agreement = false;
    }

    fn take_key_agreement_private_key(&mut self) -> Option<[u8; 32]> {
        self.key_agreement_private_key.take()
    }

    fn store_backend_owned_key_agreement(&mut self) {
        self.key_agreement_private_key = None;
        self.backend_owned_key_agreement = true;
    }

    fn take_backend_owned_key_agreement(&mut self) -> bool {
        core::mem::take(&mut self.backend_owned_key_agreement)
    }

    fn supported_pin_protocols(&self) -> &'static [u8] {
        &[1, 2]
    }

    fn supports_pin_setting(&self) -> bool {
        true
    }

    fn pin_is_set(&mut self) -> bool {
        self.storage
            .load_pin_state()
            .is_ok_and(|state| state.pin_is_set())
    }

    fn store_pin_hash(&mut self, pin_hash: [u8; 16]) -> Result<(), PinStorageError> {
        let mut state = self.storage.load_pin_state()?;
        state.set_pin_hash(pin_hash);
        self.storage.store_pin_state(&state)?;
        self.pin_uv_auth_token = [None; 2];
        self.pin_uv_auth_token_usage = [None; 2];
        self.consecutive_pin_mismatches = 0;
        Ok(())
    }

    fn verify_pin_hash(&mut self, pin_hash: &[u8; 16]) -> Result<PinVerification, PinStorageError> {
        let mut state = self.storage.load_pin_state()?;
        if state.retries() == 0 {
            return Ok(PinVerification::Blocked);
        }
        if self.consecutive_pin_mismatches >= PIN_CONSECUTIVE_MISMATCHES_MAX {
            return Ok(PinVerification::AuthBlocked);
        }

        if state
            .pin_hash()
            .is_some_and(|stored| stored.ct_eq(pin_hash).into())
        {
            if state.retries() != PIN_RETRIES_MAX {
                state.reset_retries();
                self.storage.store_pin_state(&state)?;
            }
            self.consecutive_pin_mismatches = 0;
            Ok(PinVerification::Matched)
        } else {
            state.decrement_retries();
            self.storage.store_pin_state(&state)?;
            if state.retries() == 0 {
                Ok(PinVerification::Blocked)
            } else {
                self.consecutive_pin_mismatches += 1;
                if self.consecutive_pin_mismatches >= PIN_CONSECUTIVE_MISMATCHES_MAX {
                    Ok(PinVerification::AuthBlocked)
                } else {
                    Ok(PinVerification::Mismatched)
                }
            }
        }
    }

    fn pin_uv_auth_token_state(&mut self) -> Option<PinUvAuthTokenState> {
        let _ = self.expire_token_if_needed(0);
        self.pin_uv_auth_token[0]
    }

    fn pin_uv_auth_token_state_for_protocol(
        &mut self,
        protocol: u8,
    ) -> Option<PinUvAuthTokenState> {
        let index = Self::token_index(protocol)?;
        let _ = self.expire_token_if_needed(index);
        self.pin_uv_auth_token[index]
    }

    fn pin_uv_auth_token_expired(&mut self, protocol: u8) -> bool {
        let Some(index) = Self::token_index(protocol) else {
            return false;
        };
        self.expire_token_if_needed(index)
            || (self.pin_uv_auth_token[index].is_none()
                && self.pin_uv_auth_token_usage[index].is_some())
    }

    fn mark_pin_uv_auth_token_used(&mut self, protocol: u8) -> bool {
        let Some(index) = Self::token_index(protocol) else {
            return false;
        };
        let _ = self.expire_token_if_needed(index);
        if self.pin_uv_auth_token[index].is_none() {
            return false;
        }
        if let Some(usage) = self.pin_uv_auth_token_usage[index].as_mut() {
            usage.mark_used();
        }
        true
    }

    fn clear_pin_uv_auth_token_after_user_presence(&mut self, protocol: u8) {
        let Some(index) = Self::token_index(protocol) else {
            return;
        };
        if let Some(state) = self.pin_uv_auth_token[index].as_mut() {
            state.clear_after_user_presence_operation();
        }
    }

    fn store_pin_uv_auth_token(
        &mut self,
        token: [u8; 32],
        permissions: u8,
        rp_id_hash: Option<[u8; 32]>,
    ) {
        let _ = self.store_token(1, PinUvAuthTokenState::new(token, permissions, rp_id_hash));
    }

    fn store_pin_uv_auth_token_for_protocol(
        &mut self,
        protocol: u8,
        token: [u8; 32],
        permissions: u8,
        rp_id_hash: Option<[u8; 32]>,
    ) -> Result<(), PinStorageError> {
        let state = PinUvAuthTokenState::new_for_protocol(protocol, token, permissions, rp_id_hash);
        self.store_token(protocol, state)
    }

    fn reset_pin_uv_auth_state(&mut self) -> Result<(), PinStorageError> {
        self.key_agreement_private_key = None;
        self.backend_owned_key_agreement = false;
        self.pin_uv_auth_token = [None; 2];
        self.pin_uv_auth_token_usage = [None; 2];
        self.consecutive_pin_mismatches = 0;
        self.storage.store_pin_state(&PinUvAuthState::new_unset())
    }
}

#[path = "pin_uv_auth_adapters.rs"]
mod adapters;
pub use adapters::*;
