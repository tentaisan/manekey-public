use super::*;

/// Key-agreement-only provider; PIN setting and token authentication remain unsupported.
pub struct UnconfiguredPinUvAuth {
    key_agreement_private_key: Option<[u8; 32]>,
    backend_owned_key_agreement: bool,
}

impl UnconfiguredPinUvAuth {
    pub const fn new() -> Self {
        Self {
            key_agreement_private_key: None,
            backend_owned_key_agreement: false,
        }
    }
}

impl PinUvAuthProvider for UnconfiguredPinUvAuth {
    fn pin_retries(&mut self) -> u8 {
        PIN_RETRIES_MAX
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

    fn supports_pin_setting(&self) -> bool {
        false
    }

    fn pin_is_set(&mut self) -> bool {
        false
    }

    fn store_pin_hash(&mut self, _pin_hash: [u8; 16]) -> Result<(), PinStorageError> {
        Err(PinStorageError::Unsupported)
    }

    fn verify_pin_hash(
        &mut self,
        _pin_hash: &[u8; 16],
    ) -> Result<PinVerification, PinStorageError> {
        Ok(PinVerification::Blocked)
    }

    fn pin_uv_auth_token_state(&mut self) -> Option<PinUvAuthTokenState> {
        None
    }

    fn store_pin_uv_auth_token(
        &mut self,
        _token: [u8; 32],
        _permissions: u8,
        _rp_id_hash: Option<[u8; 32]>,
    ) {
    }

    fn reset_pin_uv_auth_state(&mut self) -> Result<(), PinStorageError> {
        self.key_agreement_private_key = None;
        self.backend_owned_key_agreement = false;
        Ok(())
    }
}
