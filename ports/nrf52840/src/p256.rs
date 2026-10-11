use manekey::ctaphid::{
    crypto::{
        P256_GENERATOR_X, P256_GENERATOR_Y, P256EcdhBackend, P256EcdhError, P256KeyAgreement,
        P256KeyPair, SoftwareP256Ecdh, p256_private_scalar_is_valid,
    },
    entropy::{EntropyError, EntropySource},
};

const CC310_OK: u32 = 0;
const CC310_INVALID_KEY: u32 = 1;

unsafe extern "C" {
    fn manekey_cc310_p256_init() -> u32;
    fn manekey_cc310_p256_generate(private_out: *mut u8, public_out: *mut u8) -> u32;
    fn manekey_cc310_p256_generate_opaque(public_out: *mut u8) -> u32;
    fn manekey_cc310_p256_import_private(private_in: *const u8) -> u32;
    fn manekey_cc310_p256_ecdh_loaded(peer_public: *mut u8, shared_secret: *mut u8) -> u32;
    fn manekey_cc310_p256_ecdh_current(peer_public: *mut u8, shared_secret: *mut u8) -> u32;
    fn manekey_cc310_p256_ecdh(
        private_in: *const u8,
        peer_public: *mut u8,
        shared_secret: *mut u8,
    ) -> u32;
}

/// Experimental synchronous shim with global loaded-key state, not an independent hardware key vault.
/// Caller excludes concurrent CryptoCell/shim access, including interrupts and reentry.
pub struct Cc310P256;

struct HardwareGeneratedEntropy;

impl EntropySource for HardwareGeneratedEntropy {
    fn fill_entropy(&mut self, _output: &mut [u8]) -> Result<(), EntropyError> {
        Err(EntropyError::Unavailable)
    }
}

impl Cc310P256 {
    /// Initialize the linked shim under exclusive CryptoCell ownership.
    pub fn new() -> Result<Self, P256EcdhError> {
        if unsafe { manekey_cc310_p256_init() } == CC310_OK {
            Ok(Self)
        } else {
            Err(P256EcdhError::HardwareUnavailable)
        }
    }

    pub fn self_test(&mut self) -> Result<(), P256EcdhError> {
        let key_pair = self.generate_key_pair(&mut HardwareGeneratedEntropy)?;
        let expected_public = SoftwareP256Ecdh.public_key_xy(&key_pair.private_key)?;
        if expected_public != (key_pair.public_x, key_pair.public_y) {
            return Err(P256EcdhError::HardwareUnavailable);
        }
        if self.ecdh(&key_pair.private_key, &P256_GENERATOR_X, &P256_GENERATOR_Y)?
            != key_pair.public_x
        {
            return Err(P256EcdhError::HardwareUnavailable);
        }
        if self.ecdh(&key_pair.private_key, &[0; 32], &[0; 32]) != Err(P256EcdhError::InvalidKey) {
            return Err(P256EcdhError::HardwareUnavailable);
        }
        Ok(())
    }

    /// Replaces the shim's shared loaded private key.
    pub fn import_private_key(&mut self, private_key: &[u8; 32]) -> Result<(), P256EcdhError> {
        if !p256_private_scalar_is_valid(private_key) {
            return Err(P256EcdhError::InvalidKey);
        }

        match unsafe { manekey_cc310_p256_import_private(private_key.as_ptr()) } {
            CC310_OK => Ok(()),
            CC310_INVALID_KEY => Err(P256EcdhError::InvalidKey),
            _ => Err(P256EcdhError::HardwareUnavailable),
        }
    }

    pub fn ecdh_loaded(
        &mut self,
        peer_x: &[u8; 32],
        peer_y: &[u8; 32],
    ) -> Result<[u8; 32], P256EcdhError> {
        let mut peer_public = [0u8; 65];
        peer_public[0] = 0x04;
        peer_public[1..33].copy_from_slice(peer_x);
        peer_public[33..65].copy_from_slice(peer_y);
        let mut shared_secret = [0u8; 32];

        let status = unsafe {
            manekey_cc310_p256_ecdh_loaded(peer_public.as_mut_ptr(), shared_secret.as_mut_ptr())
        };
        match status {
            CC310_OK => Ok(shared_secret),
            CC310_INVALID_KEY => Err(P256EcdhError::InvalidKey),
            _ => Err(P256EcdhError::HardwareUnavailable),
        }
    }
}

impl P256EcdhBackend for Cc310P256 {
    fn generate_key_pair(
        &mut self,
        _entropy: &mut dyn EntropySource,
    ) -> Result<P256KeyPair, P256EcdhError> {
        let mut private_key = [0u8; 32];
        let mut public_key = [0u8; 65];

        let status = unsafe {
            manekey_cc310_p256_generate(private_key.as_mut_ptr(), public_key.as_mut_ptr())
        };
        if status != CC310_OK || !p256_private_scalar_is_valid(&private_key) {
            return Err(P256EcdhError::HardwareUnavailable);
        }

        let mut public_x = [0u8; 32];
        let mut public_y = [0u8; 32];
        public_x.copy_from_slice(&public_key[1..33]);
        public_y.copy_from_slice(&public_key[33..65]);
        Ok(P256KeyPair {
            private_key,
            public_x,
            public_y,
        })
    }

    fn generate_key_agreement(
        &mut self,
        _entropy: &mut dyn EntropySource,
    ) -> Result<P256KeyAgreement, P256EcdhError> {
        let mut public_key = [0u8; 65];

        let status = unsafe { manekey_cc310_p256_generate_opaque(public_key.as_mut_ptr()) };
        if status != CC310_OK || public_key[0] != 0x04 {
            return Err(P256EcdhError::HardwareUnavailable);
        }

        let mut public_x = [0u8; 32];
        let mut public_y = [0u8; 32];
        public_x.copy_from_slice(&public_key[1..33]);
        public_y.copy_from_slice(&public_key[33..65]);
        Ok(P256KeyAgreement::BackendOwned { public_x, public_y })
    }

    fn public_key_xy(
        &mut self,
        _private_key: &[u8; 32],
    ) -> Result<([u8; 32], [u8; 32]), P256EcdhError> {
        Err(P256EcdhError::HardwareUnavailable)
    }

    fn ecdh(
        &mut self,
        private_key: &[u8; 32],
        peer_x: &[u8; 32],
        peer_y: &[u8; 32],
    ) -> Result<[u8; 32], P256EcdhError> {
        if !p256_private_scalar_is_valid(private_key) {
            return Err(P256EcdhError::InvalidKey);
        }
        let mut peer_public = [0u8; 65];
        peer_public[0] = 0x04;
        peer_public[1..33].copy_from_slice(peer_x);
        peer_public[33..65].copy_from_slice(peer_y);
        let mut shared_secret = [0u8; 32];

        let status = unsafe {
            manekey_cc310_p256_ecdh(
                private_key.as_ptr(),
                peer_public.as_mut_ptr(),
                shared_secret.as_mut_ptr(),
            )
        };
        match status {
            CC310_OK => Ok(shared_secret),
            CC310_INVALID_KEY => Err(P256EcdhError::InvalidKey),
            _ => Err(P256EcdhError::HardwareUnavailable),
        }
    }

    fn ecdh_current(
        &mut self,
        peer_x: &[u8; 32],
        peer_y: &[u8; 32],
    ) -> Result<[u8; 32], P256EcdhError> {
        let mut peer_public = [0u8; 65];
        peer_public[0] = 0x04;
        peer_public[1..33].copy_from_slice(peer_x);
        peer_public[33..65].copy_from_slice(peer_y);
        let mut shared_secret = [0u8; 32];

        let status = unsafe {
            manekey_cc310_p256_ecdh_current(peer_public.as_mut_ptr(), shared_secret.as_mut_ptr())
        };
        match status {
            CC310_OK => Ok(shared_secret),
            CC310_INVALID_KEY => Err(P256EcdhError::InvalidKey),
            _ => Err(P256EcdhError::HardwareUnavailable),
        }
    }
}
