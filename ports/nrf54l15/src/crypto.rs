use core::cell::RefCell;
use embassy_nrf::{
    Peri,
    crypto::symmetric::{Sha256, Symmetric},
    mode::Blocking,
};
use embassy_sync::blocking_mutex::{Mutex, raw::ThreadModeRawMutex};
use manekey::ctaphid::hash::{Sha256Backend, Sha256Error};

static SYMMETRIC: Mutex<ThreadModeRawMutex, RefCell<Option<Symmetric<'static, Blocking>>>> =
    Mutex::new(RefCell::new(None));

fn record(index: usize) {
    let _ = index;
}

/// Initialize once in Secure thread mode with exclusive CRACEN ownership; no IRQ use or reentry.
pub fn init_symmetric(peripheral: Peri<'static, embassy_nrf::peripherals::CRYPTO_SYMMETRIC>) {
    SYMMETRIC.lock(|cell| {
        let mut owner = cell.borrow_mut();
        assert!(owner.is_none(), "CRACEN symmetric owner initialized twice");
        *owner = Some(Symmetric::new_blocking(peripheral));
    });
}

#[derive(Clone, Copy, Default)]
/// Blocking serialized hardware hash requiring initialized Secure symmetric runtime.
pub struct CracenSha256;

impl Sha256Backend for CracenSha256 {
    fn digest(&mut self, data: &[u8]) -> Result<[u8; 32], Sha256Error> {
        self.digest_parts(&[data])
    }

    fn digest_parts(&mut self, parts: &[&[u8]]) -> Result<[u8; 32], Sha256Error> {
        SYMMETRIC.lock(|cell| {
            let mut owner = cell.borrow_mut();
            let engine = owner.as_mut().ok_or(Sha256Error::HardwareUnavailable)?;
            let mut ctx = engine.hash_start::<Sha256>();
            for data in parts {
                engine.hash_blocking_update(&mut ctx, data);
            }
            let digest = engine.hash_blocking_finish(ctx);
            record(0);
            Ok(digest)
        })
    }
}

#[cfg(feature = "cracen-aes256")]
#[derive(Clone, Copy, Default)]
/// Blocking Secure hardware AES adapter; caller excludes concurrent independent engine owners.
pub struct CracenAes256;

#[cfg(feature = "cracen-aes256")]
impl CracenAes256 {
    fn block(
        &mut self,
        key: &[u8; 32],
        data: &mut [u8; 16],
        direction: embassy_nrf::crypto::symmetric::Direction,
    ) -> Result<(), manekey::ctaphid::crypto::Aes256Error> {
        use embassy_nrf::crypto::symmetric::AesEcb;
        use manekey::ctaphid::crypto::Aes256Error;
        SYMMETRIC.lock(|cell| {
            let mut owner = cell.borrow_mut();
            let engine = owner.as_mut().ok_or(Aes256Error::HardwareUnavailable)?;
            let cipher = AesEcb::new(key).map_err(|_| Aes256Error::HardwareUnavailable)?;
            let mut ctx = engine.aes_start(cipher, direction);
            engine
                .aes_blocking_payload_in_place(&mut ctx, data, true)
                .map_err(|_| Aes256Error::HardwareUnavailable)?;
            record(1);
            Ok(())
        })
    }
}

#[cfg(feature = "cracen-aes256")]
impl manekey::ctaphid::crypto::Aes256BlockBackend for CracenAes256 {
    fn encrypt_block(
        &mut self,
        key: &[u8; 32],
        block: &mut [u8; 16],
    ) -> Result<(), manekey::ctaphid::crypto::Aes256Error> {
        self.block(
            key,
            block,
            embassy_nrf::crypto::symmetric::Direction::Encrypt,
        )
    }
    fn decrypt_block(
        &mut self,
        key: &[u8; 32],
        block: &mut [u8; 16],
    ) -> Result<(), manekey::ctaphid::crypto::Aes256Error> {
        self.block(
            key,
            block,
            embassy_nrf::crypto::symmetric::Direction::Decrypt,
        )
    }
}

#[cfg(feature = "cracen-p256-experimental")]
mod pka {
    use super::*;
    use embassy_nrf::crypto::pka::{Error, Pka, Point, PointMut, SignatureMut, curve};
    use manekey::ctaphid::crypto::{Es256Backend, Es256Error, P256EcdhBackend, P256EcdhError};
    use zeroize::Zeroizing;

    struct Owner {
        engine: Pka<'static, Blocking>,
        rng: crate::entropy::SharedNrf54Rng,
    }
    static PKA: Mutex<ThreadModeRawMutex, RefCell<Option<Owner>>> = Mutex::new(RefCell::new(None));

    unsafe extern "C" {
        fn manekey_cracen_microcode(words: *mut usize) -> *const u32;
    }

    /// Initialize PKA once with the matching immutable microcode and initialized shared RNG owner.
    pub fn init(
        peripheral: Peri<'static, embassy_nrf::peripherals::CRYPTO_PKA>,
        rng: crate::entropy::SharedNrf54Rng,
    ) {
        let mut words = 0;

        let code = unsafe {
            let ptr = manekey_cracen_microcode(&mut words);
            core::slice::from_raw_parts(ptr, words)
        };
        PKA.lock(|cell| {
            let mut owner = cell.borrow_mut();
            assert!(owner.is_none(), "CRACEN PKA owner initialized twice");
            *owner = Some(Owner {
                engine: Pka::new_blocking(peripheral, code),
                rng,
            });
        });
    }

    fn map_ecdh(error: Error) -> P256EcdhError {
        match error {
            Error::InvalidScalar | Error::InvalidPoint | Error::InvalidLength => {
                P256EcdhError::InvalidKey
            }
            _ => P256EcdhError::HardwareUnavailable,
        }
    }

    #[derive(Clone, Copy, Default)]
    /// Experimental blocking PKA adapter using separately licensed microcode and Secure RAM key material.
    pub struct CracenP256;

    impl P256EcdhBackend for CracenP256 {
        fn public_key_xy(
            &mut self,
            private: &[u8; 32],
        ) -> Result<([u8; 32], [u8; 32]), P256EcdhError> {
            PKA.lock(|cell| {
                let mut owner = cell.borrow_mut();
                let owner = owner.as_mut().ok_or(P256EcdhError::HardwareUnavailable)?;
                let mut x = [0; 32];
                let mut y = [0; 32];
                owner
                    .engine
                    .blocking_public_key(
                        &curve::NIST_P256,
                        private,
                        PointMut {
                            x: &mut x,
                            y: &mut y,
                        },
                    )
                    .map_err(map_ecdh)?;
                record(2);
                Ok((x, y))
            })
        }
        fn ecdh(
            &mut self,
            private: &[u8; 32],
            peer_x: &[u8; 32],
            peer_y: &[u8; 32],
        ) -> Result<[u8; 32], P256EcdhError> {
            PKA.lock(|cell| {
                let mut owner = cell.borrow_mut();
                let owner = owner.as_mut().ok_or(P256EcdhError::HardwareUnavailable)?;
                let mut x = [0; 32];
                let mut y = Zeroizing::new([0; 32]);
                owner
                    .engine
                    .blocking_ecc_mul(
                        &curve::NIST_P256,
                        private,
                        Point {
                            x: peer_x,
                            y: peer_y,
                        },
                        PointMut {
                            x: &mut x,
                            y: &mut *y,
                        },
                    )
                    .map_err(map_ecdh)?;
                record(2);
                Ok(x)
            })
        }
    }

    impl CracenP256 {
        fn sign_hash<'a>(
            &mut self,
            private: &[u8; 32],
            hash: &[u8; 32],
            output: &'a mut [u8],
        ) -> Result<&'a [u8], Es256Error> {
            if !manekey::ctaphid::crypto::p256_private_scalar_is_valid(private) {
                return Err(Es256Error::InvalidPrivateKey);
            }
            PKA.lock(|cell| {
                let mut owner = cell.borrow_mut();
                let owner = owner.as_mut().ok_or(Es256Error::HardwareUnavailable)?;
                let mut entropy = crate::entropy::Nrf54EntropySource(owner.rng);
                let mut r = [0; 32];
                let mut s = [0; 32];
                for _ in 0..8 {
                    let nonce = Zeroizing::new(
                        manekey::ctaphid::crypto::generate_private_key(&mut entropy)
                            .ok_or(Es256Error::HardwareUnavailable)?,
                    );
                    match owner.engine.blocking_ecdsa_sign_with_nonce(
                        &curve::NIST_P256,
                        private,
                        &*nonce,
                        hash,
                        SignatureMut {
                            r: &mut r,
                            s: &mut s,
                        },
                    ) {
                        Ok(()) => {
                            let signature = p256::ecdsa::Signature::from_scalars(r, s)
                                .map_err(|_| Es256Error::HardwareUnavailable)?;
                            let signature = signature.normalize_s();
                            let der = signature.to_der();
                            let bytes = der.as_bytes();
                            let dst = output
                                .get_mut(..bytes.len())
                                .ok_or(Es256Error::BufferTooSmall)?;
                            dst.copy_from_slice(bytes);
                            record(3);
                            return Ok(&output[..bytes.len()]);
                        }
                        Err(Error::RetryWithNewK) => {}
                        Err(_) => return Err(Es256Error::HardwareUnavailable),
                    }
                }
                Err(Es256Error::HardwareUnavailable)
            })
        }
    }

    impl Es256Backend for CracenP256 {
        fn public_key_xy(
            &mut self,
            private: &[u8; 32],
        ) -> Result<([u8; 32], [u8; 32]), Es256Error> {
            P256EcdhBackend::public_key_xy(self, private).map_err(|error| match error {
                P256EcdhError::InvalidKey => Es256Error::InvalidPrivateKey,
                _ => Es256Error::HardwareUnavailable,
            })
        }
        fn sign_der<'a>(
            &mut self,
            private: &[u8; 32],
            message: &[u8],
            output: &'a mut [u8],
        ) -> Result<&'a [u8], Es256Error> {
            let hash = CracenSha256
                .digest(message)
                .map_err(|_| Es256Error::HardwareUnavailable)?;
            self.sign_hash(private, &hash, output)
        }
        fn sign_webauthn_der<'a>(
            &mut self,
            private: &[u8; 32],
            auth_data: &[u8],
            client_hash: &[u8; 32],
            output: &'a mut [u8],
        ) -> Result<&'a [u8], Es256Error> {
            let hash = CracenSha256
                .digest_parts(&[auth_data, client_hash])
                .map_err(|_| Es256Error::HardwareUnavailable)?;
            self.sign_hash(private, &hash, output)
        }
    }
}

#[cfg(feature = "cracen-p256-experimental")]
pub use pka::{CracenP256, init as init_pka};
