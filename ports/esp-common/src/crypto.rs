use esp_hal::{
    aes::Aes,
    efuse,
    peripherals::{AES, SHA},
    sha::{Sha, Sha256},
};
use esp_println::println;
use manekey::ctaphid::{
    crypto::{Aes256BlockBackend, Aes256Error},
    hash::{Sha256Backend, Sha256Error, SoftwareSha256},
    key_store::DerivedPrivateKeyStore,
};

/// Raw hardware AES adapter; caller owns peripheral exclusion and key lifetime.
pub struct EspAes256<'d> {
    aes: Aes<'d>,
}

impl<'d> EspAes256<'d> {
    pub fn new(aes: AES<'d>) -> Self {
        Self { aes: Aes::new(aes) }
    }
}

impl Aes256BlockBackend for EspAes256<'_> {
    fn encrypt_block(&mut self, key: &[u8; 32], block: &mut [u8; 16]) -> Result<(), Aes256Error> {
        self.aes.encrypt(block, *key);
        Ok(())
    }

    fn decrypt_block(&mut self, key: &[u8; 32], block: &mut [u8; 16]) -> Result<(), Aes256Error> {
        self.aes.decrypt(block, *key);
        Ok(())
    }
}

pub fn verify_aes256_accelerator<A: Aes256BlockBackend>(aes: &mut A) {
    let key = [
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
        0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d,
        0x1e, 0x1f,
    ];
    let plaintext = [
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee,
        0xff,
    ];
    let expected = [
        0x8e, 0xa2, 0xb7, 0xca, 0x51, 0x67, 0x45, 0xbf, 0xea, 0xfc, 0x49, 0x90, 0x4b, 0x49, 0x60,
        0x89,
    ];
    let mut block = plaintext;
    aes.encrypt_block(&key, &mut block)
        .expect("ESP AES-256 accelerator encrypt known-answer test");
    assert_eq!(block, expected);
    aes.decrypt_block(&key, &mut block)
        .expect("ESP AES-256 accelerator decrypt known-answer test");
    assert_eq!(block, plaintext);
}

/// Hardware SHA adapter with blocking polling; no hardware timeout is imposed.
pub struct EspSha256<'d> {
    sha: Sha<'d>,
}

impl<'d> EspSha256<'d> {
    pub fn new(sha: SHA<'d>) -> Self {
        Self { sha: Sha::new(sha) }
    }
}

impl Sha256Backend for EspSha256<'_> {
    fn digest(&mut self, data: &[u8]) -> Result<[u8; 32], Sha256Error> {
        self.digest_parts(&[data])
    }

    fn digest_parts(&mut self, parts: &[&[u8]]) -> Result<[u8; 32], Sha256Error> {
        let mut hasher = self.sha.start::<Sha256>();
        for part in parts {
            let mut remaining = *part;
            while !remaining.is_empty() {
                remaining = match hasher.update(remaining) {
                    Ok(remaining) => remaining,
                    Err(nb::Error::WouldBlock) => continue,
                    Err(nb::Error::Other(_)) => return Err(Sha256Error::HardwareUnavailable),
                };
            }
        }

        let mut output = [0u8; 32];
        loop {
            match hasher.finish(&mut output) {
                Ok(()) => return Ok(output),
                Err(nb::Error::WouldBlock) => {}
                Err(nb::Error::Other(_)) => return Err(Sha256Error::HardwareUnavailable),
            }
        }
    }
}

pub fn verify_sha256_accelerator<H: Sha256Backend>(sha: &mut H) {
    let expected_abc = SoftwareSha256
        .digest(b"abc")
        .expect("software SHA-256 is infallible");
    let hardware_abc = sha
        .digest(b"abc")
        .expect("ESP SHA-256 accelerator known-answer test");
    assert_eq!(hardware_abc, expected_abc);
}

/// Public device IDs do not supply a secret root; backend failure panics.
pub fn build_derived_key_store<H: Sha256Backend>(
    device_id: &[u8],
    sha: H,
) -> DerivedPrivateKeyStore<H> {
    DerivedPrivateKeyStore::from_device_id_with_hash(device_id, sha)
        .expect("derive ESP key store with SHA accelerator")
}

/// Derives reproducible material from the public MAC, not a hardware-protected secret root.
pub fn build_device_key_store_from_sha(
    sha: SHA<'static>,
) -> DerivedPrivateKeyStore<EspSha256<'static>> {
    let mut sha = EspSha256::new(sha);
    verify_sha256_accelerator(&mut sha);
    println!("ESP SHA-256 accelerator known-answer test passed");
    let device_mac = efuse::base_mac_address();
    let key_store = build_derived_key_store(device_mac.as_bytes(), sha);
    println!("ESP SHA-256 accelerator key store enabled");
    key_store
}
