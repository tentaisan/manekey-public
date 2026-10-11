#[cfg(all(
    feature = "experimental-ml-dsa-fips204-scratch",
    feature = "experimental-ml-dsa-mldsa-native"
))]
compile_error!("select only one RP ML-DSA comparison backend");

#[cfg(any(
    feature = "riscv-client-pin-sha256",
    feature = "rp2350-sha256-accelerator"
))]
pub type ClientPinCrypto =
    manekey::ctaphid::crypto::Sha256ClientPinCrypto<super::sha256::Rp2350Sha256>;
#[cfg(not(any(
    feature = "riscv-client-pin-sha256",
    feature = "rp2350-sha256-accelerator"
)))]
pub type ClientPinCrypto = manekey::ctaphid::crypto::SoftwareClientPinCrypto;

#[cfg(any(
    feature = "riscv-client-pin-sha256",
    feature = "rp2350-sha256-accelerator"
))]
pub type Hash = super::sha256::Rp2350Sha256;
#[cfg(not(any(
    feature = "riscv-client-pin-sha256",
    feature = "rp2350-sha256-accelerator"
)))]
pub type Hash = manekey::ctaphid::hash::SoftwareSha256;

/// # Safety
/// Exclusively own initialized hardware SHA across consumers, tasks, harts and interrupts.
pub unsafe fn hash_backend() -> Hash {
    #[cfg(any(
        feature = "riscv-client-pin-sha256",
        feature = "rp2350-sha256-accelerator"
    ))]
    return unsafe { Hash::new_unchecked() };
    #[cfg(not(any(
        feature = "riscv-client-pin-sha256",
        feature = "rp2350-sha256-accelerator"
    )))]
    manekey::ctaphid::hash::SoftwareSha256
}

/// # Safety
/// Serialize all selected hardware SHA consumers for this object's lifetime; exclude IRQ/DMA/other-hart access.
pub unsafe fn client_pin_crypto() -> ClientPinCrypto {
    #[cfg(any(
        feature = "riscv-client-pin-sha256",
        feature = "rp2350-sha256-accelerator"
    ))]
    return ClientPinCrypto::new(unsafe { super::sha256::Rp2350Sha256::new_unchecked() });
    #[cfg(not(any(
        feature = "riscv-client-pin-sha256",
        feature = "rp2350-sha256-accelerator"
    )))]
    manekey::ctaphid::crypto::SoftwareClientPinCrypto
}

#[cfg(any(
    feature = "riscv-client-pin-sha256",
    feature = "rp2350-sha256-accelerator"
))]
/// # Safety
/// Exclusively own the initialized SHA peripheral for the entire startup self-check.
pub unsafe fn sha256_known_answers() -> bool {
    use manekey::ctaphid::hash::{Sha256Backend, sha256_digest};
    let mut hash = unsafe { super::sha256::Rp2350Sha256::new_unchecked() };
    let input = [0x5a; 100];
    for data in [
        b"".as_slice(),
        b"abc".as_slice(),
        &input[..55],
        &input[..56],
        &input[..64],
        &input[..100],
    ] {
        if hash.digest(data) != Ok(sha256_digest(data)) {
            return false;
        }
        for split in 0..=data.len() {
            if hash.digest_parts(&[&data[..split], &[], &data[split..]]) != Ok(sha256_digest(data))
            {
                return false;
            }
        }
    }
    use manekey::ctaphid::crypto::{ClientPinCrypto as _, SoftwareClientPinCrypto};
    let mut hardware = ClientPinCrypto::new(hash);
    let mut software = SoftwareClientPinCrypto;
    let key = [0x5a; 32];
    if hardware.hmac_sha256(&key, &[b"a", b"bc"]) != software.hmac_sha256(&key, &[b"abc"])
        || hardware.protocol_two_shared_secret(&key) != software.protocol_two_shared_secret(&key)
    {
        return false;
    }
    true
}

pub use crate::platform::rp::crypto::*;
