#[cfg(feature = "cracen-sha256")]
type Hash = crate::crypto::CracenSha256;
#[cfg(not(feature = "cracen-sha256"))]
type Hash = manekey::ctaphid::hash::SoftwareSha256;
#[cfg(feature = "cracen-aes256")]
type Aes = crate::crypto::CracenAes256;
#[cfg(all(feature = "cracen-sha256", not(feature = "cracen-aes256")))]
type Aes = manekey::ctaphid::crypto::SoftwareAes256Block;
#[cfg(feature = "cracen-p256-experimental")]
type P256 = crate::crypto::CracenP256;
#[cfg(all(feature = "cracen-sha256", not(feature = "cracen-p256-experimental")))]
type P256 = manekey::ctaphid::crypto::SoftwareP256Ecdh;
#[cfg(feature = "cracen-p256-experimental")]
type Signature = crate::crypto::CracenP256;
#[cfg(not(feature = "cracen-p256-experimental"))]
type Signature = manekey::ctaphid::crypto::SoftwareEs256;

pub type DerivedKeys = manekey::ctaphid::key_store::DerivedPrivateKeyStore<Hash, Signature>;
#[cfg(feature = "cracen-sha256")]
pub type ClientPinCrypto = manekey::ctaphid::crypto::Sha256ClientPinCrypto<Hash, Aes, P256>;
#[cfg(not(feature = "cracen-sha256"))]
pub type ClientPinCrypto = manekey::ctaphid::crypto::SoftwareClientPinCrypto;

/// Caller supplies secret root material and exclusive ownership of selected hardware backends.
pub fn derived_keys(secret: [u8; 32]) -> DerivedKeys {
    DerivedKeys::new_with_backends(secret, Hash::default(), Signature::default())
}

/// Selected hardware adapters require their Secure runtime and exclusive peripheral ownership.
pub fn client_pin_crypto() -> ClientPinCrypto {
    #[cfg(feature = "cracen-sha256")]
    {
        ClientPinCrypto::new_with_backends(Hash::default(), Aes::default(), P256::default())
    }
    #[cfg(not(feature = "cracen-sha256"))]
    {
        manekey::ctaphid::crypto::SoftwareClientPinCrypto
    }
}
