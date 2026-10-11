#[cfg(all(feature = "hardware-sha256", not(feature = "trustzone-secure-layout")))]
pub type Hash = crate::sha256::Stm32Sha256;
#[cfg(all(feature = "hardware-sha256", feature = "trustzone-secure-layout"))]
pub type Hash = crate::secure_hal::SecureSha256;
#[cfg(not(feature = "hardware-sha256"))]
pub type Hash = manekey::ctaphid::hash::SoftwareSha256;
pub type DerivedKeys = manekey::ctaphid::key_store::DerivedPrivateKeyStore<Hash>;
#[cfg(feature = "hardware-sha256")]
pub type ClientPinCrypto = manekey::ctaphid::crypto::Sha256ClientPinCrypto<Hash>;
#[cfg(not(feature = "hardware-sha256"))]
pub type ClientPinCrypto = manekey::ctaphid::crypto::SoftwareClientPinCrypto;

pub fn client_pin_crypto() -> ClientPinCrypto {
    #[cfg(feature = "hardware-sha256")]
    {
        ClientPinCrypto::new(hash_backend())
    }
    #[cfg(not(feature = "hardware-sha256"))]
    {
        manekey::ctaphid::crypto::SoftwareClientPinCrypto
    }
}

pub fn derived_keys(secret: [u8; 32]) -> DerivedKeys {
    #[cfg(feature = "hardware-sha256")]
    {
        DerivedKeys::new_with_hash(secret, hash_backend())
    }
    #[cfg(not(feature = "hardware-sha256"))]
    {
        DerivedKeys::new(secret)
    }
}

/// Hardware HASH requires exclusive initialization in the selected domain; composition does not establish isolation.
pub fn hash_backend() -> Hash {
    #[cfg(not(feature = "hardware-sha256"))]
    {
        manekey::ctaphid::hash::SoftwareSha256
    }
    #[cfg(feature = "hardware-sha256")]
    {
        #[cfg(feature = "trustzone-secure-layout")]
        {
            crate::secure_hal::SecureSha256
        }
        #[cfg(not(feature = "trustzone-secure-layout"))]
        {
            crate::sha256::Stm32Sha256
        }
    }
}
