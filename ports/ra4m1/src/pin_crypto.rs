
#[cfg(not(feature = "sce5-aes"))]
pub type ClientPin = manekey::ctaphid::crypto::SoftwareClientPinCrypto;
#[cfg(feature = "sce5-aes")]
pub type ClientPin = manekey::ctaphid::crypto::Sha256ClientPinCrypto<
    manekey::ctaphid::hash::SoftwareSha256,
    crate::sce_aes::SceAes256,
>;

pub fn client_pin() -> ClientPin {
    #[cfg(not(feature = "sce5-aes"))]
    {
        manekey::ctaphid::crypto::SoftwareClientPinCrypto
    }
    #[cfg(feature = "sce5-aes")]
    {
        ClientPin::new_with_aes(
            manekey::ctaphid::hash::SoftwareSha256,
            crate::sce_aes::SceAes256,
        )
    }
}
