#[cfg(feature = "experimental-large-message-buffers")]
pub(crate) const ATTESTED_AUTH_DATA_LEN: usize = 1_536;
#[cfg(not(feature = "experimental-large-message-buffers"))]
pub(crate) const ATTESTED_AUTH_DATA_LEN: usize = 256;

#[cfg(feature = "experimental-large-message-buffers")]
pub(crate) const CREDENTIAL_SIGNATURE_LEN: usize = 2_432;
#[cfg(not(feature = "experimental-large-message-buffers"))]
pub(crate) const CREDENTIAL_SIGNATURE_LEN: usize = 256;

#[cfg(feature = "experimental-large-message-buffers")]
pub(crate) const CREDENTIAL_COSE_KEY_LEN: usize = 1_344;
#[cfg(not(feature = "experimental-large-message-buffers"))]
pub(crate) const CREDENTIAL_COSE_KEY_LEN: usize = 128;
