use crate::ctaphid::channel::MAX_REQUEST_SIZE;
use crate::ctaphid::credential::{CRED_BLOB_MAX_LEN, CREDENTIAL_ID_LEN};
use crate::ctaphid::storage::MAX_RECORDS;
use crate::transport;

use super::request::Options;

/// Baseline metadata, not certification; transport lists must match the active frontend.
/// The UV bypass feature is for tests, not identity verification.
pub(super) struct Capabilities {
    pub(super) versions: &'static [&'static [u8]],

    pub(super) aaguid: [u8; 16],

    pub(super) resident_key: bool,

    pub(super) user_presence: bool,

    pub(super) user_verification: bool,

    pub(super) transports: &'static [&'static [u8]],

    pub(super) extensions: &'static [&'static [u8]],
}

pub(super) const CURRENT: Capabilities = Capabilities {
    versions: &[b"FIDO_2_0"],
    aaguid: [0; 16],
    resident_key: true,
    user_presence: true,
    user_verification: cfg!(feature = "uv-always-verified"),
    transports: transport::USB_TRANSPORTS,
    extensions: if cfg!(all(feature = "hmac-secret", feature = "cred-blob")) {
        &[b"hmac-secret", b"credBlob", b"credProtect"]
    } else if cfg!(feature = "cred-blob") {
        &[b"credBlob", b"credProtect"]
    } else if cfg!(all(feature = "hmac-secret", feature = "uv-always-verified")) {
        &[b"hmac-secret", b"credProtect"]
    } else if cfg!(feature = "hmac-secret") {
        &[b"hmac-secret"]
    } else if cfg!(feature = "uv-always-verified") {
        &[b"credProtect"]
    } else {
        &[]
    },
};

impl Capabilities {
    pub(super) const fn max_message_size(&self) -> usize {
        MAX_REQUEST_SIZE
    }

    pub(super) const fn max_credential_count(&self) -> usize {
        MAX_RECORDS
    }

    pub(super) const fn max_credential_id_length(&self) -> usize {
        CREDENTIAL_ID_LEN
    }

    pub(super) const fn max_cred_blob_length(&self) -> usize {
        CRED_BLOB_MAX_LEN
    }

    pub(super) fn has_unsupported_options(&self, options: &Options) -> bool {
        (options.rk == Some(true) && !self.resident_key)
            || (options.uv == Some(true) && !self.user_verification)
            || (options.up == Some(false) && self.user_presence)
    }
}
