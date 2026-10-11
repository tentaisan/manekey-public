#[cfg(all(target_arch = "arm", target_os = "none", feature = "defmt-log"))]
use defmt::debug;
#[cfg(not(all(target_arch = "arm", target_os = "none", feature = "defmt-log")))]
macro_rules! debug {
    ($($arg:tt)*) => {};
}

use crate::ctaphid::key_store::PrivateKeyStore;
use crate::ctaphid::pin_uv_auth::PinUvAuthProvider;
use crate::ctaphid::storage::{Storage, StorageBackend};
use crate::presence::UserPresence;

use super::status;

pub(super) fn reset_with_keys<
    'a,
    B: StorageBackend,
    P: UserPresence,
    A: PinUvAuthProvider,
    K: PrivateKeyStore,
>(
    request: &[u8],
    storage: &mut Storage<B>,
    presence: &mut P,
    pin_uv_auth: &mut A,
    key_store: &mut K,
    buf: &'a mut [u8],
) -> &'a [u8] {
    if !request.is_empty() {
        debug!("authenticatorReset rejected payload");
        buf[0] = status::INVALID_LENGTH;
        return &buf[..1];
    }

    if !presence.wait_for_presence() {
        debug!("authenticatorReset user presence denied");
        buf[0] = status::OPERATION_DENIED;
        return &buf[..1];
    }

    if storage.debug_clear().is_err() {
        debug!("authenticatorReset storage clear failed");
        buf[0] = status::OPERATION_DENIED;
        return &buf[..1];
    }

    if key_store.reset_credential_keys().is_err() {
        buf[0] = status::OPERATION_DENIED;
        return &buf[..1];
    }

    if pin_uv_auth.reset_pin_uv_auth_state().is_err() {
        debug!("authenticatorReset PIN/UV state clear failed");
        buf[0] = status::OPERATION_DENIED;
        return &buf[..1];
    }

    debug!("authenticatorReset completed");
    buf[0] = status::OK;
    &buf[..1]
}
