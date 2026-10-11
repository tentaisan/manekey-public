use manekey::ctaphid::{
    CtaphidFrontend, storage::Storage, trusted::TrustedDispatcher,
    user_verification::UnavailableUserVerification,
};
#[cfg(all(feature = "client-pin-flash", feature = "client-pin-volatile"))]
compile_error!("CH32 ClientPIN backendはflashまたはvolatileの一方だけを選ぶ");
#[cfg(feature = "dual-task")]
use manekey::boundary::mailbox::{LocalMailboxTransport, MailboxEndpoint};
#[cfg(feature = "dual-task")]
use manekey::boundary::mailbox_backend::MailboxTrustedBackend;
#[cfg(not(any(feature = "client-pin-flash", feature = "client-pin-volatile")))]
use manekey::ctaphid::pin_uv_auth::UnconfiguredPinUvAuth;
#[cfg(feature = "client-pin-volatile")]
use manekey::ctaphid::pin_uv_auth::VolatilePinUvAuthStorage;
#[cfg(feature = "dual-task")]
use manekey::ctaphid::trusted::{TRUSTED_REQUEST_MAX, TRUSTED_RESPONSE_MAX};
#[cfg(any(feature = "client-pin-flash", feature = "client-pin-volatile"))]
use manekey::ctaphid::{
    crypto::SoftwareClientPinCrypto,
    pin_uv_auth::{PinUvAuthTokenClock, StoredPinUvAuthProvider},
};

#[cfg(feature = "client-pin-flash")]
use crate::storage::Ch32PinUvAuthFlashStorage;
use crate::{
    entropy::SelectedEntropy,
    key_store::SelectedKeyStore,
    storage::SelectedStorage,
    user_presence::{SelectedUserPresence, selected_user_presence},
};

#[cfg(feature = "client-pin-flash")]
pub type SelectedPinUvAuth =
    StoredPinUvAuthProvider<Ch32PinUvAuthFlashStorage, SoftwareClientPinCrypto, Ch32TokenClock>;
#[cfg(feature = "client-pin-volatile")]
pub type SelectedPinUvAuth =
    StoredPinUvAuthProvider<VolatilePinUvAuthStorage, SoftwareClientPinCrypto, Ch32TokenClock>;
#[cfg(not(any(feature = "client-pin-flash", feature = "client-pin-volatile")))]
pub type SelectedPinUvAuth = UnconfiguredPinUvAuth;

#[cfg(any(feature = "client-pin-flash", feature = "client-pin-volatile"))]
#[derive(Clone, Copy)]
pub struct Ch32TokenClock;

#[cfg(any(feature = "client-pin-flash", feature = "client-pin-volatile"))]
impl PinUvAuthTokenClock for Ch32TokenClock {
    fn now_ms(&self) -> u64 {
        embassy_time::Instant::now().as_millis()
    }
}

/// Software dispatcher composition, not hardware isolation; caller initializes entropy and reserves selected media.
pub type SelectedDispatcher = TrustedDispatcher<
    SelectedStorage,
    SelectedUserPresence,
    UnavailableUserVerification,
    SelectedPinUvAuth,
    SelectedKeyStore,
    SelectedEntropy,
>;

const fn selected_pin_uv_auth() -> SelectedPinUvAuth {
    #[cfg(feature = "client-pin-flash")]
    {
        StoredPinUvAuthProvider::new_with_clock(Ch32PinUvAuthFlashStorage::new(), Ch32TokenClock)
    }
    #[cfg(feature = "client-pin-volatile")]
    {
        StoredPinUvAuthProvider::new_with_clock(VolatilePinUvAuthStorage::new(), Ch32TokenClock)
    }
    #[cfg(not(any(feature = "client-pin-flash", feature = "client-pin-volatile")))]
    {
        UnconfiguredPinUvAuth::new()
    }
}

#[cfg(not(feature = "dual-task"))]
pub type SelectedCtaphid = CtaphidFrontend<SelectedDispatcher>;
#[cfg(feature = "dual-task")]
pub type SelectedCtaphid = CtaphidFrontend<
    MailboxTrustedBackend<
        LocalMailboxTransport<'static, TRUSTED_REQUEST_MAX, TRUSTED_RESPONSE_MAX>,
    >,
>;

#[cfg(not(feature = "flash-managed-keys"))]
pub const fn selected_dispatcher() -> SelectedDispatcher {
    TrustedDispatcher::new(
        Storage::new(SelectedStorage::new()),
        selected_user_presence(),
        UnavailableUserVerification,
        selected_pin_uv_auth(),
        SelectedKeyStore::new(),
        SelectedEntropy::new(),
    )
}

#[cfg(feature = "flash-managed-keys")]
pub fn selected_dispatcher() -> SelectedDispatcher {
    let mut records = Storage::new(SelectedStorage::new());
    let mut entropy = SelectedEntropy::new();
    let keys = crate::key_store::open_managed(&mut records, &mut entropy)
        .expect("checked managed key journal required");
    TrustedDispatcher::new(
        records,
        selected_user_presence(),
        UnavailableUserVerification,
        selected_pin_uv_auth(),
        keys,
        entropy,
    )
}

#[cfg(feature = "flash-managed-keys")]
pub fn initialize_dispatcher(destination: &mut core::mem::MaybeUninit<SelectedDispatcher>) {
    let mut records = Storage::new(SelectedStorage::new());
    let mut entropy = SelectedEntropy::new();
    let keys = crate::key_store::open_managed(&mut records, &mut entropy)
        .expect("checked managed key journal required");
    SelectedDispatcher::initialize_in_place(
        destination,
        records,
        selected_user_presence(),
        UnavailableUserVerification,
        selected_pin_uv_auth(),
        keys,
        entropy,
    );
}

#[cfg(all(not(feature = "dual-task"), not(feature = "flash-managed-keys")))]
pub const fn selected_ctaphid() -> SelectedCtaphid {
    CtaphidFrontend::new(
        Storage::new(SelectedStorage::new()),
        selected_user_presence(),
        UnavailableUserVerification,
        selected_pin_uv_auth(),
        SelectedKeyStore::new(),
        SelectedEntropy::new(),
    )
}

#[cfg(feature = "dual-task")]
pub type Ch32MailboxEndpoint = MailboxEndpoint<TRUSTED_REQUEST_MAX, TRUSTED_RESPONSE_MAX>;

#[cfg(feature = "dual-task")]
pub const fn selected_ctaphid(endpoint: &'static Ch32MailboxEndpoint) -> SelectedCtaphid {
    CtaphidFrontend::with_trusted_backend(MailboxTrustedBackend::new(LocalMailboxTransport::new(
        endpoint,
    )))
}

#[cfg(feature = "dual-task")]
/// Cooperative mailbox worker, not hardware isolation; one executor owns dispatcher and buffers.
pub struct Ch32LocalTrustedWorker {
    dispatcher: SelectedDispatcher,
    request: [u8; TRUSTED_REQUEST_MAX],
    response: [u8; TRUSTED_RESPONSE_MAX],
}

#[cfg(feature = "dual-task")]
impl Ch32LocalTrustedWorker {
    #[cfg(feature = "flash-managed-keys")]
    /// Initialize exclusive worker storage in place.
    ///
    /// # Safety
    /// Supply aligned writable uninitialized storage for Self with no readers or concurrent owners.
    pub unsafe fn initialize_at(destination: *mut Self) {
        unsafe {
            let dispatcher = core::ptr::addr_of_mut!((*destination).dispatcher)
                .cast::<core::mem::MaybeUninit<SelectedDispatcher>>();
            initialize_dispatcher(&mut *dispatcher);
            core::ptr::addr_of_mut!((*destination).request).write_bytes(0, 1);
            core::ptr::addr_of_mut!((*destination).response).write_bytes(0, 1);
        }
    }

    pub const fn new(dispatcher: SelectedDispatcher) -> Self {
        Self {
            dispatcher,
            request: [0; TRUSTED_REQUEST_MAX],
            response: [0; TRUSTED_RESPONSE_MAX],
        }
    }

    pub fn pump(&mut self, endpoint: &Ch32MailboxEndpoint) {
        let _ = endpoint.pump_operation_once(
            &mut self.dispatcher,
            &mut self.request,
            &mut self.response,
        );
    }
}
