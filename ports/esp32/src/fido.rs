#[cfg(feature = "client-pin-flash")]
use esp_hal::peripherals::AES;
use esp_hal::peripherals::{FLASH, SHA};
#[cfg(feature = "client-pin-flash")]
use manekey::ctaphid::pin_uv_auth::JournaledPinUvAuthStorage;
use manekey::ctaphid::{
    pin_uv_auth::UnconfiguredPinUvAuth, storage::Storage, trusted::TrustedDispatcher,
    user_verification::UnavailableUserVerification,
};
use manekey::transport::{BLE_TRANSPORTS, ble::BleFidoFrontend};
use manekey::user_interface::UiPresenceObserver;

#[cfg(feature = "client-pin-flash")]
use crate::storage::{SharedEspFlash, SharedEspFlashCredentialStorage};
use crate::{
    crypto::build_device_key_store_from_sha,
    entropy::{EspEntropy, build_trng_entropy},
    presence::{EspGpioUserPresence, EspTextPresenceObserver},
    storage::EspFlashCredentialStorage,
};

/// Software dispatcher composition, not MPU isolation; legacy derivation uses public MAC material.
pub type EspTrustedDispatcher = TrustedDispatcher<
    EspFlashCredentialStorage<'static>,
    EspGpioUserPresence<'static>,
    UnavailableUserVerification,
    UnconfiguredPinUvAuth,
    manekey::ctaphid::key_store::DerivedPrivateKeyStore<crate::crypto::EspSha256<'static>>,
    EspEntropy,
    EspBoardPresenceObserver,
>;

pub type EspBoardPresenceObserver =
    UiPresenceObserver<EspTextPresenceObserver, crate::ui::EspGpioUiOutput>;

pub fn build_ble_fido_frontend(
    flash: FLASH<'static>,
    presence: EspGpioUserPresence<'static>,
    ui_output: crate::ui::EspGpioUiOutput,
    sha: SHA<'static>,
    max_fragment_len: usize,
) -> BleFidoFrontend<EspTrustedDispatcher> {
    BleFidoFrontend::new(
        max_fragment_len,
        TrustedDispatcher::new_with_transports_and_presence_observer(
            Storage::new(EspFlashCredentialStorage::new(flash)),
            presence,
            UnavailableUserVerification,
            UnconfiguredPinUvAuth::new(),
            build_device_key_store_from_sha(sha),
            build_trng_entropy(),
            BLE_TRANSPORTS,
            UiPresenceObserver::new(EspTextPresenceObserver, ui_output),
        ),
    )
}

#[cfg(feature = "client-pin-flash")]
pub type EspSharedTrustedDispatcher = TrustedDispatcher<
    SharedEspFlashCredentialStorage<'static>,
    EspGpioUserPresence<'static>,
    UnavailableUserVerification,
    crate::client_pin::EspSoftwarePinProvider<
        JournaledPinUvAuthStorage<crate::pin_flash_storage::EspFlashPinUvAuthStorage<'static>>,
    >,
    manekey::ctaphid::key_store::DerivedPrivateKeyStore<crate::client_pin::SharedEspSha256>,
    EspEntropy,
    EspBoardPresenceObserver,
>;

#[cfg(feature = "client-pin-flash")]
pub fn build_ble_fido_frontend_from_shared_flash(
    flash: &'static SharedEspFlash<'static>,
    presence: EspGpioUserPresence<'static>,
    ui_output: crate::ui::EspGpioUiOutput,
    sha: SHA<'static>,
    aes: AES<'static>,
    max_fragment_len: usize,
) -> BleFidoFrontend<EspSharedTrustedDispatcher> {
    BleFidoFrontend::new(
        max_fragment_len,
        build_ble_dispatcher_from_shared_flash(flash, presence, ui_output, sha, aes),
    )
}

#[cfg(feature = "client-pin-flash")]
/// Initializes shared peripherals once; caller reserves plaintext journals and supplies trusted UP.
pub fn build_ble_dispatcher_from_shared_flash(
    flash: &'static SharedEspFlash<'static>,
    presence: EspGpioUserPresence<'static>,
    ui_output: crate::ui::EspGpioUiOutput,
    sha: SHA<'static>,
    aes: AES<'static>,
) -> EspSharedTrustedDispatcher {
    let pin_storage = JournaledPinUvAuthStorage::new(
        crate::pin_flash_storage::EspFlashPinUvAuthStorage::new(flash),
    );
    let (key_store, pin_uv_auth) =
        crate::client_pin::build_software_pin_backends(sha, aes, pin_storage);
    TrustedDispatcher::new_with_transports_and_presence_observer(
        Storage::new(SharedEspFlashCredentialStorage::new(flash)),
        presence,
        UnavailableUserVerification,
        pin_uv_auth,
        key_store,
        build_trng_entropy(),
        BLE_TRANSPORTS,
        UiPresenceObserver::new(EspTextPresenceObserver, ui_output),
    )
}
