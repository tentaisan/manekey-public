#[cfg(feature = "client-pin-flash")]
use esp_hal::peripherals::AES;
use esp_hal::peripherals::{FLASH, GPIO2, GPIO9, SHA};
#[cfg(any(
    feature = "ml-dsa-fips204-backend",
    feature = "ml-dsa-mldsa-native-backend"
))]
use manekey::ctaphid::key_store::AdditionalSignaturePrivateKeyStore;
#[cfg(feature = "client-pin-flash")]
use manekey::ctaphid::pin_uv_auth::JournaledPinUvAuthStorage;
#[cfg(all(feature = "ml-dsa-fips204-backend", not(any())))]
use manekey::ctaphid::pqc_signature_fips204::Fips204MlDsa44;
#[cfg(feature = "ml-dsa-mldsa-native-backend")]
use manekey::ctaphid::pqc_signature_mldsa_native::MldsaNativeMlDsa44;
use manekey::ctaphid::{
    key_store::DerivedPrivateKeyStore, pin_uv_auth::UnconfiguredPinUvAuth, storage::Storage,
    trusted::TrustedDispatcher, user_verification::UnavailableUserVerification,
};
#[cfg(feature = "up-always-present")]
use manekey::presence::AlwaysPresent;
use manekey::transport;
use manekey::transport::ble::BleFidoFrontend;

#[cfg(not(feature = "up-always-present"))]
use crate::presence::EspGpioUserPresence;
use crate::presence::EspTextPresenceObserver;
#[cfg(any(feature = "client-pin-flash", feature = "internal-uart"))]
use crate::storage::{SharedEspFlash, SharedEspFlashCredentialStorage};
use crate::{
    crypto::{EspSha256, build_device_key_store_from_sha},
    entropy::{EspEntropy, build_trng_entropy},
    storage::EspFlashCredentialStorage,
};

#[cfg(feature = "up-always-present")]
type SelectedPresence = AlwaysPresent;
#[cfg(not(feature = "up-always-present"))]
type SelectedPresence = EspGpioUserPresence<'static>;

/// Feature-selected dispatcher, not hardware isolation; legacy derivation uses public MAC material.
pub type EspTrustedDispatcher = TrustedDispatcher<
    EspFlashCredentialStorage<'static>,
    SelectedPresence,
    UnavailableUserVerification,
    UnconfiguredPinUvAuth,
    DerivedPrivateKeyStore<EspSha256<'static>>,
    EspEntropy,
    EspTextPresenceObserver,
>;

pub fn build_dispatcher(
    flash: FLASH<'static>,
    presence: SelectedPresence,
    key_store: DerivedPrivateKeyStore<EspSha256<'static>>,
    entropy: EspEntropy,
) -> EspTrustedDispatcher {
    build_dispatcher_with_transports(
        flash,
        presence,
        key_store,
        entropy,
        transport::USB_TRANSPORTS,
    )
}

pub fn build_usb_dispatcher_from_parts(
    flash: FLASH<'static>,
    gpio2: GPIO2<'static>,
    sha: SHA<'static>,
) -> EspTrustedDispatcher {
    build_dispatcher(
        flash,
        selected_presence(gpio2),
        build_device_key_store_from_sha(sha),
        build_trng_entropy(),
    )
}

pub fn build_ble_dispatcher(
    flash: FLASH<'static>,
    presence: SelectedPresence,
    key_store: DerivedPrivateKeyStore<EspSha256<'static>>,
    entropy: EspEntropy,
) -> EspTrustedDispatcher {
    build_dispatcher_with_transports(
        flash,
        presence,
        key_store,
        entropy,
        transport::BLE_TRANSPORTS,
    )
}

pub fn build_ble_dispatcher_from_parts(
    flash: FLASH<'static>,
    gpio2: GPIO2<'static>,
    sha: SHA<'static>,
) -> EspTrustedDispatcher {
    build_ble_dispatcher(
        flash,
        selected_presence(gpio2),
        build_device_key_store_from_sha(sha),
        build_trng_entropy(),
    )
}

pub fn build_ble_fido_frontend(
    flash: FLASH<'static>,
    presence: SelectedPresence,
    key_store: DerivedPrivateKeyStore<EspSha256<'static>>,
    entropy: EspEntropy,
    max_fragment_len: usize,
) -> BleFidoFrontend<EspTrustedDispatcher> {
    BleFidoFrontend::new(
        max_fragment_len,
        build_ble_dispatcher(flash, presence, key_store, entropy),
    )
}

pub fn build_ble_fido_frontend_from_parts(
    flash: FLASH<'static>,
    gpio2: GPIO2<'static>,
    sha: SHA<'static>,
    max_fragment_len: usize,
) -> BleFidoFrontend<EspTrustedDispatcher> {
    BleFidoFrontend::new(
        max_fragment_len,
        build_ble_dispatcher_from_parts(flash, gpio2, sha),
    )
}

#[cfg(feature = "client-pin-flash")]
#[cfg(feature = "ml-dsa-fips204-backend")]

type SelectedMlDsaBackend = Fips204MlDsa44;

#[cfg(feature = "client-pin-flash")]
#[cfg(feature = "ml-dsa-fips204-backend")]
type EspSharedKeyStore =
    AdditionalSignaturePrivateKeyStore<ClassicalSharedKeyStore, SelectedMlDsaBackend>;
#[cfg(all(feature = "client-pin-flash", feature = "ml-dsa-mldsa-native-backend"))]
type EspSharedKeyStore =
    AdditionalSignaturePrivateKeyStore<ClassicalSharedKeyStore, MldsaNativeMlDsa44>;
#[cfg(all(
    feature = "client-pin-flash",
    not(any(
        feature = "ml-dsa-fips204-backend",
        feature = "ml-dsa-mldsa-native-backend"
    ))
))]
type EspSharedKeyStore = ClassicalSharedKeyStore;

#[cfg(all(feature = "client-pin-flash", not(feature = "flash-managed-keys")))]
type ClassicalSharedKeyStore = DerivedPrivateKeyStore<crate::client_pin::SharedEspSha256>;
#[cfg(feature = "flash-managed-keys")]
type ClassicalSharedKeyStore =
    crate::managed_key_storage::EspManagedKeyStore<crate::client_pin::SharedEspSha256>;

#[cfg(feature = "client-pin-flash")]
pub type EspSharedTrustedDispatcher = TrustedDispatcher<
    SharedEspFlashCredentialStorage<'static>,
    SelectedPresence,
    UnavailableUserVerification,
    crate::client_pin::EspSoftwarePinProvider<
        JournaledPinUvAuthStorage<crate::pin_flash_storage::EspFlashPinUvAuthStorage<'static>>,
    >,
    EspSharedKeyStore,
    EspEntropy,
    EspTextPresenceObserver,
>;

#[cfg(feature = "client-pin-flash")]
pub fn build_ble_fido_frontend_from_shared_flash(
    flash: &'static SharedEspFlash<'static>,
    gpio2: GPIO2<'static>,
    sha: SHA<'static>,
    aes: AES<'static>,
    max_fragment_len: usize,
) -> BleFidoFrontend<EspSharedTrustedDispatcher> {
    BleFidoFrontend::new(
        max_fragment_len,
        build_ble_dispatcher_from_shared_flash(flash, gpio2, sha, aes),
    )
}

#[cfg(feature = "client-pin-flash")]
pub fn build_ble_dispatcher_from_shared_flash(
    flash: &'static SharedEspFlash<'static>,
    gpio2: GPIO2<'static>,
    sha: SHA<'static>,
    aes: AES<'static>,
) -> EspSharedTrustedDispatcher {
    build_shared_dispatcher_from_shared_flash(
        flash,
        selected_presence(gpio2),
        sha,
        aes,
        transport::BLE_TRANSPORTS,
    )
}

#[cfg(feature = "client-pin-flash")]
pub fn build_internal_dispatcher_from_shared_flash(
    flash: &'static SharedEspFlash<'static>,
    gpio2: GPIO2<'static>,
    sha: SHA<'static>,
    aes: AES<'static>,
) -> EspSharedTrustedDispatcher {
    build_shared_dispatcher_from_shared_flash(flash, selected_presence(gpio2), sha, aes, &[])
}

#[cfg(feature = "client-pin-flash")]
pub fn build_internal_dispatcher_from_shared_flash_boot(
    flash: &'static SharedEspFlash<'static>,
    gpio9: GPIO9<'static>,
    sha: SHA<'static>,
    aes: AES<'static>,
) -> EspSharedTrustedDispatcher {
    build_shared_dispatcher_from_shared_flash(flash, selected_boot_presence(gpio9), sha, aes, &[])
}

#[cfg(feature = "client-pin-flash")]
/// Initializes shared peripherals once; caller reserves plaintext journals and owns exclusion/UP policy.
/// Managed setup/failure may initialize an empty root or panic according to explicit features.
fn build_shared_dispatcher_from_shared_flash(
    flash: &'static SharedEspFlash<'static>,
    presence: SelectedPresence,
    sha: SHA<'static>,
    aes: AES<'static>,
    transports: &'static [&'static [u8]],
) -> EspSharedTrustedDispatcher {
    let pin_storage = JournaledPinUvAuthStorage::new(
        crate::pin_flash_storage::EspFlashPinUvAuthStorage::new(flash),
    );
    let mut records = Storage::new(SharedEspFlashCredentialStorage::new(flash));
    let mut entropy = build_trng_entropy();
    #[cfg(not(feature = "flash-managed-keys"))]
    let (key_store, pin_uv_auth) =
        crate::client_pin::build_software_pin_backends(sha, aes, pin_storage);
    #[cfg(feature = "flash-managed-keys")]
    let (key_store, pin_uv_auth) = {
        let hash = crate::client_pin::init_shared_hash(sha);
        let region = crate::managed_key_storage::require_partition(
            flash,
            crate::board::FLASH_MANAGED_BASE,
            crate::board::FLASH_MANAGED_SIZE,
        );
        let keys = crate::managed_key_storage::open_classical(
            flash,
            crate::managed_key_storage::ManagedKeyConfig {
                region,
                owner: *b"ESP-FID1",
                handle_domain: b"manekey-esp-flash-handle-v1",
                prf_domain: b"manekey-esp-flash-prf-v1",
                allow_setup: cfg!(feature = "flash-managed-key-setup"),
            },
            &mut records,
            &mut entropy,
            hash,
        )
        .unwrap_or_else(|error| {
            esp_println::println!("ESP managed factory failed: {error:?}");
            panic!("managed key factory failed closed")
        });
        (
            keys,
            crate::client_pin::pin_from_hash(hash, aes, pin_storage),
        )
    };
    #[cfg(feature = "ml-dsa-fips204-backend")]
    let key_store =
        AdditionalSignaturePrivateKeyStore::new(key_store, SelectedMlDsaBackend::default());
    #[cfg(feature = "ml-dsa-mldsa-native-backend")]
    let key_store = AdditionalSignaturePrivateKeyStore::new(key_store, MldsaNativeMlDsa44);
    TrustedDispatcher::new_with_transports_and_presence_observer(
        records,
        presence,
        UnavailableUserVerification,
        pin_uv_auth,
        key_store,
        entropy,
        transports,
        EspTextPresenceObserver,
    )
}

pub fn build_dispatcher_with_transports(
    flash: FLASH<'static>,
    presence: SelectedPresence,
    key_store: DerivedPrivateKeyStore<EspSha256<'static>>,
    entropy: EspEntropy,
    transports: &'static [&'static [u8]],
) -> EspTrustedDispatcher {
    TrustedDispatcher::new_with_transports_and_presence_observer(
        Storage::new(EspFlashCredentialStorage::new(flash)),
        presence,
        UnavailableUserVerification,
        UnconfiguredPinUvAuth::new(),
        key_store,
        entropy,
        transports,
        EspTextPresenceObserver,
    )
}

#[cfg(feature = "up-always-present")]
fn selected_presence(_gpio2: GPIO2<'static>) -> SelectedPresence {
    AlwaysPresent
}

#[cfg(not(feature = "up-always-present"))]
fn selected_presence(gpio2: GPIO2<'static>) -> SelectedPresence {
    EspGpioUserPresence::from_gpio2(gpio2)
}

#[cfg(feature = "up-always-present")]
fn selected_boot_presence(_gpio9: GPIO9<'static>) -> SelectedPresence {
    AlwaysPresent
}

#[cfg(not(feature = "up-always-present"))]
fn selected_boot_presence(gpio9: GPIO9<'static>) -> SelectedPresence {
    EspGpioUserPresence::from_gpio9(gpio9)
}
