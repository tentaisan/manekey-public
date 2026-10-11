#[cfg(not(feature = "up-always-present"))]
use esp_hal::gpio::{Input, InputConfig, Pull};
#[cfg(any(feature = "client-pin-flash", feature = "pmp-persistent-pin"))]
use esp_hal::peripherals::AES;
use esp_hal::peripherals::GPIO28;
#[cfg(feature = "ble")]
use esp_hal::peripherals::{FLASH, SHA};
#[cfg(any(
    feature = "experimental-ml-dsa-fips204",
    feature = "ble-ml-dsa-native",
    feature = "pmp-internal-uart-ml-dsa"
))]
use manekey::ctaphid::key_store::AdditionalSignaturePrivateKeyStore;
#[cfg(any(feature = "client-pin-flash", feature = "pmp-persistent-pin"))]
use manekey::ctaphid::pin_uv_auth::JournaledPinUvAuthStorage;
#[cfg(not(feature = "up-always-present"))]
use manekey::presence::{DEFAULT_GPIO_PRESENCE_STABLE_MILLIS, TimedPresenceConfig};
#[cfg(feature = "ble")]
use manekey::transport;
#[cfg(feature = "ble")]
use manekey::transport::ble::BleFidoFrontend;
use manekey::{
    ctaphid::{
        key_store::DerivedPrivateKeyStore, pin_uv_auth::UnconfiguredPinUvAuth, storage::Storage,
        trusted::TrustedDispatcher, user_verification::UnavailableUserVerification,
    },
    user_interface::UiPresenceObserver,
};

#[cfg(feature = "up-always-present")]
use manekey::presence::AlwaysPresent;

#[cfg(not(feature = "up-always-present"))]
use crate::presence::EspGpioUserPresence;
#[cfg(any(feature = "client-pin-flash", feature = "pmp-persistent-pin"))]
use crate::storage::{SharedEspFlash, SharedEspFlashCredentialStorage};
use crate::{
    crypto::EspSha256, entropy::EspEntropy, presence::EspTextPresenceObserver,
    storage::EspFlashCredentialStorage,
};
#[cfg(feature = "ble")]
use crate::{crypto::build_device_key_store_from_sha, entropy::build_radio_entropy};

#[cfg(feature = "up-always-present")]
type SelectedPresence = AlwaysPresent;
#[cfg(not(feature = "up-always-present"))]
type SelectedPresence = EspGpioUserPresence<'static>;

/// Dispatcher composition is not hardware isolation; legacy derivation is not a hardware-protected root.
pub type EspTrustedDispatcher = TrustedDispatcher<
    EspFlashCredentialStorage<'static>,
    SelectedPresence,
    UnavailableUserVerification,
    UnconfiguredPinUvAuth,
    DerivedPrivateKeyStore<EspSha256<'static>>,
    EspEntropy,
    UiPresenceObserver<EspTextPresenceObserver, &'static manekey::user_interface::AtomicUiStatus>,
>;

#[cfg(feature = "up-always-present")]
fn selected_presence(_boot: GPIO28<'static>) -> SelectedPresence {
    AlwaysPresent
}

#[cfg(not(feature = "up-always-present"))]
fn selected_presence(boot: GPIO28<'static>) -> SelectedPresence {
    const CONFIG: TimedPresenceConfig =
        TimedPresenceConfig::low_active_button("boot", DEFAULT_GPIO_PRESENCE_STABLE_MILLIS, 20_000);
    EspGpioUserPresence::from_input(
        Input::new(boot, InputConfig::default().with_pull(Pull::Up)),
        CONFIG,
        true,
        "GPIO28 BOOT",
    )
}

#[cfg(feature = "ble")]
pub fn build_ble_fido_frontend_from_parts(
    flash: FLASH<'static>,
    boot: GPIO28<'static>,
    sha: SHA<'static>,
    max_fragment_len: usize,
) -> BleFidoFrontend<EspTrustedDispatcher> {
    BleFidoFrontend::new(
        max_fragment_len,
        build_ble_dispatcher_from_parts(flash, boot, sha),
    )
}

#[cfg(feature = "ble")]
/// Initialize only after BLE controller startup establishes the radio entropy precondition.
pub fn build_ble_dispatcher_from_parts(
    flash: FLASH<'static>,
    boot: GPIO28<'static>,
    sha: SHA<'static>,
) -> EspTrustedDispatcher {
    TrustedDispatcher::new_with_transports_and_presence_observer(
        Storage::new(EspFlashCredentialStorage::new(flash)),
        selected_presence(boot),
        UnavailableUserVerification,
        UnconfiguredPinUvAuth::new(),
        build_device_key_store_from_sha(sha),
        build_radio_entropy(),
        transport::BLE_TRANSPORTS,
        UiPresenceObserver::new(EspTextPresenceObserver, &crate::board_ui::UI_STATUS),
    )
}

#[cfg(any(feature = "client-pin-flash", feature = "pmp-persistent-pin"))]
#[cfg(not(feature = "flash-managed-keys"))]
type ClassicalSharedKeyStore = DerivedPrivateKeyStore<crate::client_pin::SharedEspSha256>;
#[cfg(feature = "flash-managed-keys")]
type ClassicalSharedKeyStore =
    crate::managed_key_storage::EspManagedKeyStore<crate::client_pin::SharedEspSha256>;

#[cfg(any(feature = "client-pin-flash", feature = "pmp-persistent-pin"))]
#[cfg(not(any(
    feature = "experimental-ml-dsa-fips204",
    feature = "ble-ml-dsa-native",
    feature = "pmp-internal-uart-ml-dsa"
)))]
type EspSharedKeyStore = ClassicalSharedKeyStore;
#[cfg(all(
    any(feature = "client-pin-flash", feature = "pmp-persistent-pin"),
    any(
        feature = "experimental-ml-dsa-fips204",
        feature = "ble-ml-dsa-native",
        feature = "pmp-internal-uart-ml-dsa"
    )
))]
type EspSharedKeyStore = AdditionalSignaturePrivateKeyStore<
    ClassicalSharedKeyStore,
    crate::ml_dsa_backend::SelectedMlDsaBackend,
>;

#[cfg(any(feature = "client-pin-flash", feature = "pmp-persistent-pin"))]
pub type EspSharedTrustedDispatcher = TrustedDispatcher<
    SharedEspFlashCredentialStorage<'static>,
    SelectedPresence,
    UnavailableUserVerification,
    crate::client_pin::EspSoftwarePinProvider<
        JournaledPinUvAuthStorage<crate::pin_flash_storage::EspFlashPinUvAuthStorage<'static>>,
    >,
    EspSharedKeyStore,
    EspEntropy,
    UiPresenceObserver<EspTextPresenceObserver, &'static manekey::user_interface::AtomicUiStatus>,
>;

#[cfg(feature = "client-pin-flash")]
/// Initialize shared peripherals once after controller startup; reserve journals exclusively and supply trusted UP.
pub fn build_ble_dispatcher_from_shared_flash(
    flash: &'static SharedEspFlash<'static>,
    boot: GPIO28<'static>,
    sha: SHA<'static>,
    aes: AES<'static>,
) -> EspSharedTrustedDispatcher {
    let mut records = Storage::new(SharedEspFlashCredentialStorage::new(flash));
    let mut entropy = build_radio_entropy();
    let pin_storage = JournaledPinUvAuthStorage::new(
        crate::pin_flash_storage::EspFlashPinUvAuthStorage::new(flash),
    );
    #[cfg(not(feature = "flash-managed-keys"))]
    let (key_store, pin_uv_auth) =
        crate::client_pin::build_software_pin_backends(sha, aes, pin_storage);
    #[cfg(feature = "flash-managed-keys")]
    let (key_store, pin_uv_auth) = {
        let hash = crate::client_pin::init_shared_hash(sha);
        let keys = open_managed(flash, &mut records, &mut entropy, hash);
        (
            keys,
            crate::client_pin::pin_from_hash(hash, aes, pin_storage),
        )
    };
    #[cfg(any(feature = "experimental-ml-dsa-fips204", feature = "ble-ml-dsa-native"))]
    let key_store =
        AdditionalSignaturePrivateKeyStore::new(key_store, crate::ml_dsa_backend::init_backend());
    TrustedDispatcher::new_with_transports_and_presence_observer(
        records,
        selected_presence(boot),
        UnavailableUserVerification,
        pin_uv_auth,
        key_store,
        entropy,
        transport::BLE_TRANSPORTS,
        UiPresenceObserver::new(EspTextPresenceObserver, &crate::board_ui::UI_STATUS),
    )
}

#[cfg(feature = "pmp-persistent-pin")]
const INTERNAL_INGRESS_TRANSPORTS: &[&[u8]] = &[];

#[cfg(feature = "pmp-persistent-pin")]
pub type EspPmpUiTrustedDispatcher<U> = TrustedDispatcher<
    SharedEspFlashCredentialStorage<'static>,
    SelectedPresence,
    UnavailableUserVerification,
    crate::client_pin::EspSoftwarePinProvider<
        JournaledPinUvAuthStorage<crate::pin_flash_storage::EspFlashPinUvAuthStorage<'static>>,
    >,
    EspSharedKeyStore,
    crate::entropy::C5AdcDrbgEntropy,
    UiPresenceObserver<EspTextPresenceObserver, U>,
>;

#[cfg(feature = "pmp-persistent-pin")]
/// BLE-less composition; caller keeps flash, SHA, AES, UI and dispatcher M-mode-private.
/// Internal ingress advertises no USB/BLE/NFC wire transport; entropy remains experimental.
pub fn build_pmp_internal_dispatcher_from_shared_flash<
    U: manekey::user_interface::UiStatusOutput,
>(
    flash: &'static SharedEspFlash<'static>,
    boot: GPIO28<'static>,
    sha_state: &'static crate::client_pin::SharedEspShaPeripheral,
    aes: AES<'static>,
    ui_output: U,
    mut entropy: crate::entropy::C5AdcDrbgEntropy,
) -> EspPmpUiTrustedDispatcher<U> {
    let mut records = Storage::new(SharedEspFlashCredentialStorage::new(flash));
    let pin_storage = JournaledPinUvAuthStorage::new(
        crate::pin_flash_storage::EspFlashPinUvAuthStorage::new(flash),
    );
    #[cfg(not(feature = "flash-managed-keys"))]
    let (key_store, pin_uv_auth) =
        crate::client_pin::build_software_pin_backends_from_shared(sha_state, aes, pin_storage);
    #[cfg(feature = "flash-managed-keys")]
    let (key_store, pin_uv_auth) = {
        let hash = crate::client_pin::shared_hash_from_peripheral(sha_state);
        let keys = open_managed(flash, &mut records, &mut entropy, hash);
        (
            keys,
            crate::client_pin::pin_from_hash(hash, aes, pin_storage),
        )
    };
    #[cfg(any(
        feature = "experimental-ml-dsa-fips204",
        feature = "pmp-internal-uart-ml-dsa"
    ))]
    let key_store =
        AdditionalSignaturePrivateKeyStore::new(key_store, crate::ml_dsa_backend::init_backend());
    TrustedDispatcher::new_with_transports_and_presence_observer(
        records,
        selected_presence(boot),
        UnavailableUserVerification,
        pin_uv_auth,
        key_store,
        entropy,
        INTERNAL_INGRESS_TRANSPORTS,
        UiPresenceObserver::new(EspTextPresenceObserver, ui_output),
    )
}

#[cfg(feature = "flash-managed-keys")]
fn open_managed<E: manekey::ctaphid::entropy::EntropySource>(
    flash: &'static SharedEspFlash<'static>,
    records: &mut Storage<SharedEspFlashCredentialStorage<'static>>,
    entropy: &mut E,
    hash: crate::client_pin::SharedEspSha256,
) -> ClassicalSharedKeyStore {
    use crate::{
        flash_region::{EspFlashRegion, EspFlashStorageSource},
        managed_key_storage::ManagedKeyConfig,
    };

    let region = EspFlashRegion {
        base: crate::board::FLASH_MANAGED_BASE,
        len: 8192,
        source: EspFlashStorageSource::Fallback,
    };
    let exclusive = flash.lock(|cell| {
        let mut data = [0; esp_bootloader_esp_idf::partitions::PARTITION_TABLE_MAX_LEN];
        let mut media = cell.borrow_mut();
        let Ok(table) =
            esp_bootloader_esp_idf::partitions::read_partition_table(&mut *media, &mut data)
        else {
            return false;
        };
        table.iter().all(|part| {
            part.offset()
                .checked_add(part.len())
                .is_some_and(|end| end <= region.base || part.offset() >= region.base + region.len)
        })
    });
    assert!(
        exclusive,
        "C5 managed region overlaps partition or invalid table"
    );
    crate::managed_key_storage::open_classical(
        flash,
        ManagedKeyConfig {
            region,
            owner: *b"ESP-FID1",
            handle_domain: b"manekey-esp-flash-handle-v1",
            prf_domain: b"manekey-esp-flash-prf-v1",
            allow_setup: cfg!(feature = "flash-managed-key-setup"),
        },
        records,
        entropy,
        hash,
    )
    .unwrap_or_else(|error| {
        esp_println::println!("ESP managed factory failed: {error:?}");
        panic!("managed key factory failed closed")
    })
}
