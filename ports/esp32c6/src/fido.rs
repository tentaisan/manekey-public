use esp_hal::peripherals::{AES, ECC, FLASH, GPIO2, SHA};
#[cfg(feature = "experimental-p256-accelerator")]
use manekey::ctaphid::crypto::Sha256ClientPinCrypto;
#[cfg(any(
    feature = "ml-dsa-fips204-backend",
    feature = "ml-dsa-mldsa-native-backend"
))]
use manekey::ctaphid::key_store::AdditionalSignaturePrivateKeyStore;
#[cfg(any(feature = "client-pin-flash", feature = "pmp-persistent-pin"))]
use manekey::ctaphid::pin_uv_auth::JournaledPinUvAuthStorage;
#[cfg(not(feature = "client-pin-volatile"))]
use manekey::ctaphid::pin_uv_auth::UnconfiguredPinUvAuth;
#[cfg(feature = "client-pin-volatile")]
use manekey::ctaphid::pin_uv_auth::{
    PinUvAuthStateStorage, StoredPinUvAuthProvider, VolatilePinUvAuthStorage,
};
#[cfg(feature = "ml-dsa-fips204-backend")]
use manekey::ctaphid::pqc_signature_fips204::Fips204MlDsa44;
#[cfg(feature = "ml-dsa-mldsa-native-backend")]
use manekey::ctaphid::pqc_signature_mldsa_native::MldsaNativeMlDsa44;
use manekey::ctaphid::{
    key_store::DerivedPrivateKeyStore, storage::Storage, trusted::TrustedDispatcher,
    user_verification::UnavailableUserVerification,
};
#[cfg(feature = "up-always-present")]
use manekey::presence::AlwaysPresent;
use manekey::transport;
use manekey::transport::ble::BleFidoFrontend;
use manekey::user_interface::UiPresenceObserver;
#[cfg(feature = "pmp-persistent-pin")]
use manekey::user_interface::UiStatusOutput;

#[cfg(feature = "pmp-persistent-pin")]
use crate::client_pin::SharedEspShaPeripheral;
#[cfg(feature = "client-pin-volatile")]
use crate::client_pin::{EspTokenClock, SharedEspSha256};
#[cfg(not(feature = "client-pin-volatile"))]
use crate::crypto::EspSha256;
#[cfg(not(feature = "client-pin-volatile"))]
use crate::crypto::build_device_key_store_from_sha;
#[cfg(not(feature = "up-always-present"))]
use crate::presence::EspGpioUserPresence;
use crate::presence::EspTextPresenceObserver;
#[cfg(any(feature = "ble-security", feature = "pmp-persistent-pin"))]
use crate::storage::{SharedEspFlash, SharedEspFlashCredentialStorage};
use crate::{
    entropy::{EspEntropy, build_trng_entropy},
    storage::EspFlashCredentialStorage,
};
#[cfg(feature = "up-always-present")]
type SelectedPresence = AlwaysPresent;
#[cfg(not(feature = "up-always-present"))]
type SelectedPresence = EspGpioUserPresence<'static>;

#[cfg(not(feature = "client-pin-volatile"))]
pub type EspPinUvAuth = UnconfiguredPinUvAuth;

#[cfg(not(feature = "client-pin-volatile"))]
pub type EspKeyStore = DerivedPrivateKeyStore<EspSha256<'static>>;
#[cfg(feature = "client-pin-volatile")]
pub type EspKeyStore = DerivedPrivateKeyStore<SharedEspSha256>;

#[cfg(not(feature = "flash-managed-keys"))]
type ClassicalSharedKeyStore = EspKeyStore;
#[cfg(feature = "flash-managed-keys")]
type ClassicalSharedKeyStore = crate::managed_key_storage::EspManagedKeyStore<SharedEspSha256>;

#[cfg(all(
    feature = "client-pin-volatile",
    not(feature = "experimental-p256-accelerator")
))]
type SelectedClientPinCrypto = crate::client_pin::EspSoftwarePinCrypto;
#[cfg(feature = "experimental-p256-accelerator")]
type SelectedClientPinCrypto = Sha256ClientPinCrypto<
    SharedEspSha256,
    crate::crypto::EspAes256<'static>,
    crate::p256::EspP256Ecdh<'static>,
>;

#[cfg(feature = "client-pin-volatile")]
pub type EspPinUvAuth =
    StoredPinUvAuthProvider<VolatilePinUvAuthStorage, SelectedClientPinCrypto, EspTokenClock>;

#[cfg(any(feature = "client-pin-flash", feature = "pmp-persistent-pin"))]
type EspSharedPinUvAuth = StoredPinUvAuthProvider<
    JournaledPinUvAuthStorage<crate::pin_flash_storage::EspFlashPinUvAuthStorage<'static>>,
    SelectedClientPinCrypto,
    EspTokenClock,
>;
#[cfg(all(feature = "ble-security", not(feature = "client-pin-flash")))]
type EspSharedPinUvAuth = EspPinUvAuth;

#[cfg(all(
    any(feature = "client-pin-flash", feature = "pmp-persistent-pin"),
    feature = "ml-dsa-fips204-backend"
))]
type EspSharedKeyStore =
    AdditionalSignaturePrivateKeyStore<ClassicalSharedKeyStore, Fips204MlDsa44>;
#[cfg(all(
    any(feature = "client-pin-flash", feature = "pmp-persistent-pin"),
    feature = "ml-dsa-mldsa-native-backend"
))]
type EspSharedKeyStore =
    AdditionalSignaturePrivateKeyStore<ClassicalSharedKeyStore, MldsaNativeMlDsa44>;
#[cfg(all(
    any(feature = "client-pin-flash", feature = "pmp-persistent-pin"),
    not(any(
        feature = "ml-dsa-fips204-backend",
        feature = "ml-dsa-mldsa-native-backend"
    ))
))]
type EspSharedKeyStore = ClassicalSharedKeyStore;
#[cfg(all(
    feature = "ble-security",
    not(any(feature = "client-pin-flash", feature = "pmp-persistent-pin"))
))]
type EspSharedKeyStore = EspKeyStore;

#[cfg(not(feature = "client-pin-volatile"))]
fn build_crypto_backends(
    sha: SHA<'static>,
    _aes: AES<'static>,
    _ecc: ECC<'static>,
) -> (EspKeyStore, EspPinUvAuth) {
    (
        build_device_key_store_from_sha(sha),
        UnconfiguredPinUvAuth::new(),
    )
}

#[cfg(feature = "client-pin-volatile")]
fn build_crypto_backends_with_storage<S: PinUvAuthStateStorage>(
    sha: SHA<'static>,
    aes: AES<'static>,
    ecc: ECC<'static>,
    storage: S,
) -> (
    EspKeyStore,
    StoredPinUvAuthProvider<S, SelectedClientPinCrypto, EspTokenClock>,
) {
    #[cfg(not(feature = "experimental-p256-accelerator"))]
    {
        let _ = ecc;
        crate::client_pin::build_software_pin_backends(sha, aes, storage)
    }
    #[cfg(feature = "experimental-p256-accelerator")]
    {
        let (key_store, hash) = crate::client_pin::init_shared_sha(sha);
        let aes = crate::client_pin::checked_aes(aes);
        let mut p256 = crate::p256::EspP256Ecdh::new(ecc);
        manekey::ctaphid::crypto::verify_p256_ecdh_backend(&mut p256)
            .expect("experimental ESP32-C6 ECC P-256 startup self-test");
        esp_println::println!("ClientPIN P-256 experimental ESP32-C6 ECC backend enabled");
        let crypto = Sha256ClientPinCrypto::new_with_backends(hash, aes, p256);
        let pin =
            StoredPinUvAuthProvider::new_with_crypto_and_clock(storage, crypto, EspTokenClock);
        (key_store, pin)
    }
}

#[cfg(feature = "client-pin-volatile")]
fn build_crypto_backends(
    sha: SHA<'static>,
    aes: AES<'static>,
    ecc: ECC<'static>,
) -> (EspKeyStore, EspPinUvAuth) {
    build_crypto_backends_with_storage(sha, aes, ecc, VolatilePinUvAuthStorage::new())
}

/// Dispatcher composition is not hardware isolation; legacy derivation is not a hardware-protected root.
pub type EspTrustedDispatcher = TrustedDispatcher<
    EspFlashCredentialStorage<'static>,
    SelectedPresence,
    UnavailableUserVerification,
    EspPinUvAuth,
    EspKeyStore,
    EspEntropy,
    EspTextPresenceObserver,
>;

const INTERNAL_INGRESS_TRANSPORTS: &[&[u8]] = &[];

pub fn build_dispatcher(
    flash: FLASH<'static>,
    presence: SelectedPresence,
    key_store: EspKeyStore,
    pin_uv_auth: EspPinUvAuth,
    entropy: EspEntropy,
) -> EspTrustedDispatcher {
    build_dispatcher_with_transports(
        flash,
        presence,
        key_store,
        pin_uv_auth,
        entropy,
        transport::USB_TRANSPORTS,
    )
}

pub fn build_usb_dispatcher_from_parts(
    flash: FLASH<'static>,
    gpio2: GPIO2<'static>,
    sha: SHA<'static>,
    aes: AES<'static>,
    ecc: ECC<'static>,
) -> EspTrustedDispatcher {
    let (key_store, pin_uv_auth) = build_crypto_backends(sha, aes, ecc);
    build_dispatcher(
        flash,
        selected_presence(gpio2),
        key_store,
        pin_uv_auth,
        build_trng_entropy(),
    )
}

/// Internal ingress advertises no USB/BLE/NFC wire transport.
pub fn build_internal_dispatcher_from_parts(
    flash: FLASH<'static>,
    gpio2: GPIO2<'static>,
    sha: SHA<'static>,
    aes: AES<'static>,
    ecc: ECC<'static>,
) -> EspTrustedDispatcher {
    let (key_store, pin_uv_auth) = build_crypto_backends(sha, aes, ecc);
    build_dispatcher_with_transports(
        flash,
        selected_presence(gpio2),
        key_store,
        pin_uv_auth,
        build_trng_entropy(),
        INTERNAL_INGRESS_TRANSPORTS,
    )
}

pub fn build_ble_dispatcher(
    flash: FLASH<'static>,
    presence: SelectedPresence,
    key_store: EspKeyStore,
    pin_uv_auth: EspPinUvAuth,
    entropy: EspEntropy,
) -> EspTrustedDispatcher {
    build_dispatcher_with_transports(
        flash,
        presence,
        key_store,
        pin_uv_auth,
        entropy,
        transport::BLE_TRANSPORTS,
    )
}

pub fn build_ble_dispatcher_from_parts(
    flash: FLASH<'static>,
    gpio2: GPIO2<'static>,
    sha: SHA<'static>,
    aes: AES<'static>,
    ecc: ECC<'static>,
) -> EspTrustedDispatcher {
    let (key_store, pin_uv_auth) = build_crypto_backends(sha, aes, ecc);
    build_ble_dispatcher(
        flash,
        selected_presence(gpio2),
        key_store,
        pin_uv_auth,
        build_trng_entropy(),
    )
}

pub fn build_ble_fido_frontend(
    flash: FLASH<'static>,
    presence: SelectedPresence,
    key_store: EspKeyStore,
    pin_uv_auth: EspPinUvAuth,
    entropy: EspEntropy,
    max_fragment_len: usize,
) -> BleFidoFrontend<EspTrustedDispatcher> {
    BleFidoFrontend::new(
        max_fragment_len,
        build_ble_dispatcher(flash, presence, key_store, pin_uv_auth, entropy),
    )
}

pub fn build_ble_fido_frontend_from_parts(
    flash: FLASH<'static>,
    gpio2: GPIO2<'static>,
    sha: SHA<'static>,
    aes: AES<'static>,
    ecc: ECC<'static>,
    max_fragment_len: usize,
) -> BleFidoFrontend<EspTrustedDispatcher> {
    BleFidoFrontend::new(
        max_fragment_len,
        build_ble_dispatcher_from_parts(flash, gpio2, sha, aes, ecc),
    )
}

#[cfg(any(feature = "ble-security", feature = "pmp-persistent-pin"))]
pub type EspSharedTrustedDispatcher = TrustedDispatcher<
    SharedEspFlashCredentialStorage<'static>,
    SelectedPresence,
    UnavailableUserVerification,
    EspSharedPinUvAuth,
    EspSharedKeyStore,
    EspEntropy,
    UiPresenceObserver<EspTextPresenceObserver, &'static manekey::user_interface::AtomicUiStatus>,
>;

#[cfg(feature = "pmp-persistent-pin")]
pub type EspPmpUiTrustedDispatcher<U> = TrustedDispatcher<
    SharedEspFlashCredentialStorage<'static>,
    SelectedPresence,
    UnavailableUserVerification,
    EspSharedPinUvAuth,
    EspSharedKeyStore,
    EspEntropy,
    UiPresenceObserver<EspTextPresenceObserver, U>,
>;

#[cfg(feature = "ble-security")]
pub fn build_ble_fido_frontend_from_shared_flash(
    flash: &'static SharedEspFlash<'static>,
    gpio2: GPIO2<'static>,
    sha: SHA<'static>,
    aes: AES<'static>,
    ecc: ECC<'static>,
    max_fragment_len: usize,
) -> BleFidoFrontend<EspSharedTrustedDispatcher> {
    BleFidoFrontend::new(
        max_fragment_len,
        build_ble_dispatcher_from_shared_flash(flash, gpio2, sha, aes, ecc),
    )
}

#[cfg(feature = "ble-security")]
/// Initialize shared peripherals once; caller reserves journals and supplies trusted UP.
pub fn build_ble_dispatcher_from_shared_flash(
    flash: &'static SharedEspFlash<'static>,
    gpio2: GPIO2<'static>,
    sha: SHA<'static>,
    aes: AES<'static>,
    ecc: ECC<'static>,
) -> EspSharedTrustedDispatcher {
    let mut records = Storage::new(SharedEspFlashCredentialStorage::new(flash));
    let mut entropy = build_trng_entropy();
    #[cfg(all(feature = "client-pin-flash", not(feature = "flash-managed-keys")))]
    let (key_store, pin_uv_auth) = build_crypto_backends_with_storage(
        sha,
        aes,
        ecc,
        JournaledPinUvAuthStorage::new(crate::pin_flash_storage::EspFlashPinUvAuthStorage::new(
            flash,
        )),
    );
    #[cfg(not(feature = "client-pin-flash"))]
    let (key_store, pin_uv_auth) = build_crypto_backends(sha, aes, ecc);
    #[cfg(feature = "flash-managed-keys")]
    let (key_store, pin_uv_auth) = {
        let hash = crate::client_pin::init_shared_hash(sha);
        let keys = open_managed(flash, &mut records, &mut entropy, hash);
        let pin = managed_pin_from_hash(
            hash,
            aes,
            ecc,
            JournaledPinUvAuthStorage::new(
                crate::pin_flash_storage::EspFlashPinUvAuthStorage::new(flash),
            ),
        );
        (keys, pin)
    };
    #[cfg(feature = "ml-dsa-fips204-backend")]
    let key_store = AdditionalSignaturePrivateKeyStore::new(key_store, Fips204MlDsa44);
    #[cfg(feature = "ml-dsa-mldsa-native-backend")]
    let key_store = AdditionalSignaturePrivateKeyStore::new(key_store, MldsaNativeMlDsa44);
    TrustedDispatcher::new_with_transports_and_presence_observer(
        records,
        selected_presence(gpio2),
        UnavailableUserVerification,
        pin_uv_auth,
        key_store,
        entropy,
        transport::BLE_TRANSPORTS,
        UiPresenceObserver::new(EspTextPresenceObserver, &crate::board::UI_STATUS),
    )
}

#[cfg(feature = "pmp-persistent-pin")]
/// BLE-less composition; caller keeps flash, SHA, crypto, UI and dispatcher private to M-mode.
pub fn build_pmp_internal_dispatcher_from_shared_flash<U: UiStatusOutput>(
    flash: &'static SharedEspFlash<'static>,
    gpio2: GPIO2<'static>,
    aes: AES<'static>,
    ecc: ECC<'static>,
    sha_state: &'static SharedEspShaPeripheral,
    ui_output: U,
) -> EspPmpUiTrustedDispatcher<U> {
    #[cfg(not(feature = "flash-managed-keys"))]
    let _ = ecc;
    let mut records = Storage::new(SharedEspFlashCredentialStorage::new(flash));
    let mut entropy = build_trng_entropy();
    #[cfg(not(feature = "flash-managed-keys"))]
    let (key_store, pin_uv_auth) = crate::client_pin::build_software_pin_backends_from_shared(
        sha_state,
        aes,
        JournaledPinUvAuthStorage::new(crate::pin_flash_storage::EspFlashPinUvAuthStorage::new(
            flash,
        )),
    );
    #[cfg(feature = "flash-managed-keys")]
    let (key_store, pin_uv_auth) = {
        let hash = crate::client_pin::shared_hash_from_peripheral(sha_state);
        let keys = open_managed(flash, &mut records, &mut entropy, hash);
        let pin = managed_pin_from_hash(
            hash,
            aes,
            ecc,
            JournaledPinUvAuthStorage::new(
                crate::pin_flash_storage::EspFlashPinUvAuthStorage::new(flash),
            ),
        );
        (keys, pin)
    };
    #[cfg(feature = "ml-dsa-fips204-backend")]
    let key_store = AdditionalSignaturePrivateKeyStore::new(key_store, Fips204MlDsa44);
    #[cfg(feature = "ml-dsa-mldsa-native-backend")]
    let key_store = AdditionalSignaturePrivateKeyStore::new(key_store, MldsaNativeMlDsa44);
    TrustedDispatcher::new_with_transports_and_presence_observer(
        records,
        selected_presence(gpio2),
        UnavailableUserVerification,
        pin_uv_auth,
        key_store,
        entropy,
        INTERNAL_INGRESS_TRANSPORTS,
        UiPresenceObserver::new(EspTextPresenceObserver, ui_output),
    )
}

#[cfg(feature = "flash-managed-keys")]
fn managed_pin_from_hash<S: PinUvAuthStateStorage>(
    hash: SharedEspSha256,
    aes: AES<'static>,
    ecc: ECC<'static>,
    storage: S,
) -> StoredPinUvAuthProvider<S, SelectedClientPinCrypto, EspTokenClock> {
    #[cfg(not(feature = "experimental-p256-accelerator"))]
    {
        let _ = ecc;
        crate::client_pin::pin_from_hash(hash, aes, storage)
    }
    #[cfg(feature = "experimental-p256-accelerator")]
    {
        let aes = crate::client_pin::checked_aes(aes);
        let mut p256 = crate::p256::EspP256Ecdh::new(ecc);
        manekey::ctaphid::crypto::verify_p256_ecdh_backend(&mut p256)
            .expect("experimental ESP32-C6 ECC P-256 startup self-test");
        let crypto = Sha256ClientPinCrypto::new_with_backends(hash, aes, p256);
        StoredPinUvAuthProvider::new_with_crypto_and_clock(storage, crypto, EspTokenClock)
    }
}

#[cfg(feature = "flash-managed-keys")]
fn open_managed(
    flash: &'static SharedEspFlash<'static>,
    records: &mut Storage<SharedEspFlashCredentialStorage<'static>>,
    entropy: &mut EspEntropy,
    hash: SharedEspSha256,
) -> ClassicalSharedKeyStore {
    let region = flash.lock(|cell| {
        let mut media = cell.borrow_mut();
        let region = crate::flash_region::find_partition_region(
            &mut media,
            "key-assets",
            crate::board::FLASH_MANAGED_SIZE,
        )
        .expect("dedicated managed key partition required");
        assert_eq!(region.base, crate::board::FLASH_MANAGED_BASE);
        assert_eq!(region.len, crate::board::FLASH_MANAGED_SIZE);
        let mut data = [0; esp_bootloader_esp_idf::partitions::PARTITION_TABLE_MAX_LEN];
        let table =
            esp_bootloader_esp_idf::partitions::read_partition_table(&mut *media, &mut data)
                .expect("valid partition table");
        assert!(
            table.iter().all(|part| {
                if part.label_as_str() == "key-assets" {
                    return part.offset() == region.base && part.len() == region.len;
                }
                part.offset().checked_add(part.len()).is_some_and(|end| {
                    end <= region.base || part.offset() >= region.base + region.len
                })
            }),
            "managed partition overlaps another partition"
        );
        region
    });
    crate::managed_key_storage::open_classical(
        flash,
        crate::managed_key_storage::ManagedKeyConfig {
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

pub fn build_dispatcher_with_transports(
    flash: FLASH<'static>,
    presence: SelectedPresence,
    key_store: EspKeyStore,
    pin_uv_auth: EspPinUvAuth,
    entropy: EspEntropy,
    transports: &'static [&'static [u8]],
) -> EspTrustedDispatcher {
    TrustedDispatcher::new_with_transports_and_presence_observer(
        Storage::new(EspFlashCredentialStorage::new(flash)),
        presence,
        UnavailableUserVerification,
        pin_uv_auth,
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
