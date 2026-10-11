#[cfg(feature = "board-ui")]
use esp_hal::peripherals::GPIO0;
use esp_hal::peripherals::{AES, FLASH, GPIO2, SHA};
#[cfg(any(
    feature = "experimental-ml-dsa-fips204",
    feature = "experimental-ml-dsa-fips204-scratch",
    feature = "experimental-ml-dsa-mldsa-native"
))]
use manekey::ctaphid::key_store::AdditionalSignaturePrivateKeyStore;
#[cfg(feature = "client-pin-flash")]
use manekey::ctaphid::pin_uv_auth::JournaledPinUvAuthStorage;
#[cfg(not(feature = "client-pin-volatile"))]
use manekey::ctaphid::pin_uv_auth::UnconfiguredPinUvAuth;
#[cfg(all(feature = "client-pin-volatile", not(feature = "client-pin-flash")))]
use manekey::ctaphid::pin_uv_auth::VolatilePinUvAuthStorage;
#[cfg(feature = "experimental-ml-dsa-fips204")]
use manekey::ctaphid::pqc_signature_fips204::Fips204MlDsa44;
#[cfg(feature = "experimental-ml-dsa-fips204-scratch")]
use manekey::ctaphid::pqc_signature_fips204_scratch::Fips204ScratchMlDsa44;
#[cfg(feature = "experimental-ml-dsa-mldsa-native")]
use manekey::ctaphid::pqc_signature_mldsa_native::MldsaNativeMlDsa44;
#[cfg(feature = "client-pin-volatile")]
use manekey::ctaphid::{
    crypto::Sha256ClientPinCrypto,
    hash::{Sha256Backend, Sha256Error},
    pin_uv_auth::{PinUvAuthStateStorage, PinUvAuthTokenClock, StoredPinUvAuthProvider},
};

#[cfg(any(
    all(
        feature = "experimental-ml-dsa-fips204",
        feature = "experimental-ml-dsa-fips204-scratch"
    ),
    all(
        feature = "experimental-ml-dsa-fips204",
        feature = "experimental-ml-dsa-mldsa-native"
    ),
    all(
        feature = "experimental-ml-dsa-fips204-scratch",
        feature = "experimental-ml-dsa-mldsa-native"
    )
))]
compile_error!("select exactly one ESP ML-DSA backend");
use manekey::ctaphid::{
    key_store::DerivedPrivateKeyStore, storage::Storage, trusted::TrustedDispatcher,
    user_verification::UnavailableUserVerification,
};
#[cfg(feature = "up-always-present")]
use manekey::presence::AlwaysPresent;
use manekey::presence::PresenceObserver;
#[cfg(any(feature = "ble-security", feature = "client-pin-flash"))]
use manekey::presence::UserPresence;
use manekey::transport;
use manekey::transport::ble::BleFidoFrontend;
use manekey::user_interface::UiPresenceObserver;
use manekey::user_interface::UiStatusOutput;

#[cfg(not(feature = "client-pin-volatile"))]
pub type EspPinUvAuth = UnconfiguredPinUvAuth;
#[cfg(all(feature = "client-pin-volatile", not(feature = "client-pin-flash")))]
pub type EspPinUvAuth = StoredPinUvAuthProvider<
    VolatilePinUvAuthStorage,
    Sha256ClientPinCrypto<SharedEspSha256, crate::crypto::EspAes256<'static>>,
    EspTokenClock,
>;
#[cfg(feature = "client-pin-flash")]
pub type EspPinUvAuth = StoredPinUvAuthProvider<
    JournaledPinUvAuthStorage<crate::pin_flash_storage::EspFlashPinUvAuthStorage<'static>>,
    Sha256ClientPinCrypto<SharedEspSha256, crate::crypto::EspAes256<'static>>,
    EspTokenClock,
>;

#[cfg(feature = "client-pin-volatile")]
#[derive(Clone, Copy)]
pub struct EspTokenClock;

#[cfg(feature = "client-pin-volatile")]
impl PinUvAuthTokenClock for EspTokenClock {
    fn now_ms(&self) -> u64 {
        embassy_time::Instant::now().as_millis()
    }
}

#[cfg(not(feature = "client-pin-volatile"))]
use crate::crypto::build_device_key_store_from_sha;
#[cfg(any(feature = "ble-security", feature = "client-pin-flash"))]
use crate::storage::{SharedEspFlash, SharedEspFlashCredentialStorage};
use crate::{
    crypto::EspSha256,
    entropy::{EspEntropy, build_trng_entropy},
    presence::{EspGpioUserPresence, EspTextPresenceObserver},
    storage::EspFlashCredentialStorage,
};

#[cfg(feature = "client-pin-volatile")]
use core::cell::RefCell;
#[cfg(feature = "client-pin-volatile")]
use embassy_sync::blocking_mutex::{Mutex, raw::CriticalSectionRawMutex};
#[cfg(feature = "client-pin-volatile")]
use esp_hal::efuse;
#[cfg(feature = "client-pin-volatile")]
use esp_println::println;
#[cfg(feature = "client-pin-volatile")]
use static_cell::StaticCell;

#[cfg(feature = "client-pin-volatile")]
type SharedEspShaPeripheral = Mutex<CriticalSectionRawMutex, RefCell<EspSha256<'static>>>;

#[cfg(feature = "client-pin-volatile")]
#[derive(Clone, Copy)]
pub struct SharedEspSha256 {
    shared: &'static SharedEspShaPeripheral,
}

#[cfg(feature = "client-pin-volatile")]
impl Sha256Backend for SharedEspSha256 {
    fn digest(&mut self, data: &[u8]) -> Result<[u8; 32], Sha256Error> {
        self.shared.lock(|sha| sha.borrow_mut().digest(data))
    }

    fn digest_parts(&mut self, parts: &[&[u8]]) -> Result<[u8; 32], Sha256Error> {
        self.shared.lock(|sha| sha.borrow_mut().digest_parts(parts))
    }
}

#[cfg(feature = "client-pin-volatile")]
static SHARED_SHA: StaticCell<SharedEspShaPeripheral> = StaticCell::new();

#[cfg(not(feature = "client-pin-volatile"))]
pub type EspKeyStore = DerivedPrivateKeyStore<EspSha256<'static>>;
#[cfg(feature = "client-pin-volatile")]
pub type EspKeyStore = DerivedPrivateKeyStore<SharedEspSha256>;

#[cfg(not(any(
    feature = "experimental-ml-dsa-fips204",
    feature = "experimental-ml-dsa-fips204-scratch",
    feature = "experimental-ml-dsa-mldsa-native"
)))]
type SignatureKeyStore<K> = K;
#[cfg(feature = "experimental-ml-dsa-fips204")]
type SignatureKeyStore<K> = AdditionalSignaturePrivateKeyStore<K, Fips204MlDsa44>;
#[cfg(feature = "experimental-ml-dsa-fips204-scratch")]
type SignatureKeyStore<K> = AdditionalSignaturePrivateKeyStore<K, Fips204ScratchMlDsa44<'static>>;
#[cfg(feature = "experimental-ml-dsa-mldsa-native")]
type SignatureKeyStore<K> = AdditionalSignaturePrivateKeyStore<K, MldsaNativeMlDsa44>;

/// Feature-selected key backend; derived MAC material is reproducible, not a secret device root.
pub type SelectedEspKeyStore = SignatureKeyStore<EspKeyStore>;
#[cfg(not(feature = "flash-managed-keys"))]
pub type SelectedSharedEspKeyStore = SelectedEspKeyStore;
#[cfg(feature = "flash-managed-keys")]
pub type SelectedSharedEspKeyStore =
    SignatureKeyStore<crate::managed_key_storage::EspManagedKeyStore<SharedEspSha256>>;

fn select_key_store<K>(store: K) -> SignatureKeyStore<K> {
    #[cfg(feature = "experimental-ml-dsa-fips204")]
    {
        AdditionalSignaturePrivateKeyStore::new(store, Fips204MlDsa44)
    }
    #[cfg(feature = "experimental-ml-dsa-fips204-scratch")]
    {
        AdditionalSignaturePrivateKeyStore::new(store, crate::ml_dsa_scratch::init_backend())
    }
    #[cfg(feature = "experimental-ml-dsa-mldsa-native")]
    {
        AdditionalSignaturePrivateKeyStore::new(store, MldsaNativeMlDsa44)
    }
    #[cfg(not(any(
        feature = "experimental-ml-dsa-fips204",
        feature = "experimental-ml-dsa-fips204-scratch",
        feature = "experimental-ml-dsa-mldsa-native"
    )))]
    {
        store
    }
}

#[cfg(not(feature = "client-pin-volatile"))]
fn build_crypto_backends(sha: SHA<'static>, aes: AES<'static>) -> (EspKeyStore, EspPinUvAuth) {
    let _ = aes;
    (
        build_device_key_store_from_sha(sha),
        UnconfiguredPinUvAuth::new(),
    )
}

#[cfg(feature = "client-pin-volatile")]
fn build_crypto_backends_with_storage<S: PinUvAuthStateStorage>(
    sha: SHA<'static>,
    aes: AES<'static>,
    storage: S,
) -> (
    EspKeyStore,
    StoredPinUvAuthProvider<
        S,
        Sha256ClientPinCrypto<SharedEspSha256, crate::crypto::EspAes256<'static>>,
        EspTokenClock,
    >,
) {
    let shared = &*SHARED_SHA.init(Mutex::new(RefCell::new(EspSha256::new(sha))));
    let mut key_store_hash = SharedEspSha256 { shared };
    crate::crypto::verify_sha256_accelerator(&mut key_store_hash);
    println!("ESP SHA-256 accelerator shared by key store and ClientPIN");

    let device_mac = efuse::base_mac_address();
    let key_store = crate::crypto::build_derived_key_store(device_mac.as_bytes(), key_store_hash);
    let mut aes = crate::crypto::EspAes256::new(aes);
    crate::crypto::verify_aes256_accelerator(&mut aes);
    println!("ESP AES-256 accelerator enabled for ClientPIN CBC");
    let pin_uv_auth = StoredPinUvAuthProvider::new_with_crypto_and_clock(
        storage,
        Sha256ClientPinCrypto::new_with_aes(SharedEspSha256 { shared }, aes),
        EspTokenClock,
    );
    (key_store, pin_uv_auth)
}

#[cfg(all(feature = "client-pin-volatile", not(feature = "client-pin-flash")))]
fn build_crypto_backends(sha: SHA<'static>, aes: AES<'static>) -> (EspKeyStore, EspPinUvAuth) {
    build_crypto_backends_with_storage(sha, aes, VolatilePinUvAuthStorage::new())
}

pub type EspTrustedDispatcher = TrustedDispatcher<
    EspFlashCredentialStorage<'static>,
    EspGpioUserPresence<'static>,
    UnavailableUserVerification,
    EspPinUvAuth,
    SelectedEspKeyStore,
    EspEntropy,
    EspTextPresenceObserver,
>;

pub type EspUiTrustedDispatcher<U> = TrustedDispatcher<
    EspFlashCredentialStorage<'static>,
    EspGpioUserPresence<'static>,
    UnavailableUserVerification,
    EspPinUvAuth,
    SelectedEspKeyStore,
    EspEntropy,
    UiPresenceObserver<EspTextPresenceObserver, U>,
>;

#[cfg(feature = "client-pin-flash")]
pub type EspUiSharedTrustedDispatcher<U> = TrustedDispatcher<
    SharedEspFlashCredentialStorage<'static>,
    EspGpioUserPresence<'static>,
    UnavailableUserVerification,
    EspPinUvAuth,
    SelectedSharedEspKeyStore,
    EspEntropy,
    UiPresenceObserver<EspTextPresenceObserver, U>,
>;

#[cfg(any(feature = "ble-security", feature = "client-pin-flash"))]
pub type EspSharedTrustedDispatcher = TrustedDispatcher<
    SharedEspFlashCredentialStorage<'static>,
    EspGpioUserPresence<'static>,
    UnavailableUserVerification,
    EspPinUvAuth,
    SelectedSharedEspKeyStore,
    EspEntropy,
    SharedPresenceObserver,
>;

#[cfg(all(
    feature = "up-always-present",
    any(feature = "ble-security", feature = "client-pin-flash")
))]
pub type EspAlwaysSharedTrustedDispatcher = TrustedDispatcher<
    SharedEspFlashCredentialStorage<'static>,
    AlwaysPresent,
    UnavailableUserVerification,
    EspPinUvAuth,
    SelectedSharedEspKeyStore,
    EspEntropy,
    EspTextPresenceObserver,
>;

#[cfg(not(feature = "board-ui"))]
#[cfg(any(feature = "ble-security", feature = "client-pin-flash"))]
type SharedPresenceObserver = EspTextPresenceObserver;
#[cfg(feature = "board-ui")]
#[cfg(any(feature = "ble-security", feature = "client-pin-flash"))]
type SharedPresenceObserver =
    UiPresenceObserver<EspTextPresenceObserver, &'static manekey::user_interface::AtomicUiStatus>;

#[cfg(feature = "board-ui")]
#[cfg(any(feature = "ble-security", feature = "client-pin-flash"))]
fn shared_presence_observer() -> SharedPresenceObserver {
    UiPresenceObserver::new(EspTextPresenceObserver, &crate::board_ui::UI_STATUS)
}

#[cfg(not(feature = "board-ui"))]
#[cfg(any(feature = "ble-security", feature = "client-pin-flash"))]
fn shared_presence_observer() -> SharedPresenceObserver {
    EspTextPresenceObserver
}

#[cfg(feature = "ble-security")]
pub fn build_ble_secure_fido_frontend_from_parts(
    flash: &'static SharedEspFlash<'static>,
    gpio2: GPIO2<'static>,
    sha: SHA<'static>,
    aes: AES<'static>,
    max_fragment_len: usize,
) -> BleFidoFrontend<EspSharedTrustedDispatcher> {
    BleFidoFrontend::new(
        max_fragment_len,
        build_shared_dispatcher_from_parts(
            flash,
            EspGpioUserPresence::from_gpio2(gpio2),
            sha,
            aes,
            transport::BLE_TRANSPORTS,
        ),
    )
}

#[cfg(feature = "client-pin-flash")]
pub fn build_usb_flash_dispatcher_from_parts(
    flash: &'static SharedEspFlash<'static>,
    gpio2: GPIO2<'static>,
    sha: SHA<'static>,
    aes: AES<'static>,
) -> EspSharedTrustedDispatcher {
    build_shared_dispatcher_from_parts(
        flash,
        EspGpioUserPresence::from_gpio2(gpio2),
        sha,
        aes,
        transport::USB_TRANSPORTS,
    )
}

#[cfg(feature = "client-pin-flash")]
pub fn build_usb_flash_dispatcher_with_ui_from_parts<U: UiStatusOutput>(
    flash: &'static SharedEspFlash<'static>,
    presence: EspGpioUserPresence<'static>,
    ui_output: U,
    sha: SHA<'static>,
    aes: AES<'static>,
) -> EspUiSharedTrustedDispatcher<U> {
    build_shared_dispatcher_with_observer_from_parts(
        flash,
        presence,
        sha,
        aes,
        transport::USB_TRANSPORTS,
        UiPresenceObserver::new(EspTextPresenceObserver, ui_output),
    )
}

#[cfg(feature = "usb-ble-multi")]
pub fn build_usb_ble_direct_dispatcher_from_parts(
    flash: &'static SharedEspFlash<'static>,
    gpio2: GPIO2<'static>,
    sha: SHA<'static>,
    aes: AES<'static>,
) -> EspSharedTrustedDispatcher {
    build_shared_dispatcher_from_parts(
        flash,
        EspGpioUserPresence::from_gpio2(gpio2),
        sha,
        aes,
        transport::USB_BLE_TRANSPORTS,
    )
}

#[cfg(feature = "board-ui")]
pub fn build_usb_ble_direct_dispatcher_with_boot(
    flash: &'static SharedEspFlash<'static>,
    gpio0: GPIO0<'static>,
    sha: SHA<'static>,
    aes: AES<'static>,
) -> EspSharedTrustedDispatcher {
    build_shared_dispatcher_from_parts(
        flash,
        EspGpioUserPresence::from_gpio0(gpio0),
        sha,
        aes,
        transport::USB_BLE_TRANSPORTS,
    )
}

#[cfg(all(feature = "usb-ble-multi", feature = "up-always-present"))]
/// Test/maintenance bypass of physical UP; not suitable for real credentials.
pub fn build_usb_ble_direct_dispatcher_always_present_from_parts(
    flash: &'static SharedEspFlash<'static>,
    sha: SHA<'static>,
    aes: AES<'static>,
) -> EspAlwaysSharedTrustedDispatcher {
    build_shared_dispatcher_with_observer_from_parts(
        flash,
        AlwaysPresent,
        sha,
        aes,
        transport::USB_BLE_TRANSPORTS,
        EspTextPresenceObserver,
    )
}

#[cfg(any(feature = "ble-security", feature = "client-pin-flash"))]
fn build_shared_dispatcher_from_parts(
    flash: &'static SharedEspFlash<'static>,
    presence: EspGpioUserPresence<'static>,
    sha: SHA<'static>,
    aes: AES<'static>,
    transports: &'static [&'static [u8]],
) -> EspSharedTrustedDispatcher {
    build_shared_dispatcher_with_observer_from_parts(
        flash,
        presence,
        sha,
        aes,
        transports,
        shared_presence_observer(),
    )
}

#[cfg(any(feature = "ble-security", feature = "client-pin-flash"))]
/// Initialize shared peripheral state once; HAL checks/managed journal failure may panic.
/// Caller owns protected placement, exclusive storage layout and trusted UP; advertised transports are metadata.
pub fn build_shared_dispatcher_with_observer_from_parts<P: UserPresence, O: PresenceObserver>(
    flash: &'static SharedEspFlash<'static>,
    presence: P,
    sha: SHA<'static>,
    aes: AES<'static>,
    transports: &'static [&'static [u8]],
    observer: O,
) -> TrustedDispatcher<
    SharedEspFlashCredentialStorage<'static>,
    P,
    UnavailableUserVerification,
    EspPinUvAuth,
    SelectedSharedEspKeyStore,
    EspEntropy,
    O,
> {
    #[cfg_attr(not(feature = "flash-managed-keys"), allow(unused_mut))]
    let mut records = Storage::new(SharedEspFlashCredentialStorage::new(flash));
    #[cfg_attr(not(feature = "flash-managed-keys"), allow(unused_mut))]
    let mut entropy = build_trng_entropy();
    #[cfg(all(feature = "client-pin-flash", not(feature = "flash-managed-keys")))]
    let (key_store, pin_uv_auth) = build_crypto_backends_with_storage(
        sha,
        aes,
        JournaledPinUvAuthStorage::new(crate::pin_flash_storage::EspFlashPinUvAuthStorage::new(
            flash,
        )),
    );
    #[cfg(not(feature = "client-pin-flash"))]
    let (key_store, pin_uv_auth) = build_crypto_backends(sha, aes);
    #[cfg(feature = "flash-managed-keys")]
    let (key_store, pin_uv_auth) = {
        let shared = &*SHARED_SHA.init(Mutex::new(RefCell::new(EspSha256::new(sha))));
        let mut hash = SharedEspSha256 { shared };
        crate::crypto::verify_sha256_accelerator(&mut hash);
        println!("ESP SHA-256 accelerator shared by managed keys and ClientPIN");
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
            println!("ESP managed factory failed: {error:?}");
            panic!("managed key factory failed closed")
        });
        let mut aes = crate::crypto::EspAes256::new(aes);
        crate::crypto::verify_aes256_accelerator(&mut aes);
        println!("ESP AES-256 accelerator enabled for ClientPIN CBC");
        let pin = StoredPinUvAuthProvider::new_with_crypto_and_clock(
            JournaledPinUvAuthStorage::new(
                crate::pin_flash_storage::EspFlashPinUvAuthStorage::new(flash),
            ),
            Sha256ClientPinCrypto::new_with_aes(hash, aes),
            EspTokenClock,
        );
        (keys, pin)
    };
    TrustedDispatcher::new_with_transports_and_presence_observer(
        records,
        presence,
        UnavailableUserVerification,
        pin_uv_auth,
        select_key_store(key_store),
        entropy,
        transports,
        observer,
    )
}

pub fn build_dispatcher(
    flash: FLASH<'static>,
    presence: EspGpioUserPresence<'static>,
    key_store: SelectedEspKeyStore,
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

#[cfg(not(feature = "client-pin-flash"))]
pub fn build_usb_dispatcher_from_parts(
    flash: FLASH<'static>,
    gpio2: GPIO2<'static>,
    sha: SHA<'static>,
    aes: AES<'static>,
) -> EspTrustedDispatcher {
    let (key_store, pin_uv_auth) = build_crypto_backends(sha, aes);
    build_dispatcher(
        flash,
        EspGpioUserPresence::from_gpio2(gpio2),
        select_key_store(key_store),
        pin_uv_auth,
        build_trng_entropy(),
    )
}

#[cfg(not(feature = "client-pin-flash"))]
pub fn build_usb_dispatcher_with_ui_from_parts<U: UiStatusOutput>(
    flash: FLASH<'static>,
    presence: EspGpioUserPresence<'static>,
    ui_output: U,
    sha: SHA<'static>,
    aes: AES<'static>,
) -> EspUiTrustedDispatcher<U> {
    let (key_store, pin_uv_auth) = build_crypto_backends(sha, aes);
    build_dispatcher_with_observer(
        flash,
        presence,
        select_key_store(key_store),
        pin_uv_auth,
        build_trng_entropy(),
        transport::USB_TRANSPORTS,
        UiPresenceObserver::new(EspTextPresenceObserver, ui_output),
    )
}

pub fn build_ble_dispatcher(
    flash: FLASH<'static>,
    presence: EspGpioUserPresence<'static>,
    key_store: SelectedEspKeyStore,
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

#[cfg(not(feature = "client-pin-flash"))]
pub fn build_ble_dispatcher_from_parts(
    flash: FLASH<'static>,
    gpio2: GPIO2<'static>,
    sha: SHA<'static>,
    aes: AES<'static>,
) -> EspTrustedDispatcher {
    let (key_store, pin_uv_auth) = build_crypto_backends(sha, aes);
    build_ble_dispatcher(
        flash,
        EspGpioUserPresence::from_gpio2(gpio2),
        select_key_store(key_store),
        pin_uv_auth,
        build_trng_entropy(),
    )
}

#[cfg(not(feature = "client-pin-flash"))]
pub fn build_internal_dispatcher_from_parts(
    flash: FLASH<'static>,
    gpio2: GPIO2<'static>,
    sha: SHA<'static>,
    aes: AES<'static>,
) -> EspTrustedDispatcher {
    let (key_store, pin_uv_auth) = build_crypto_backends(sha, aes);
    build_dispatcher_with_transports(
        flash,
        EspGpioUserPresence::from_gpio2(gpio2),
        select_key_store(key_store),
        pin_uv_auth,
        build_trng_entropy(),
        &[],
    )
}

pub fn build_ble_fido_frontend(
    flash: FLASH<'static>,
    presence: EspGpioUserPresence<'static>,
    key_store: SelectedEspKeyStore,
    pin_uv_auth: EspPinUvAuth,
    entropy: EspEntropy,
    max_fragment_len: usize,
) -> BleFidoFrontend<EspTrustedDispatcher> {
    BleFidoFrontend::new(
        max_fragment_len,
        build_ble_dispatcher(flash, presence, key_store, pin_uv_auth, entropy),
    )
}

#[cfg(not(feature = "client-pin-flash"))]
pub fn build_ble_fido_frontend_from_parts(
    flash: FLASH<'static>,
    gpio2: GPIO2<'static>,
    sha: SHA<'static>,
    aes: AES<'static>,
    max_fragment_len: usize,
) -> BleFidoFrontend<EspTrustedDispatcher> {
    BleFidoFrontend::new(
        max_fragment_len,
        build_ble_dispatcher_from_parts(flash, gpio2, sha, aes),
    )
}

pub fn build_dispatcher_with_transports(
    flash: FLASH<'static>,
    presence: EspGpioUserPresence<'static>,
    key_store: SelectedEspKeyStore,
    pin_uv_auth: EspPinUvAuth,
    entropy: EspEntropy,
    transports: &'static [&'static [u8]],
) -> EspTrustedDispatcher {
    build_dispatcher_with_observer(
        flash,
        presence,
        key_store,
        pin_uv_auth,
        entropy,
        transports,
        EspTextPresenceObserver,
    )
}

fn build_dispatcher_with_observer<O: PresenceObserver>(
    flash: FLASH<'static>,
    presence: EspGpioUserPresence<'static>,
    key_store: SelectedEspKeyStore,
    pin_uv_auth: EspPinUvAuth,
    entropy: EspEntropy,
    transports: &'static [&'static [u8]],
    observer: O,
) -> TrustedDispatcher<
    EspFlashCredentialStorage<'static>,
    EspGpioUserPresence<'static>,
    UnavailableUserVerification,
    EspPinUvAuth,
    SelectedEspKeyStore,
    EspEntropy,
    O,
> {
    TrustedDispatcher::new_with_transports_and_presence_observer(
        Storage::new(EspFlashCredentialStorage::new(flash)),
        presence,
        UnavailableUserVerification,
        pin_uv_auth,
        key_store,
        entropy,
        transports,
        observer,
    )
}
