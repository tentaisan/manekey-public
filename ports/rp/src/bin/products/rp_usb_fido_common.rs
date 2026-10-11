#[cfg(feature = "usb-ccid-experimental")]
use core::cell::RefCell;

#[cfg(feature = "usb-ccid-experimental")]
use embassy_futures::select::{Either, select};

#[cfg(feature = "up-gpio15")]
use embassy_rp::gpio::{Input, Pull};
#[cfg(feature = "chip-rp235xa")]
use embassy_rp::interrupt::typelevel::{Binding, TRNG_IRQ};
#[cfg(feature = "chip-rp235xa")]
use embassy_rp::trng::{InterruptHandler as TrngInterruptHandler, Trng};
use embassy_rp::usb::Driver;
use embassy_rp::{Peri, peripherals};
#[cfg(feature = "usb-ccid-experimental")]
use embassy_sync::blocking_mutex::{Mutex, raw::ThreadModeRawMutex};
use embassy_time::Duration;
#[cfg(any(all(), feature = "pin-storage-volatile"))]
use embassy_time::Instant;
#[cfg(feature = "usb-ccid-experimental")]
use embassy_time::Ticker;
use embassy_usb::class::hid::{HidBootProtocol, HidReaderWriter, HidSubclass, State};
use embassy_usb::{Builder, Config};
#[cfg(feature = "single-core-task-transport")]
use manekey::boundary::mailbox::LocalMailboxTransport;
#[cfg(feature = "dual-core-core0-flash-service")]
use manekey::boundary::mailbox::MailboxEndpoint;
#[cfg(any(
    feature = "single-core-task-transport",
    all(
        feature = "dual-core-transport",
        not(feature = "usb-ccid-experimental")
    )
))]
use manekey::boundary::mailbox::MailboxEndpoint as TrustedMailboxEndpoint;
#[cfg(any(
    feature = "dual-core-transport",
    feature = "single-core-task-transport"
))]
use manekey::boundary::mailbox_backend::MailboxTrustedBackend;
#[cfg(feature = "dual-core-core0-flash-service")]
use manekey::boundary::storage_mailbox::{CORE0_FLASH_REQUEST_MAX, CORE0_FLASH_RESPONSE_MAX};
#[cfg(all(
    not(feature = "usb-ccid-experimental"),
    not(any(
        feature = "dual-core-transport",
        feature = "single-core-task-transport"
    ))
))]
use manekey::ctaphid::Ctaphid;
#[cfg(all(
    not(feature = "usb-ccid-experimental"),
    any(
        feature = "dual-core-transport",
        feature = "single-core-task-transport"
    )
))]
use manekey::ctaphid::CtaphidFrontend;
use manekey::ctaphid::descriptor::{
    CtaphidUsbDeviceInfo, REPORT_DESCRIPTOR, REPORT_SIZE, REPORT_SIZE_U8, REPORT_SIZE_U16,
};
use manekey::ctaphid::entropy::HmacDrbgEntropy;
#[cfg(feature = "rp-ml-dsa-credential-experimental")]
use manekey::ctaphid::key_store::AdditionalSignaturePrivateKeyStore;

#[cfg(all())]
use manekey::ctaphid::pin_uv_auth::JournaledPinUvAuthStorage;

#[cfg(feature = "pin-storage-volatile")]
use manekey::ctaphid::pin_uv_auth::VolatilePinUvAuthStorage;
#[cfg(any(all(), feature = "pin-storage-volatile"))]
use manekey::ctaphid::pin_uv_auth::{PinUvAuthTokenClock, StoredPinUvAuthProvider};
#[cfg(any(
    feature = "usb-ccid-experimental",
    feature = "dual-core-transport",
    feature = "single-core-task-transport"
))]
use manekey::ctaphid::trusted::TrustedDispatcher;
#[cfg(any(
    feature = "dual-core-transport",
    feature = "single-core-task-transport"
))]
use manekey::ctaphid::trusted::{TRUSTED_REQUEST_MAX, TRUSTED_RESPONSE_MAX};
#[cfg(feature = "uv-always-verified")]
use manekey::ctaphid::user_verification::AlwaysVerified;
#[cfg(not(feature = "uv-always-verified"))]
use manekey::ctaphid::user_verification::UnavailableUserVerification;
#[cfg(all(any(all(), feature = "pin-storage-volatile"), feature = "chip-rp2040"))]
type SelectedClientPinCrypto = manekey::ctaphid::crypto::SoftwareClientPinCrypto;
#[cfg(all(any(all(), feature = "pin-storage-volatile"), feature = "chip-rp235xa"))]
type SelectedClientPinCrypto = manekey_rp::platform::rp2350::crypto::ClientPinCrypto;
#[cfg(feature = "usb-ccid-experimental")]
use manekey::frontend::ccid::{CCID_RESPONSE_MAX, CcidFrontend};
#[cfg(feature = "usb-ccid-experimental")]
use manekey::frontend::ingress::{IngressArbiter, IngressId, IngressKind};
#[cfg(feature = "up-always-present")]
use manekey::presence::AlwaysPresent;
use manekey::presence::DefmtPresenceObserver;
use manekey::transport::usb::embassy::HidTransport;
#[cfg(not(feature = "usb-ccid-experimental"))]
use manekey::transport::usb::embassy::run_ctaphid_loop;
#[cfg(feature = "usb-ccid-experimental")]
use manekey::transport::usb::embassy::{CcidUsbClass, CcidUsbError, CcidUsbState};
#[cfg(feature = "board-ui-experimental")]
use manekey::user_interface::UiPresenceObserver;
#[cfg(all(feature = "board-ui-experimental", feature = "dual-core-transport"))]
use manekey::user_interface::{AtomicUiStatus, UiStatusOutput};
#[cfg(feature = "chip-rp2040")]
use manekey_rp::platform::rp::entropy::RoscEntropy;
#[cfg(feature = "dual-core-transport")]
use manekey_rp::platform::rp::mailbox::PollingMailboxTransport;

#[cfg(all(
    feature = "dual-core-transport",
    feature = "rp2350-ml-dsa-credential-experimental"
))]
pub const DUAL_CORE_WORKER_STACK_SIZE: usize = 256 * 1024;
#[cfg(all(
    feature = "dual-core-transport",
    not(feature = "rp2350-ml-dsa-credential-experimental"),
    feature = "rp2040-dual-core-core1-stack-160k-experimental"
))]
pub const DUAL_CORE_WORKER_STACK_SIZE: usize = 160 * 1024;
#[cfg(all(
    feature = "dual-core-transport",
    not(feature = "rp2350-ml-dsa-credential-experimental"),
    not(feature = "rp2040-dual-core-core1-stack-160k-experimental")
))]
pub const DUAL_CORE_WORKER_STACK_SIZE: usize = 64 * 1024;

#[cfg(all(
    all(),
    not(feature = "usb-ccid-experimental"),
    not(any(
        feature = "dual-core-transport",
        feature = "single-core-task-transport"
    ))
))]
use manekey_rp::platform::rp::storage::SharedFlashBackedStorage;
#[cfg(all(all(), not(feature = "dual-core-core0-flash-service")))]
use manekey_rp::platform::rp::storage::{
    SharedFlashStorage, SharedPinUvAuthFlashStorage, SharedRpFlash,
};
#[cfg(all(feature = "dual-core-core0-flash-service", all()))]
use manekey_rp::platform::rp::storage_mailbox::Core0FlashPinUvAuthStorageClient;
#[cfg(feature = "dual-core-core0-flash-service")]
use manekey_rp::platform::rp::storage_mailbox::Core0FlashStorageClient;
#[cfg(feature = "up-gpio15")]
use manekey_rp::platform::rp::user_interface::GpioUserPresence;
#[cfg(feature = "board-ui-experimental")]
use manekey_rp::platform::rp::user_interface::RpGpio25Led;
#[cfg(all(feature = "up-bootsel-experimental", feature = "dual-core-transport"))]
use manekey_rp::platform::rp::user_interface::{Core0BootselPresence, core0_bootsel_presence};
#[cfg(all(
    feature = "up-bootsel-experimental",
    not(feature = "dual-core-transport")
))]
use manekey_rp::platform::rp::user_interface::{RpBootselPresence, rp_bootsel_presence};
#[cfg(feature = "chip-rp235xa")]
use manekey_rp::platform::rp2350::entropy::Rp2350Trng;

use static_cell::StaticCell;

type RpHidTransport = HidTransport<'static, Driver<'static, peripherals::USB>>;
#[cfg(feature = "usb-ccid-experimental")]
pub type RpCcidTransport = CcidUsbClass<'static, Driver<'static, peripherals::USB>>;
#[cfg(feature = "usb-ccid-experimental")]
const USB_HID_INGRESS: IngressId = IngressId::new(IngressKind::UsbHid, 0);

#[cfg(feature = "chip-rp235xa")]
#[unsafe(link_section = ".start_block")]
#[used]
static RP2350_IMAGE_DEF: embassy_rp::block::Block<3> = {
    use embassy_rp::block::{
        Architecture, Block, Security, item_image_type_exe, item_vector_table,
    };

    let vector_table = item_vector_table(0x1000_0100);
    Block::new([
        item_image_type_exe(Security::Secure, Architecture::Arm),
        vector_table[0],
        vector_table[1],
    ])
};

#[cfg(any(
    all(feature = "up-gpio15", feature = "up-always-present"),
    all(feature = "up-gpio15", feature = "up-bootsel-experimental"),
    all(feature = "up-always-present", feature = "up-bootsel-experimental")
))]
compile_error!("select only one user presence provider");

#[cfg(not(any(
    feature = "up-gpio15",
    feature = "up-always-present",
    feature = "up-bootsel-experimental"
)))]
compile_error!("select a user presence provider");

#[cfg(all(feature = "chip-rp2040", feature = "chip-rp235xa"))]
compile_error!("select only one RP chip target");

#[cfg(not(any(feature = "chip-rp2040", feature = "chip-rp235xa")))]
compile_error!("select an RP chip target");

#[cfg(all(feature = "trustzone-secure-layout", not(feature = "chip-rp235xa")))]
compile_error!("trustzone-secure-layout requires chip-rp235xa");

#[cfg(feature = "trustzone-nonsecure-image")]
compile_error!("build the Non-secure image with --bin tz-nonsecure");

#[cfg(feature = "trustzone-product-runtime")]
compile_error!("build the TrustZone Secure image with --bin tz-secure");

#[cfg(not(any(feature = "key-storage-flash", any())))]
compile_error!("select a private key storage provider");

#[cfg(all(feature = "rp2350-sha256-accelerator", not(feature = "chip-rp235xa")))]
compile_error!("rp2350-sha256-accelerator currently supports only RP2350 Arm firmware");

#[cfg(all(
    feature = "rp2350-ml-dsa-credential-experimental",
    not(feature = "chip-rp235xa")
))]
compile_error!("RP2350 ML-DSA credential experiment requires RP2350 Arm firmware");

#[cfg(all(all(), feature = "pin-storage-volatile"))]
compile_error!("select only one PIN/UV auth storage provider");

#[cfg(all(feature = "dual-core-transport", feature = "trustzone-secure-layout"))]
compile_error!("dual-core-transport is a non-TrustZone configuration");

#[cfg(all(
    feature = "single-core-task-transport",
    feature = "trustzone-secure-layout"
))]
compile_error!("single-core-task-transport is a non-TrustZone configuration");

#[cfg(all(
    feature = "single-core-task-transport",
    feature = "dual-core-transport"
))]
compile_error!("select only one mailbox transport backend");

#[cfg(all(
    feature = "single-core-task-transport",
    feature = "dual-core-core0-flash-service"
))]
compile_error!("single-core-task-transport does not use the core0 flash service");

#[cfg(feature = "up-always-present")]
pub type SelectedUserPresence = AlwaysPresent;

#[cfg(feature = "up-gpio15")]
pub type SelectedUserPresence = GpioUserPresence<'static>;

#[cfg(all(
    feature = "up-bootsel-experimental",
    not(feature = "dual-core-transport")
))]
pub type SelectedUserPresence = RpBootselPresence;

#[cfg(all(feature = "up-bootsel-experimental", feature = "dual-core-transport"))]
pub type SelectedUserPresence = Core0BootselPresence;

#[cfg(all(
    feature = "board-ui-experimental",
    not(feature = "dual-core-transport")
))]
pub type SelectedPresenceObserver = UiPresenceObserver<DefmtPresenceObserver, RpGpio25Led>;
#[cfg(all(feature = "board-ui-experimental", feature = "dual-core-transport"))]
pub type SelectedPresenceObserver =
    UiPresenceObserver<DefmtPresenceObserver, &'static AtomicUiStatus>;
#[cfg(not(feature = "board-ui-experimental"))]
pub type SelectedPresenceObserver = DefmtPresenceObserver;

#[cfg(feature = "uv-always-verified")]
pub type SelectedUserVerification = AlwaysVerified;

#[cfg(not(feature = "uv-always-verified"))]
pub type SelectedUserVerification = UnavailableUserVerification;

#[cfg(feature = "chip-rp2040")]
pub type SelectedEntropySource = HmacDrbgEntropy<RoscEntropy>;

#[cfg(feature = "chip-rp235xa")]
pub type SelectedEntropySource = HmacDrbgEntropy<Rp2350Trng<'static, peripherals::TRNG>>;

#[cfg(all(all(), not(feature = "dual-core-transport")))]
type SelectedKeyMedia =
    manekey_rp::platform::rp::managed_flash::SharedManagedKeyFlashStorage<'static>;
#[cfg(all(all(), feature = "dual-core-transport"))]
type SelectedKeyMedia =
    manekey_rp::platform::rp::storage_mailbox::Core0FlashStorageClient<'static, 7>;
#[cfg(all())]
type SelectedClassicalPrivateKeyStore =
    manekey_rp::platform::rp::key_store::ClassicalKeys<SelectedKeyMedia, SelectedKeyHash>;
#[cfg(all(all(), feature = "chip-rp2040"))]
type SelectedKeyHash = manekey::ctaphid::hash::SoftwareSha256;
#[cfg(all(all(), feature = "chip-rp235xa"))]
type SelectedKeyHash = manekey_rp::platform::rp2350::crypto::Hash;

#[cfg(not(feature = "rp-ml-dsa-credential-experimental"))]
pub type SelectedPrivateKeyStore = SelectedClassicalPrivateKeyStore;

#[cfg(feature = "rp-ml-dsa-credential-experimental")]
pub type SelectedPrivateKeyStore = AdditionalSignaturePrivateKeyStore<
    SelectedClassicalPrivateKeyStore,
    super::rp_ml_dsa_experimental::TracingMlDsa44,
>;

#[cfg(all(all(), not(feature = "dual-core-core0-flash-service")))]
pub type SelectedPinUvAuthProvider = StoredPinUvAuthProvider<
    JournaledPinUvAuthStorage<SharedPinUvAuthFlashStorage<'static>>,
    SelectedClientPinCrypto,
    RpEmbassyTokenClock,
>;

#[cfg(all(all(), feature = "dual-core-core0-flash-service"))]
pub type SelectedPinUvAuthProvider = StoredPinUvAuthProvider<
    JournaledPinUvAuthStorage<Core0FlashPinUvAuthStorageClient<'static>>,
    SelectedClientPinCrypto,
    RpEmbassyTokenClock,
>;

#[cfg(any(all(), feature = "pin-storage-volatile"))]
#[derive(Clone, Copy)]
pub struct RpEmbassyTokenClock;

#[cfg(any(all(), feature = "pin-storage-volatile"))]
impl PinUvAuthTokenClock for RpEmbassyTokenClock {
    fn now_ms(&self) -> u64 {
        Instant::now().as_millis()
    }
}

#[cfg(all(
    all(),
    not(feature = "usb-ccid-experimental"),
    not(any(
        feature = "dual-core-transport",
        feature = "single-core-task-transport"
    ))
))]
pub type SelectedCredentialStorage = SharedFlashBackedStorage<'static>;

#[cfg(all(
    all(),
    any(
        feature = "dual-core-transport",
        feature = "single-core-task-transport"
    ),
    not(feature = "dual-core-core0-flash-service")
))]
pub type SelectedCredentialStorageBackend = SharedFlashStorage<'static>;

#[cfg(feature = "dual-core-core0-flash-service")]
pub type SelectedCredentialStorageBackend = Core0FlashStorageClient<'static>;

#[cfg(feature = "dual-core-transport")]
pub type SelectedTrustedDispatcher = TrustedDispatcher<
    SelectedCredentialStorageBackend,
    SelectedUserPresence,
    SelectedUserVerification,
    SelectedPinUvAuthProvider,
    SelectedPrivateKeyStore,
    SelectedEntropySource,
    SelectedPresenceObserver,
>;

#[cfg(feature = "single-core-task-transport")]
pub type SelectedTrustedDispatcher = TrustedDispatcher<
    SelectedCredentialStorageBackend,
    SelectedUserPresence,
    SelectedUserVerification,
    SelectedPinUvAuthProvider,
    SelectedPrivateKeyStore,
    SelectedEntropySource,
    SelectedPresenceObserver,
>;

#[cfg(all(
    feature = "usb-ccid-experimental",
    not(any(
        feature = "dual-core-transport",
        feature = "single-core-task-transport"
    ))
))]
pub type SelectedDirectCcidDispatcher = TrustedDispatcher<
    SharedFlashStorage<'static>,
    SelectedUserPresence,
    SelectedUserVerification,
    SelectedPinUvAuthProvider,
    SelectedPrivateKeyStore,
    SelectedEntropySource,
    SelectedPresenceObserver,
>;

#[cfg(all(
    feature = "usb-ccid-experimental",
    not(any(
        feature = "dual-core-transport",
        feature = "single-core-task-transport"
    ))
))]
pub type SharedDirectIngressArbiter =
    Mutex<ThreadModeRawMutex, RefCell<IngressArbiter<SelectedDirectCcidDispatcher>>>;

#[cfg(feature = "single-core-task-transport")]
type SelectedMailboxClientTransport =
    LocalMailboxTransport<'static, TRUSTED_REQUEST_MAX, TRUSTED_RESPONSE_MAX>;
#[cfg(feature = "dual-core-transport")]
type SelectedMailboxClientTransport =
    PollingMailboxTransport<'static, TRUSTED_REQUEST_MAX, TRUSTED_RESPONSE_MAX>;

#[cfg(all(
    feature = "usb-ccid-experimental",
    any(
        feature = "single-core-task-transport",
        feature = "dual-core-transport"
    )
))]
pub type SharedMailboxIngressArbiter = Mutex<
    ThreadModeRawMutex,
    RefCell<IngressArbiter<MailboxTrustedBackend<SelectedMailboxClientTransport>>>,
>;

#[cfg(all(
    feature = "chip-rp2040",
    not(feature = "usb-ccid-experimental"),
    not(feature = "rp-ml-dsa-credential-experimental")
))]
pub const PRODUCT_NAME: &str = "RP2040 HID";

#[cfg(all(
    feature = "chip-rp235xa",
    not(feature = "usb-ccid-experimental"),
    not(feature = "rp-ml-dsa-credential-experimental")
))]
pub const PRODUCT_NAME: &str = "RP2350 HID";

#[cfg(all(
    feature = "rp-ml-dsa-credential-experimental",
    not(feature = "usb-ccid-experimental"),
    feature = "chip-rp235xa"
))]
pub const PRODUCT_NAME: &str = "RP2350 ML-DSA USB";

#[cfg(all(
    feature = "rp-ml-dsa-credential-experimental",
    not(feature = "usb-ccid-experimental"),
    feature = "chip-rp2040"
))]
pub const PRODUCT_NAME: &str = "RP2040 ML-DSA USB";

#[cfg(feature = "up-always-present")]
pub fn selected_user_presence(_pin_15: Peri<'static, peripherals::PIN_15>) -> SelectedUserPresence {
    AlwaysPresent
}

#[cfg(feature = "up-gpio15")]
pub fn selected_user_presence(pin_15: Peri<'static, peripherals::PIN_15>) -> SelectedUserPresence {
    GpioUserPresence::new(Input::new(pin_15, Pull::Up))
}

#[cfg(all(
    feature = "up-bootsel-experimental",
    not(feature = "dual-core-transport")
))]
pub fn selected_user_presence(
    bootsel: Peri<'static, peripherals::BOOTSEL>,
) -> SelectedUserPresence {
    rp_bootsel_presence(bootsel)
}

#[cfg(all(feature = "up-bootsel-experimental", feature = "dual-core-transport"))]
pub fn selected_dual_core_bootsel_presence() -> SelectedUserPresence {
    core0_bootsel_presence()
}

#[cfg(all(
    feature = "board-ui-experimental",
    not(feature = "dual-core-transport")
))]
pub fn selected_presence_observer(
    pin_25: Peri<'static, peripherals::PIN_25>,
) -> SelectedPresenceObserver {
    UiPresenceObserver::new(DefmtPresenceObserver, RpGpio25Led::new(pin_25))
}

#[cfg(all(feature = "board-ui-experimental", feature = "dual-core-transport"))]
static CORE0_UI_STATUS: AtomicUiStatus = AtomicUiStatus::new();

#[cfg(all(feature = "board-ui-experimental", feature = "dual-core-transport"))]
pub fn selected_dual_core_presence_observer() -> SelectedPresenceObserver {
    UiPresenceObserver::new(DefmtPresenceObserver, &CORE0_UI_STATUS)
}

#[cfg(all(feature = "board-ui-experimental", feature = "dual-core-transport"))]
#[embassy_executor::task]
/// Sole core0 GPIO25 UI owner; other cores publish hints only. Not the wireless board LED.
pub async fn core0_gpio25_ui_task(pin_25: Peri<'static, peripherals::PIN_25>) {
    let mut led = RpGpio25Led::new(pin_25);
    loop {
        led.set_ui_hint(CORE0_UI_STATUS.get());
        embassy_time::Timer::after_millis(5).await;
    }
}

#[cfg(not(feature = "board-ui-experimental"))]
pub fn selected_presence_observer() -> SelectedPresenceObserver {
    DefmtPresenceObserver
}

#[cfg(feature = "uv-always-verified")]
pub fn selected_user_verification() -> SelectedUserVerification {
    AlwaysVerified
}

#[cfg(not(feature = "uv-always-verified"))]
pub fn selected_user_verification() -> SelectedUserVerification {
    UnavailableUserVerification
}

#[cfg(feature = "chip-rp2040")]
pub fn selected_entropy() -> SelectedEntropySource {
    HmacDrbgEntropy::new(RoscEntropy).expect("seed HMAC-DRBG from RP2040 ROSC")
}

#[cfg(feature = "chip-rp235xa")]
pub fn selected_entropy<I>(trng: Peri<'static, peripherals::TRNG>, irq: I) -> SelectedEntropySource
where
    I: Binding<TRNG_IRQ, TrngInterruptHandler<peripherals::TRNG>> + 'static,
{
    HmacDrbgEntropy::new(Rp2350Trng::new(Trng::new(trng, irq, Default::default())))
        .expect("seed HMAC-DRBG from RP2350 TRNG")
}

#[cfg(all())]
/// Exclusive journal/hash owner; require real entropy and a live sole core0 Flash service for mailbox media.
pub fn selected_managed_private_key_store<R: manekey::ctaphid::storage::StorageBackend>(
    #[cfg(not(feature = "dual-core-transport"))] flash: &'static SharedRpFlash<'static>,
    #[cfg(feature = "dual-core-transport")] endpoint: &'static MailboxEndpoint<
        CORE0_FLASH_REQUEST_MAX,
        CORE0_FLASH_RESPONSE_MAX,
    >,
    storage: &mut manekey::ctaphid::storage::Storage<R>,
    entropy: &mut SelectedEntropySource,
) -> SelectedPrivateKeyStore {
    #[cfg(not(feature = "dual-core-transport"))]
    let media = SelectedKeyMedia::new(flash);
    #[cfg(feature = "dual-core-transport")]
    let media = SelectedKeyMedia::new(endpoint);
    #[cfg(feature = "chip-rp2040")]
    let hash = manekey::ctaphid::hash::SoftwareSha256;

    #[cfg(feature = "chip-rp235xa")]
    let hash = unsafe { manekey_rp::platform::rp2350::crypto::hash_backend() };
    let keys = manekey_rp::platform::rp::key_store::open_classical(
        media,
        storage,
        entropy,
        hash,
        cfg!(feature = "rp-flash-managed-key-setup"),
    )
    .expect("RP managed keys");
    wrap_private_key_store(keys)
}

#[cfg(not(feature = "rp-ml-dsa-credential-experimental"))]
fn wrap_private_key_store(store: SelectedClassicalPrivateKeyStore) -> SelectedPrivateKeyStore {
    store
}

#[cfg(feature = "rp-ml-dsa-credential-experimental")]
fn wrap_private_key_store(store: SelectedClassicalPrivateKeyStore) -> SelectedPrivateKeyStore {
    AdditionalSignaturePrivateKeyStore::new(
        store,
        super::rp_ml_dsa_experimental::TracingMlDsa44::default(),
    )
}

#[cfg(all(all(), not(feature = "dual-core-core0-flash-service")))]
pub fn selected_pin_uv_auth(flash: &'static SharedRpFlash<'static>) -> SelectedPinUvAuthProvider {
    StoredPinUvAuthProvider::new_with_crypto_and_clock(
        JournaledPinUvAuthStorage::new(SharedPinUvAuthFlashStorage::new(flash)),
        selected_client_pin_crypto(),
        RpEmbassyTokenClock,
    )
}

#[cfg(all(all(), feature = "dual-core-core0-flash-service"))]
pub fn selected_core0_pin_uv_auth(
    endpoint: &'static MailboxEndpoint<CORE0_FLASH_REQUEST_MAX, CORE0_FLASH_RESPONSE_MAX>,
) -> SelectedPinUvAuthProvider {
    StoredPinUvAuthProvider::new_with_crypto_and_clock(
        JournaledPinUvAuthStorage::new(Core0FlashPinUvAuthStorageClient::new(endpoint)),
        selected_client_pin_crypto(),
        RpEmbassyTokenClock,
    )
}

#[cfg(any(all(), feature = "pin-storage-volatile"))]
/// Dispatcher-only initialized SHA owner on RP2350; sharing the provider does not serialize hardware access.
fn selected_client_pin_crypto() -> SelectedClientPinCrypto {
    #[cfg(feature = "chip-rp2040")]
    return manekey::ctaphid::crypto::SoftwareClientPinCrypto;
    #[cfg(feature = "chip-rp235xa")]
    {
        #[cfg(feature = "rp2350-sha256-accelerator")]
        assert!(unsafe { manekey_rp::platform::rp2350::crypto::sha256_known_answers() });
        unsafe { manekey_rp::platform::rp2350::crypto::client_pin_crypto() }
    }
}

#[cfg(all(all(), not(feature = "dual-core-core0-flash-service")))]
pub fn selected_storage(
    flash: &'static SharedRpFlash<'static>,
) -> manekey::ctaphid::storage::Storage<SharedFlashStorage<'static>> {
    manekey::ctaphid::storage::Storage::new(SharedFlashStorage::new(flash))
}

#[cfg(feature = "dual-core-core0-flash-service")]
pub fn selected_storage(
    endpoint: &'static MailboxEndpoint<CORE0_FLASH_REQUEST_MAX, CORE0_FLASH_RESPONSE_MAX>,
) -> manekey::ctaphid::storage::Storage<Core0FlashStorageClient<'static>> {
    manekey::ctaphid::storage::Storage::new(Core0FlashStorageClient::new(endpoint))
}

#[cfg(not(feature = "usb-ccid-experimental"))]
/// Build once with exclusive USB ownership; fixed serial metadata is not a device identity or secret.
pub fn build_ctaphid_usb(
    driver: Driver<'static, peripherals::USB>,
    product: &'static str,
) -> (
    embassy_usb::UsbDevice<'static, Driver<'static, peripherals::USB>>,
    RpHidTransport,
) {
    let identity = CtaphidUsbDeviceInfo::new(product, "12345678").with_manufacturer("You");
    let mut config = Config::new(identity.vendor_id, identity.product_id);
    config.manufacturer = Some(identity.manufacturer);
    config.product = Some(identity.product);
    config.serial_number = identity.serial_number;
    config.max_power = 100;
    config.max_packet_size_0 = REPORT_SIZE_U8;
    config.composite_with_iads = false;
    config.device_class = 0;
    config.device_sub_class = 0;
    config.device_protocol = 0;

    static CONFIG_DESCRIPTOR: StaticCell<[u8; 256]> = StaticCell::new();
    static BOS_DESCRIPTOR: StaticCell<[u8; 256]> = StaticCell::new();
    static MSOS_DESCRIPTOR: StaticCell<[u8; 256]> = StaticCell::new();
    static CONTROL_BUF: StaticCell<[u8; REPORT_SIZE]> = StaticCell::new();
    static STATE: StaticCell<State> = StaticCell::new();

    let mut builder = Builder::new(
        driver,
        config,
        CONFIG_DESCRIPTOR.init([0; 256]),
        BOS_DESCRIPTOR.init([0; 256]),
        MSOS_DESCRIPTOR.init([0; 256]),
        CONTROL_BUF.init([0; REPORT_SIZE]),
    );

    let hid_config = embassy_usb::class::hid::Config {
        hid_subclass: HidSubclass::No,
        hid_boot_protocol: HidBootProtocol::None,
        poll_ms: identity.poll_ms,
        max_packet_size: REPORT_SIZE_U16,
        request_handler: None,
        report_descriptor: REPORT_DESCRIPTOR,
    };

    let hid = HidReaderWriter::<_, REPORT_SIZE, REPORT_SIZE>::new(
        &mut builder,
        STATE.init(State::new()),
        hid_config,
    );
    let transport = HidTransport::new(hid);
    let usb = builder.build();

    (usb, transport)
}

#[cfg(all(feature = "usb-ccid-experimental",))]
pub struct RpCompositeUsb {
    pub device: embassy_usb::UsbDevice<'static, Driver<'static, peripherals::USB>>,
    pub hid: RpHidTransport,
    pub ccid: RpCcidTransport,
}

#[cfg(all(feature = "usb-ccid-experimental",))]
/// Build once with exclusive USB ownership and serialized shared ingress; fixed serial is not a device identity.
pub fn build_ctaphid_ccid_usb(
    driver: Driver<'static, peripherals::USB>,
    product: &'static str,
) -> RpCompositeUsb {
    let identity = CtaphidUsbDeviceInfo::new(product, "12345678").with_manufacturer("You");
    let mut config = Config::new(identity.vendor_id, identity.product_id);
    config.manufacturer = Some(identity.manufacturer);
    config.product = Some(identity.product);
    config.serial_number = identity.serial_number;
    config.max_power = 100;
    config.max_packet_size_0 = REPORT_SIZE_U8;

    static CONFIG_DESCRIPTOR: StaticCell<[u8; 256]> = StaticCell::new();
    static BOS_DESCRIPTOR: StaticCell<[u8; 256]> = StaticCell::new();
    static MSOS_DESCRIPTOR: StaticCell<[u8; 256]> = StaticCell::new();
    static CONTROL_BUF: StaticCell<[u8; REPORT_SIZE]> = StaticCell::new();
    static HID_STATE: StaticCell<State> = StaticCell::new();
    static CCID_STATE: StaticCell<CcidUsbState<'static>> = StaticCell::new();
    let mut builder = Builder::new(
        driver,
        config,
        CONFIG_DESCRIPTOR.init([0; 256]),
        BOS_DESCRIPTOR.init([0; 256]),
        MSOS_DESCRIPTOR.init([0; 256]),
        CONTROL_BUF.init([0; REPORT_SIZE]),
    );
    let hid = HidReaderWriter::<_, REPORT_SIZE, REPORT_SIZE>::new(
        &mut builder,
        HID_STATE.init(State::new()),
        embassy_usb::class::hid::Config {
            hid_subclass: HidSubclass::No,
            hid_boot_protocol: HidBootProtocol::None,
            poll_ms: identity.poll_ms,
            max_packet_size: REPORT_SIZE_U16,
            request_handler: None,
            report_descriptor: REPORT_DESCRIPTOR,
        },
    );
    let ccid = CcidUsbClass::new(
        &mut builder,
        CCID_STATE.init(CcidUsbState::new()),
        REPORT_SIZE_U16,
        CCID_RESPONSE_MAX as u32,
    );
    RpCompositeUsb {
        device: builder.build(),
        hid: HidTransport::new(hid),
        ccid,
    }
}

#[embassy_executor::task]
pub async fn usb_task(mut usb: embassy_usb::UsbDevice<'static, Driver<'static, peripherals::USB>>) {
    usb.run().await;
}

#[cfg(feature = "usb-ccid-experimental")]
/// Sole HID owner with a serialized arbiter; link loss cancels ownership and abandons queued reports.
async fn run_shared_hid_frontend<B: manekey::ctaphid::trusted::TrustedBackend>(
    mut transport: RpHidTransport,
    arbiter: &'static Mutex<ThreadModeRawMutex, RefCell<IngressArbiter<B>>>,
) -> ! {
    let mut frontend = manekey::frontend::ctaphid::CtaphidReportFrontend::new();
    let mut ticker = Ticker::every(Duration::from_millis(100));
    let mut link_lost = false;

    loop {
        if let Some(report) = frontend.current_report().copied() {
            if transport.write(&report).await.is_ok() {
                frontend.advance_report();
            } else {
                arbiter.lock(|arbiter| {
                    frontend.on_link_lost(&mut arbiter.borrow_mut(), USB_HID_INGRESS);
                });
                link_lost = true;
            }
            continue;
        }
        let event = select(transport.read(), ticker.next()).await;
        let io_failed = matches!(&event, Either::First(Err(_)));
        arbiter.lock(|arbiter| {
            let mut arbiter = arbiter.borrow_mut();
            match event {
                Either::First(Ok(report)) => {
                    link_lost = false;
                    frontend.handle_report(&mut arbiter, USB_HID_INGRESS, report);
                }
                Either::First(Err(_)) if link_lost => frontend.poll(&mut arbiter, USB_HID_INGRESS),
                Either::First(Err(_)) => {
                    frontend.on_link_lost(&mut arbiter, USB_HID_INGRESS);
                    link_lost = true;
                }
                Either::Second(()) => frontend.poll(&mut arbiter, USB_HID_INGRESS),
            }
        });
        if io_failed {
            embassy_time::Timer::after_millis(10).await;
        }
    }
}

#[embassy_executor::task]
#[cfg(all(
    feature = "usb-ccid-experimental",
    not(any(
        feature = "dual-core-transport",
        feature = "single-core-task-transport"
    ))
))]
/// Sole direct HID task using the shared report frontend.
pub async fn hid_direct_shared_frontend_task(
    transport: RpHidTransport,
    arbiter: &'static SharedDirectIngressArbiter,
) -> ! {
    run_shared_hid_frontend(transport, arbiter).await
}

#[embassy_executor::task]
#[cfg(all(
    feature = "usb-ccid-experimental",
    not(any(
        feature = "dual-core-transport",
        feature = "single-core-task-transport"
    ))
))]
/// Sole CCID owner with thread-mode arbiter; reset/abort update ownership, but send failures are discarded.
pub async fn ccid_direct_frontend_task(
    mut transport: RpCcidTransport,
    arbiter: &'static SharedDirectIngressArbiter,
) -> ! {
    let mut frontend = CcidFrontend::new(0);
    let mut request = [0u8; CCID_RESPONSE_MAX];
    let mut response = [0u8; CCID_RESPONSE_MAX];
    let mut ticker = Ticker::every(Duration::from_millis(100));

    loop {
        if transport.take_bus_reset() {
            arbiter.lock(|arbiter| frontend.disconnect(&mut arbiter.borrow_mut()));
        }
        if let Some((slot, sequence)) = transport.take_control_abort() {
            arbiter.lock(|arbiter| frontend.begin_abort(&mut arbiter.borrow_mut(), slot, sequence));
        }
        let event = select(transport.read_message(&mut request), ticker.next()).await;
        if transport.take_bus_reset() {
            arbiter.lock(|arbiter| frontend.disconnect(&mut arbiter.borrow_mut()));
        }
        if let Some((slot, sequence)) = transport.take_control_abort() {
            arbiter.lock(|arbiter| frontend.begin_abort(&mut arbiter.borrow_mut(), slot, sequence));
        }
        let response_len = match event {
            Either::First(Ok(len)) => arbiter.lock(|arbiter| {
                frontend
                    .handle_message(&mut arbiter.borrow_mut(), &request[..len], &mut response)
                    .ok()
            }),
            Either::First(Err(CcidUsbError::Disabled)) => {
                arbiter.lock(|arbiter| frontend.disconnect(&mut arbiter.borrow_mut()));
                transport.wait_connection().await;
                continue;
            }
            Either::First(Err(_)) => continue,
            Either::Second(()) => arbiter.lock(|arbiter| {
                frontend
                    .poll(&mut arbiter.borrow_mut(), &mut response)
                    .ok()
                    .flatten()
            }),
        };
        if let Some(len) = response_len {
            let _ = transport.write_message(&response[..len]).await;
        }
    }
}

#[embassy_executor::task]
#[cfg(all(
    feature = "usb-ccid-experimental",
    any(
        feature = "single-core-task-transport",
        feature = "dual-core-transport"
    )
))]
/// Sole mailbox HID task using the shared report frontend and one live trusted worker.
pub async fn hid_mailbox_shared_frontend_task(
    transport: RpHidTransport,
    arbiter: &'static SharedMailboxIngressArbiter,
) -> ! {
    run_shared_hid_frontend(transport, arbiter).await
}

#[embassy_executor::task]
#[cfg(all(
    feature = "usb-ccid-experimental",
    any(
        feature = "single-core-task-transport",
        feature = "dual-core-transport"
    )
))]
/// Sole CCID owner with serialized mailbox client; reset/abort update ownership, but send failures are discarded.
pub async fn ccid_mailbox_frontend_task(
    mut transport: RpCcidTransport,
    arbiter: &'static SharedMailboxIngressArbiter,
) -> ! {
    let mut frontend = CcidFrontend::new(0);
    let mut request = [0u8; CCID_RESPONSE_MAX];
    let mut response = [0u8; CCID_RESPONSE_MAX];
    let mut ticker = Ticker::every(Duration::from_millis(100));

    loop {
        if transport.take_bus_reset() {
            arbiter.lock(|arbiter| frontend.disconnect(&mut arbiter.borrow_mut()));
        }
        if let Some((slot, sequence)) = transport.take_control_abort() {
            arbiter.lock(|arbiter| frontend.begin_abort(&mut arbiter.borrow_mut(), slot, sequence));
        }
        let event = select(transport.read_message(&mut request), ticker.next()).await;
        if transport.take_bus_reset() {
            arbiter.lock(|arbiter| frontend.disconnect(&mut arbiter.borrow_mut()));
        }
        if let Some((slot, sequence)) = transport.take_control_abort() {
            arbiter.lock(|arbiter| frontend.begin_abort(&mut arbiter.borrow_mut(), slot, sequence));
        }
        let response_len = match event {
            Either::First(Ok(len)) => arbiter.lock(|arbiter| {
                frontend
                    .handle_message(&mut arbiter.borrow_mut(), &request[..len], &mut response)
                    .ok()
            }),
            Either::First(Err(CcidUsbError::Disabled)) => {
                arbiter.lock(|arbiter| frontend.disconnect(&mut arbiter.borrow_mut()));
                transport.wait_connection().await;
                continue;
            }
            Either::First(Err(_)) => continue,
            Either::Second(()) => arbiter.lock(|arbiter| {
                frontend
                    .poll(&mut arbiter.borrow_mut(), &mut response)
                    .ok()
                    .flatten()
            }),
        };
        if let Some(len) = response_len {
            let _ = transport.write_message(&response[..len]).await;
        }
    }
}

#[embassy_executor::task]
#[cfg(feature = "single-core-task-transport")]
/// Sole dispatcher/endpoint worker; local task separation provides no memory isolation.
pub async fn single_core_trusted_task(
    dispatcher: &'static mut SelectedTrustedDispatcher,
    endpoint: &'static TrustedMailboxEndpoint<TRUSTED_REQUEST_MAX, TRUSTED_RESPONSE_MAX>,
) {
    let mut request = [0; TRUSTED_REQUEST_MAX];
    let mut response = [0; TRUSTED_RESPONSE_MAX];

    loop {
        match endpoint.pump_operation_once(dispatcher, &mut request, &mut response) {
            Ok(true) => {}
            Ok(false) | Err(_) => embassy_futures::yield_now().await,
        }
    }
}

#[embassy_executor::task]
#[cfg(all(
    not(feature = "usb-ccid-experimental"),
    not(any(
        feature = "dual-core-transport",
        feature = "single-core-task-transport"
    ))
))]
pub async fn hid_direct_task(
    mut transport: RpHidTransport,
    storage: SelectedCredentialStorage,
    presence: SelectedUserPresence,
    verification: SelectedUserVerification,
    pin_uv_auth: SelectedPinUvAuthProvider,
    key_store: SelectedPrivateKeyStore,
    entropy: SelectedEntropySource,
    presence_observer: SelectedPresenceObserver,
) {
    let mut ctaphid = Ctaphid::new_with_presence_observer(
        storage,
        presence,
        verification,
        pin_uv_auth,
        key_store,
        entropy,
        presence_observer,
    );
    run_ctaphid_loop(&mut transport, &mut ctaphid, Duration::from_millis(100)).await
}

#[embassy_executor::task]
#[cfg(all(
    not(feature = "usb-ccid-experimental"),
    any(
        feature = "dual-core-transport",
        feature = "single-core-task-transport"
    )
))]
/// Sole client of the selected mailbox endpoint; require one live trusted worker and USB runner.
pub async fn hid_frontend_task(
    mut transport: RpHidTransport,
    endpoint: &'static TrustedMailboxEndpoint<TRUSTED_REQUEST_MAX, TRUSTED_RESPONSE_MAX>,
) {
    #[cfg(feature = "dual-core-transport")]
    let mailbox = PollingMailboxTransport::new(endpoint);
    #[cfg(feature = "single-core-task-transport")]
    let mailbox = LocalMailboxTransport::new(endpoint);
    let trusted = MailboxTrustedBackend::new(mailbox);
    let mut ctaphid = CtaphidFrontend::with_trusted_backend(trusted);
    run_ctaphid_loop(&mut transport, &mut ctaphid, Duration::from_millis(100)).await
}

#[cfg(not(feature = "rp-flash-managed-keys"))]
compile_error!("Public products require rp-flash-managed-keys");
