#![no_std]
#![no_main]

#[cfg(feature = "riscv-pico-2-w-ble-bond-flash")]
compile_error!("dual-core BLE bond flash must use riscv-pico-2-w-ble-dual-core-bond-flash");

use manekey::boundary::{
    mailbox::{MailboxEndpoint, MailboxError, MailboxState},
    mailbox_backend::MailboxTrustedBackend,
    storage_mailbox::{CORE0_FLASH_REQUEST_MAX, CORE0_FLASH_RESPONSE_MAX, Core0FlashService},
};
#[cfg(all(
    not(feature = "riscv-flash-managed-keys"),
    feature = "riscv-pico-2-w-ble-ml-dsa-fips204-experimental"
))]
use manekey::ctaphid::key_store::AdditionalSignaturePrivateKeyStore;
#[cfg(not(feature = "riscv-flash-managed-keys"))]
use manekey::ctaphid::key_store::FlashPrivateKeyStore;
use manekey::ctaphid::{
    entropy::HmacDrbgEntropy,
    pin_uv_auth::{JournaledPinUvAuthStorage, StoredPinUvAuthProvider},
    storage::Storage,
    trusted::{TRUSTED_REQUEST_MAX, TRUSTED_RESPONSE_MAX, TrustedDispatcher},
    user_verification::UnavailableUserVerification,
};
#[cfg(feature = "riscv-pico-2-w-ble-dual-core-bond-flash")]
use manekey_rp::platform::rp::storage::RiscvBleBondFlashStorage;
use manekey_rp::platform::rp::{
    storage::{RiscvFlashStorage, RiscvPinUvAuthFlashStorage},
    storage_mailbox::{Core0FlashPinUvAuthStorageClient, Core0FlashStorageClient},
};
#[cfg(not(any(feature = "riscv-pico-2-w-ble-bootsel", feature = "up-always-present")))]
use manekey_rp::platform::rp2350::riscv_dual_core::RawGpio15UserPresence;
#[cfg(feature = "riscv-pico-2-w-ble-dual-core-bond-flash")]
use manekey_rp::platform::rp2350::riscv_dual_core::request_core1_xip_pause;
use manekey_rp::platform::rp2350::{
    entropy::RiscvTrng,
    riscv_dual_core::{RiscvPollingTransport, core1_park_for_xip_if_requested, spawn_riscv_core1},
    riscv_token_clock::Rp2350RiscvTokenClock,
};
#[cfg(not(feature = "riscv-pico-2-w-ble-ml-dsa-fips204-experimental"))]
const CORE1_STACK_WORDS: usize = 16_384;
#[cfg(feature = "riscv-pico-2-w-ble-ml-dsa-fips204-experimental")]
const CORE1_STACK_WORDS: usize = 65_536;
const SELECTED_BLE_RUNTIME_TICK_MS: u64 = 10;
const FIDO_PENDING_POLL_TICKS: u8 = 10;

#[repr(C, align(32))]
struct Core1Stack {
    words: [usize; CORE1_STACK_WORDS],
}

impl Core1Stack {
    const fn new() -> Self {
        Self {
            words: [0; CORE1_STACK_WORDS],
        }
    }
}

static TRUSTED_ENDPOINT: MailboxEndpoint<TRUSTED_REQUEST_MAX, TRUSTED_RESPONSE_MAX> =
    MailboxEndpoint::new();
static FLASH_ENDPOINT: MailboxEndpoint<CORE0_FLASH_REQUEST_MAX, CORE0_FLASH_RESPONSE_MAX> =
    MailboxEndpoint::new();
static DISPATCHER: static_cell::StaticCell<SelectedDispatcher> = static_cell::StaticCell::new();
#[cfg(feature = "riscv-flash-managed-keys")]
type SelectedFlashService = Core0FlashService<
    RiscvFlashStorage,
    RiscvPinUvAuthFlashStorage,
    manekey_rp::platform::rp::storage::RiscvManagedKeyFlashStorage,
>;
#[cfg(not(feature = "riscv-flash-managed-keys"))]
type SelectedFlashService = Core0FlashService<RiscvFlashStorage, RiscvPinUvAuthFlashStorage>;
static FLASH_SERVICE: static_cell::StaticCell<SelectedFlashService> =
    static_cell::StaticCell::new();
static FLASH_REQUEST: static_cell::StaticCell<[u8; CORE0_FLASH_REQUEST_MAX]> =
    static_cell::StaticCell::new();
static FLASH_RESPONSE: static_cell::StaticCell<[u8; CORE0_FLASH_RESPONSE_MAX]> =
    static_cell::StaticCell::new();
static mut CORE1_STACK: Core1Stack = Core1Stack::new();

#[cfg(feature = "riscv-pico-2-w-ble-dual-core-bond-flash")]
/// Core0 bond journal requiring serialized core1 pause requests and exclusion of all other XIP masters.
struct DualCoreBleBondFlashStorage {
    inner: RiscvBleBondFlashStorage,
}

#[cfg(feature = "riscv-pico-2-w-ble-dual-core-bond-flash")]
impl DualCoreBleBondFlashStorage {
    const fn new() -> Self {
        Self {
            inner: RiscvBleBondFlashStorage::new(),
        }
    }
}

#[cfg(feature = "riscv-pico-2-w-ble-dual-core-bond-flash")]
impl manekey::transport::ble::BleBondStore for DualCoreBleBondFlashStorage {
    fn load_bonds<F>(&mut self, visit: F)
    where
        F: FnMut(manekey::transport::ble::StoredBleBond),
    {
        self.inner.load_bonds(visit);
    }

    fn store_bond(&mut self, bond: manekey::transport::ble::StoredBleBond) -> bool {
        let Some(_pause) = request_core1_xip_pause() else {
            return false;
        };
        self.inner.store_bond(bond)
    }

    fn clear_bonds(&mut self) -> bool {
        let Some(_pause) = request_core1_xip_pause() else {
            return false;
        };
        self.inner.clear_bonds()
    }
}

#[cfg(feature = "riscv-pico-2-w-ble-dual-core-bond-flash")]
fn selected_dual_core_ble_bond_store() -> DualCoreBleBondFlashStorage {
    DualCoreBleBondFlashStorage::new()
}

type SelectedDispatcher = TrustedDispatcher<
    Core0FlashStorageClient<'static>,
    SelectedPresence,
    UnavailableUserVerification,
    StoredPinUvAuthProvider<
        JournaledPinUvAuthStorage<Core0FlashPinUvAuthStorageClient<'static>>,
        manekey_rp::platform::rp2350::riscv_crypto::ClientPinCrypto,
        Rp2350RiscvTokenClock,
    >,
    SelectedPrivateKeyStore,
    HmacDrbgEntropy<RiscvTrng>,
    manekey_rp::platform::rp2350::riscv_ui::PresenceObserver,
>;

#[cfg(all(
    feature = "riscv-pico-2-w-ble-bootsel",
    not(feature = "up-always-present")
))]
type SelectedPresence = manekey_rp::platform::rp2350::riscv_dual_core::DualCoreBootselPresence;
#[cfg(not(any(feature = "riscv-pico-2-w-ble-bootsel", feature = "up-always-present")))]
type SelectedPresence = RawGpio15UserPresence;

#[cfg(feature = "up-always-present")]
type SelectedPresence = manekey::presence::AlwaysPresent;

#[cfg(feature = "riscv-flash-managed-keys")]
type SelectedPrivateKeyStore = manekey_rp::platform::rp2350::key_store::Keys<
    manekey_rp::platform::rp::storage_mailbox::Core0FlashStorageClient<'static, 7>,
>;
#[cfg(all(
    not(feature = "riscv-flash-managed-keys"),
    feature = "riscv-pico-2-w-ble-ml-dsa-fips204-experimental"
))]
type SelectedPrivateKeyStore = AdditionalSignaturePrivateKeyStore<
    FlashPrivateKeyStore,
    manekey_rp::platform::rp2350::riscv_crypto::MlDsa,
>;
#[cfg(not(any(
    feature = "riscv-flash-managed-keys",
    feature = "riscv-pico-2-w-ble-ml-dsa-fips204-experimental"
)))]
type SelectedPrivateKeyStore = FlashPrivateKeyStore;

type SelectedBleBackend = MailboxTrustedBackend<
    RiscvPollingTransport<'static, TRUSTED_REQUEST_MAX, TRUSTED_RESPONSE_MAX>,
>;

struct SelectedBleRuntime {
    #[cfg(not(feature = "riscv-pico-2-w-ble-multi-transport"))]
    flash_service: &'static mut SelectedFlashService,
    #[cfg(not(feature = "riscv-pico-2-w-ble-multi-transport"))]
    request: &'static mut [u8; CORE0_FLASH_REQUEST_MAX],
    #[cfg(not(feature = "riscv-pico-2-w-ble-multi-transport"))]
    response: &'static mut [u8; CORE0_FLASH_RESPONSE_MAX],
    fido_poll_ticks: u8,
}

#[allow(unused_variables)]
/// Initialize once with exclusive core1 stack/FIFO and a single core0 Flash service; this is not PMP isolation.
fn selected_ble_backend(
    spawner: embassy_executor::Spawner,
    _timer: hal::timer::Timer<hal::timer::CopyableTimer0>,
    _button: ButtonPin,
    _trng: hal::pac::TRNG,
    psm: &mut hal::pac::PSM,
    fifo: &mut hal::sio::SioFifo,
) -> Result<(SelectedBleBackend, SelectedBleRuntime), u32> {
    let stack_start = unsafe { core::ptr::addr_of_mut!(CORE1_STACK.words).cast::<usize>() };
    unsafe {
        spawn_riscv_core1(
            psm,
            fifo,
            stack_start,
            CORE1_STACK_WORDS,
            riscv_core1_startup,
        )
    }
    .map_err(|_| 0xffff_fffd_u32)?;

    #[cfg(not(feature = "riscv-flash-managed-keys"))]
    let flash_service = FLASH_SERVICE.init(Core0FlashService::with_pin_backend(
        RiscvFlashStorage::new(),
        RiscvPinUvAuthFlashStorage::new(),
    ));
    #[cfg(feature = "riscv-flash-managed-keys")]
    let flash_service = FLASH_SERVICE.init(Core0FlashService::with_key_backend(
        RiscvFlashStorage::new(),
        RiscvPinUvAuthFlashStorage::new(),
        manekey_rp::platform::rp::storage::RiscvManagedKeyFlashStorage,
    ));
    let request = FLASH_REQUEST.init([0; CORE0_FLASH_REQUEST_MAX]);
    let response = FLASH_RESPONSE.init([0; CORE0_FLASH_RESPONSE_MAX]);
    #[cfg(feature = "riscv-pico-2-w-ble-multi-transport")]
    {
        let task =
            core0_service_task(flash_service, request, response).map_err(|_| 0xffff_fffc_u32)?;
        spawner.spawn(task);
    }
    let runtime = SelectedBleRuntime {
        #[cfg(not(feature = "riscv-pico-2-w-ble-multi-transport"))]
        flash_service,
        #[cfg(not(feature = "riscv-pico-2-w-ble-multi-transport"))]
        request,
        #[cfg(not(feature = "riscv-pico-2-w-ble-multi-transport"))]
        response,
        fido_poll_ticks: 0,
    };
    let backend = MailboxTrustedBackend::new(RiscvPollingTransport::new(&TRUSTED_ENDPOINT));
    Ok((backend, runtime))
}

fn selected_ble_runtime_tick(runtime: &mut SelectedBleRuntime) {
    #[cfg(feature = "riscv-pico-2-w-ble-multi-transport")]
    let _ = runtime;
    #[cfg(not(feature = "riscv-pico-2-w-ble-multi-transport"))]
    {
        #[cfg(all(
            feature = "riscv-pico-2-w-ble-bootsel",
            not(feature = "up-always-present")
        ))]
        manekey_rp::platform::rp2350::riscv_dual_core::core0_park_for_bootsel_if_requested();
        service_flash_once(runtime.flash_service, runtime.request, runtime.response);
    }
}

/// Sole Flash endpoint owner; storage must provide cross-hart/XIP exclusion for each mutation.
fn service_flash_once(
    flash_service: &mut SelectedFlashService,
    request: &mut [u8; CORE0_FLASH_REQUEST_MAX],
    response: &mut [u8; CORE0_FLASH_RESPONSE_MAX],
) {
    if FLASH_ENDPOINT.state() != Ok(MailboxState::RequestReady) {
        return;
    }
    let result = FLASH_ENDPOINT
        .take_request(request)
        .and_then(|len| {
            flash_service
                .process(&request[..len], response)
                .map_err(|_| MailboxError::InvalidState)
        })
        .and_then(|len| FLASH_ENDPOINT.publish_response(&response[..len]));
    if result.is_err() {
        let _ = FLASH_ENDPOINT.publish_response(&[0xff]);
    }
    hal::arch::sev();
}

#[cfg(feature = "riscv-pico-2-w-ble-multi-transport")]
#[embassy_executor::task]
async fn core0_service_task(
    flash_service: &'static mut SelectedFlashService,
    request: &'static mut [u8; CORE0_FLASH_REQUEST_MAX],
    response: &'static mut [u8; CORE0_FLASH_RESPONSE_MAX],
) {
    loop {
        #[cfg(all(
            feature = "riscv-pico-2-w-ble-bootsel",
            not(feature = "up-always-present")
        ))]
        manekey_rp::platform::rp2350::riscv_dual_core::core0_park_for_bootsel_if_requested();
        service_flash_once(flash_service, request, response);
        embassy_futures::yield_now().await;
    }
}

fn selected_ble_runtime_should_poll_status(runtime: &mut SelectedBleRuntime) -> bool {
    runtime.fido_poll_ticks = runtime.fido_poll_ticks.saturating_add(1);
    if runtime.fido_poll_ticks >= FIDO_PENDING_POLL_TICKS {
        runtime.fido_poll_ticks = 0;
        true
    } else {
        false
    }
}

/// Core1-only initialization after clocks/reset, with exclusive TRNG/SHA and a live core0 Flash service.
fn selected_dispatcher(trng: hal::pac::TRNG) -> SelectedDispatcher {
    #[allow(unused_mut)]
    let mut entropy = HmacDrbgEntropy::new(RiscvTrng::new(trng)).unwrap();
    #[cfg(feature = "up-always-present")]
    let presence = manekey::presence::AlwaysPresent;
    #[cfg(all(
        feature = "riscv-pico-2-w-ble-bootsel",
        not(feature = "up-always-present")
    ))]
    let presence = manekey_rp::platform::rp2350::riscv_dual_core::DualCoreBootselPresence::new();
    #[cfg(not(any(feature = "riscv-pico-2-w-ble-bootsel", feature = "up-always-present")))]
    let presence = RawGpio15UserPresence::new();
    #[allow(unused_mut)]
    let mut records = Storage::new(Core0FlashStorageClient::new(&FLASH_ENDPOINT));
    #[cfg(feature = "riscv-flash-managed-keys")]
    let private_key_store = unsafe {
        manekey_rp::platform::rp2350::key_store::open(
            manekey_rp::platform::rp::storage_mailbox::Core0FlashStorageClient::<7>::new(
                &FLASH_ENDPOINT,
            ),
            &mut records,
            &mut entropy,
        )
    }
    .expect("RP managed keys");
    #[cfg(all(
        not(feature = "riscv-flash-managed-keys"),
        feature = "riscv-pico-2-w-ble-ml-dsa-fips204-experimental"
    ))]
    let private_key_store = AdditionalSignaturePrivateKeyStore::new(
        FlashPrivateKeyStore,
        manekey_rp::platform::rp2350::riscv_crypto::ml_dsa(),
    );
    #[cfg(not(any(
        feature = "riscv-flash-managed-keys",
        feature = "riscv-pico-2-w-ble-ml-dsa-fips204-experimental"
    )))]
    let private_key_store = FlashPrivateKeyStore;
    TrustedDispatcher::new_with_transports_and_presence_observer(
        records,
        presence,
        UnavailableUserVerification,
        StoredPinUvAuthProvider::new_with_crypto_and_clock(
            JournaledPinUvAuthStorage::new(Core0FlashPinUvAuthStorageClient::new(&FLASH_ENDPOINT)),
            unsafe { manekey_rp::platform::rp2350::riscv_crypto::client_pin_crypto() },
            Rp2350RiscvTokenClock,
        ),
        private_key_store,
        entropy,
        selected_transport_ids(),
        manekey_rp::platform::rp2350::riscv_ui::presence_observer(),
    )
}

fn core1_entry(trng: hal::pac::TRNG) -> ! {
    let dispatcher = DISPATCHER.init(selected_dispatcher(trng));
    let mut request = [0; TRUSTED_REQUEST_MAX];
    let mut response = [0; TRUSTED_RESPONSE_MAX];

    loop {
        core1_park_for_xip_if_requested();
        match TRUSTED_ENDPOINT.pump_operation_once(dispatcher, &mut request, &mut response) {
            Ok(true) => hal::arch::sev(),
            Ok(false) | Err(_) => hal::arch::wfe(),
        }
    }
}

/// Boot-ROM-only core1 entry; reclaim only exclusively reserved TRNG and the startup FIFO acknowledgement.
extern "C" fn riscv_core1_startup() -> ! {
    let peripherals = unsafe { hal::pac::Peripherals::steal() };
    let trng = peripherals.TRNG;
    let mut sio = hal::Sio::new(peripherals.SIO);
    sio.fifo.write_blocking(1);
    core1_entry(trng)
}

include!("ble/riscv_pico_2_w_ble_common.rs");
