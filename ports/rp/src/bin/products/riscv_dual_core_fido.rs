#![no_std]
#![no_main]

use panic_halt as _;
use rp235x_hal as hal;
use static_cell::StaticCell;
use usb_device::{
    bus::UsbBusAllocator,
    device::{StringDescriptors, UsbDeviceBuilder, UsbVidPid},
};
use usbd_hid::hid_class::HIDClass;

#[cfg(any(
    feature = "riscv-dual-core-internal-ccid",
    all(feature = "riscv-dual-core-ml-dsa-fips204-experimental", any())
))]
use rp235x_hal::{Clock, fugit::RateExtU32};

#[cfg(feature = "riscv-dual-core-flash")]
use manekey::boundary::mailbox::{MailboxError, MailboxState};
#[cfg(feature = "riscv-dual-core-flash")]
use manekey::boundary::storage_mailbox::{
    CORE0_FLASH_REQUEST_MAX, CORE0_FLASH_RESPONSE_MAX, Core0FlashService,
};
use manekey::boundary::{mailbox::MailboxEndpoint, mailbox_backend::MailboxTrustedBackend};
#[cfg(not(feature = "riscv-dual-core-internal-ccid"))]
use manekey::ctaphid::CtaphidFrontend;
#[cfg(not(feature = "riscv-dual-core-internal-ccid"))]
use manekey::ctaphid::descriptor::REPORT_SIZE as CTAPHID_REPORT_SIZE;
#[cfg(feature = "riscv-dual-core-trng")]
use manekey::ctaphid::entropy::HmacDrbgEntropy;

#[cfg(feature = "riscv-dual-core-flash")]
use manekey::ctaphid::pin_uv_auth::JournaledPinUvAuthStorage;
#[cfg(not(feature = "riscv-dual-core-flash"))]
use manekey::ctaphid::pin_uv_auth::VolatilePinUvAuthStorage;
#[cfg(not(feature = "riscv-dual-core-flash"))]
use manekey::ctaphid::storage::StubStorage;
use manekey::ctaphid::{
    descriptor::{CtaphidUsbDeviceInfo, POLL_MS as CTAPHID_POLL_MS, REPORT_DESCRIPTOR},
    pin_uv_auth::StoredPinUvAuthProvider,
    storage::Storage,
    trusted::{TRUSTED_REQUEST_MAX, TRUSTED_RESPONSE_MAX, TrustedDispatcher},
    user_verification::UnavailableUserVerification,
};
use manekey_rp::platform::rp2350::riscv_crypto::{self, ClientPinCrypto};
#[cfg(feature = "riscv-dual-core-internal-ccid")]
#[path = "riscv_usb_internal.rs"]
mod multi_transport;
use manekey::presence::NoPresenceObserver;
#[cfg(feature = "board-ui-experimental")]
use manekey::user_interface::UiPresenceObserver;
#[cfg(feature = "riscv-dual-core-flash")]
use manekey_rp::platform::rp::storage::{RiscvFlashStorage, RiscvPinUvAuthFlashStorage};
#[cfg(feature = "riscv-dual-core-flash")]
use manekey_rp::platform::rp::storage_mailbox::{
    Core0FlashPinUvAuthStorageClient, Core0FlashStorageClient,
};
#[cfg(feature = "board-ui-experimental")]
use manekey_rp::platform::rp::user_interface::RiscvSioGpio25Led;
#[cfg(feature = "riscv-dual-core-trng")]
use manekey_rp::platform::rp2350::entropy::RiscvTrng;
#[cfg(all(
    feature = "riscv-dual-core-bootsel",
    not(feature = "up-always-present")
))]
use manekey_rp::platform::rp2350::riscv_dual_core::DualCoreBootselPresence;
#[cfg(not(feature = "riscv-dual-core-bootsel"))]
use manekey_rp::platform::rp2350::riscv_dual_core::RawGpio15UserPresence;
#[cfg(feature = "riscv-dual-core-bootsel")]
use manekey_rp::platform::rp2350::riscv_dual_core::core0_park_for_bootsel_if_requested;
use manekey_rp::platform::rp2350::riscv_dual_core::{RiscvPollingTransport, spawn_riscv_core1};
use manekey_rp::platform::rp2350::riscv_token_clock::Rp2350RiscvTokenClock;
#[cfg(not(feature = "riscv-dual-core-internal-ccid"))]
use manekey_rp::platform::rp2350::riscv_usb::write_response;

#[cfg(not(feature = "riscv-dual-core-internal-ccid"))]
const CTAPHID_POLL_INTERVAL_US: u64 = 100_000;

#[cfg(all())]
type SelectedFlashService = Core0FlashService<
    RiscvFlashStorage,
    RiscvPinUvAuthFlashStorage,
    manekey_rp::platform::rp::storage::RiscvManagedKeyFlashStorage,
>;

#[unsafe(link_section = ".start_block")]
#[used]
pub static IMAGE_DEF: hal::block::ImageDef = hal::block::ImageDef::secure_exe();

static ENDPOINT: MailboxEndpoint<TRUSTED_REQUEST_MAX, TRUSTED_RESPONSE_MAX> =
    MailboxEndpoint::new();
#[cfg(feature = "riscv-dual-core-flash")]
static FLASH_ENDPOINT: MailboxEndpoint<CORE0_FLASH_REQUEST_MAX, CORE0_FLASH_RESPONSE_MAX> =
    MailboxEndpoint::new();
static DISPATCHER: StaticCell<ProbeDispatcher> = StaticCell::new();
#[cfg(not(feature = "riscv-dual-core-ml-dsa-fips204-experimental"))]
const CORE1_STACK_WORDS: usize = 16_384;
#[cfg(feature = "riscv-dual-core-ml-dsa-fips204-experimental")]
const CORE1_STACK_WORDS: usize = 65_536;
static mut CORE1_STACK: Core1Stack<CORE1_STACK_WORDS> = Core1Stack::new();

#[repr(C, align(32))]
struct Core1Stack<const WORDS: usize> {
    mem: [usize; WORDS],
}

impl<const WORDS: usize> Core1Stack<WORDS> {
    const fn new() -> Self {
        Self { mem: [0; WORDS] }
    }
}

#[cfg(all(
    feature = "riscv-dual-core-bootsel",
    not(feature = "up-always-present")
))]
type SelectedUserPresence = DualCoreBootselPresence;
#[cfg(all(
    not(feature = "riscv-dual-core-bootsel"),
    not(feature = "up-always-present")
))]
type SelectedUserPresence = RawGpio15UserPresence;
#[cfg(feature = "up-always-present")]
type SelectedUserPresence = manekey::presence::AlwaysPresent;

#[cfg(feature = "board-ui-experimental")]
type SelectedPresenceObserver = UiPresenceObserver<NoPresenceObserver, RiscvSioGpio25Led>;
#[cfg(not(feature = "board-ui-experimental"))]
type SelectedPresenceObserver = NoPresenceObserver;

type ProbeDispatcher = TrustedDispatcher<
    SelectedStorage,
    SelectedUserPresence,
    UnavailableUserVerification,
    SelectedPinUvAuthProvider,
    SelectedPrivateKeyStore,
    SelectedEntropy,
    SelectedPresenceObserver,
>;

#[cfg(all())]
type SelectedPrivateKeyStore =
    manekey_rp::platform::rp2350::key_store::Keys<Core0FlashStorageClient<'static, 7>>;

#[cfg(not(feature = "riscv-dual-core-flash"))]
type SelectedStorage = StubStorage;

#[cfg(feature = "riscv-dual-core-flash")]
type SelectedStorage = Core0FlashStorageClient<'static>;

#[cfg(not(feature = "riscv-dual-core-flash"))]
type SelectedPinUvAuthProvider =
    StoredPinUvAuthProvider<VolatilePinUvAuthStorage, ClientPinCrypto, Rp2350RiscvTokenClock>;

#[cfg(feature = "riscv-dual-core-flash")]
type SelectedPinUvAuthProvider = StoredPinUvAuthProvider<
    JournaledPinUvAuthStorage<Core0FlashPinUvAuthStorageClient<'static>>,
    ClientPinCrypto,
    Rp2350RiscvTokenClock,
>;

#[cfg(all(not(feature = "riscv-dual-core-trng"), not(any())))]
compile_error!("Dual-core products require real TRNG; deterministic entropy is diagnostic-only");

#[cfg(feature = "riscv-dual-core-trng")]
type SelectedEntropy = HmacDrbgEntropy<RiscvTrng>;

#[cfg(feature = "riscv-dual-core-trng")]
fn selected_entropy(trng: hal::pac::TRNG) -> SelectedEntropy {
    HmacDrbgEntropy::new(RiscvTrng::new(trng)).unwrap()
}

#[cfg(not(feature = "riscv-dual-core-flash"))]
fn selected_storage() -> Storage<SelectedStorage> {
    Storage::new(StubStorage::new())
}

#[cfg(feature = "riscv-dual-core-flash")]
fn selected_storage() -> Storage<SelectedStorage> {
    Storage::new(Core0FlashStorageClient::new(&FLASH_ENDPOINT))
}

#[cfg(not(feature = "riscv-dual-core-flash"))]
fn selected_pin_uv_auth() -> SelectedPinUvAuthProvider {
    StoredPinUvAuthProvider::new_with_clock(VolatilePinUvAuthStorage::new(), Rp2350RiscvTokenClock)
}

#[cfg(feature = "riscv-dual-core-flash")]
fn selected_pin_uv_auth() -> SelectedPinUvAuthProvider {
    StoredPinUvAuthProvider::new_with_crypto_and_clock(
        JournaledPinUvAuthStorage::new(Core0FlashPinUvAuthStorageClient::new(&FLASH_ENDPOINT)),
        unsafe { riscv_crypto::client_pin_crypto() },
        Rp2350RiscvTokenClock,
    )
}

/// Core1-only crypto owner after clock/reset initialization, with a live core0 Flash pump for persistent configurations.
fn dispatcher(trng: hal::pac::TRNG) -> ProbeDispatcher {
    #[allow(unused_mut)]
    let mut entropy = selected_entropy(trng);
    #[allow(unused_mut)]
    let mut records = selected_storage();
    #[cfg(all())]
    let private_key_store = unsafe {
        manekey_rp::platform::rp2350::key_store::open(
            Core0FlashStorageClient::<7>::new(&FLASH_ENDPOINT),
            &mut records,
            &mut entropy,
        )
    }
    .expect("RP managed keys");

    #[cfg(all(
        feature = "riscv-dual-core-bootsel",
        not(feature = "up-always-present")
    ))]
    let presence = DualCoreBootselPresence::new();
    #[cfg(all(
        not(feature = "riscv-dual-core-bootsel"),
        not(feature = "up-always-present")
    ))]
    let presence = RawGpio15UserPresence::new();
    #[cfg(feature = "up-always-present")]
    let presence = manekey::presence::AlwaysPresent;
    #[cfg(feature = "board-ui-experimental")]
    let presence_observer = UiPresenceObserver::new(NoPresenceObserver, RiscvSioGpio25Led::new());
    #[cfg(not(feature = "board-ui-experimental"))]
    let presence_observer = NoPresenceObserver;
    TrustedDispatcher::new_with_transports_and_presence_observer(
        records,
        presence,
        UnavailableUserVerification,
        selected_pin_uv_auth(),
        private_key_store,
        entropy,
        manekey::transport::USB_TRANSPORTS,
        presence_observer,
    )
}

fn core1_entry(trng: hal::pac::TRNG) -> ! {
    let service = DISPATCHER.init(dispatcher(trng));

    let mut request = [0; TRUSTED_REQUEST_MAX];
    let mut response = [0; TRUSTED_RESPONSE_MAX];

    loop {
        match ENDPOINT.pump_operation_once(service, &mut request, &mut response) {
            Ok(true) => {
                hal::arch::sev();
            }
            Ok(false) => hal::arch::wfe(),
            Err(_) => hal::arch::wfe(),
        }
    }
}

/// Boot-ROM core1 entry; reclaim only reserved TRNG and startup FIFO, never competing core0 peripherals.
extern "C" fn riscv_core1_startup() -> ! {
    let peripherals = unsafe { hal::pac::Peripherals::steal() };
    let trng = peripherals.TRNG;
    let mut sio = hal::Sio::new(peripherals.SIO);
    sio.fifo.write_blocking(1);

    core1_entry(trng)
}

#[cfg(not(feature = "riscv-dual-core-internal-ccid"))]
fn handle_ctaphid_poll<T: manekey::ctaphid::trusted::TrustedBackend>(
    timer: hal::timer::Timer<hal::timer::CopyableTimer0>,
    next_poll_at: &mut u64,
    ctaphid: &mut CtaphidFrontend<T>,
    usb_dev: &mut usb_device::device::UsbDevice<'_, hal::usb::UsbBus>,
    hid: &mut HIDClass<'_, hal::usb::UsbBus>,
) {
    let now = timer.get_counter().ticks();
    if now.saturating_sub(*next_poll_at) < CTAPHID_POLL_INTERVAL_US {
        return;
    }
    *next_poll_at = now;

    if let Some(response) = ctaphid.poll() {
        write_response(usb_dev, hid, response);
    }
}

#[cfg(feature = "riscv-dual-core-flash")]
/// Sole Flash endpoint worker; preserve cross-hart exclusion through each storage mutation.
fn pump_core0_flash_service(
    service: &mut SelectedFlashService,
    request: &mut [u8; CORE0_FLASH_REQUEST_MAX],
    response: &mut [u8; CORE0_FLASH_RESPONSE_MAX],
) {
    if FLASH_ENDPOINT.state() != Ok(MailboxState::RequestReady) {
        return;
    }
    let result = FLASH_ENDPOINT
        .take_request(request)
        .and_then(|len| {
            service
                .process(&request[..len], response)
                .map_err(|_| MailboxError::InvalidState)
        })
        .and_then(|len| FLASH_ENDPOINT.publish_response(&response[..len]));
    if result.is_err() {
        let _ = FLASH_ENDPOINT.publish_response(&[0xff]);
    }
    hal::arch::sev();
}

#[hal::entry]
/// Sole core0 USB/Flash owner with a dedicated core1 stack; use real TRNG and reserved journals for product builds.
/// Dual cores do not provide PMP isolation; BOOTSEL/Flash require complete XIP-master exclusion.
fn main() -> ! {
    let mut pac = hal::pac::Peripherals::take().unwrap();
    let mut watchdog = hal::Watchdog::new(pac.WATCHDOG);
    let clocks = hal::clocks::init_clocks_and_plls(
        12_000_000,
        pac.XOSC,
        pac.CLOCKS,
        pac.PLL_SYS,
        pac.PLL_USB,
        &mut pac.RESETS,
        &mut watchdog,
    )
    .unwrap();

    let sio = hal::Sio::new(pac.SIO);
    let timer = hal::Timer::new_timer0(pac.TIMER0, &mut pac.RESETS, &clocks);
    let pins = hal::gpio::Pins::new(
        pac.IO_BANK0,
        pac.PADS_BANK0,
        sio.gpio_bank0,
        &mut pac.RESETS,
    );
    #[cfg(any(
        feature = "riscv-dual-core-internal-ccid",
        all(feature = "riscv-dual-core-ml-dsa-fips204-experimental", any())
    ))]
    let uart_pins = (pins.gpio0.into_function(), pins.gpio1.into_function());
    #[cfg(any(
        feature = "riscv-dual-core-internal-ccid",
        all(feature = "riscv-dual-core-ml-dsa-fips204-experimental", any())
    ))]
    let uart = hal::uart::UartPeripheral::new(pac.UART0, uart_pins, &mut pac.RESETS)
        .enable(
            hal::uart::UartConfig::new(
                115_200.Hz(),
                hal::uart::DataBits::Eight,
                None,
                hal::uart::StopBits::One,
            ),
            clocks.peripheral_clock.freq(),
        )
        .unwrap();
    #[cfg(not(feature = "riscv-dual-core-bootsel"))]
    let _button = pins.gpio15.into_pull_up_input();
    #[cfg(feature = "riscv-client-pin-sha256")]
    {
        pac.RESETS.reset().modify(|_, w| w.sha256().set_bit());
        pac.RESETS.reset().modify(|_, w| w.sha256().clear_bit());
        while pac.RESETS.reset_done().read().sha256().bit_is_clear() {}

        assert!(unsafe { riscv_crypto::sha256_known_answers() });
    }
    #[cfg(feature = "board-ui-experimental")]
    let _led = pins.gpio25.into_push_pull_output();
    let mut fifo = sio.fifo;
    unsafe {
        let stack_start = core::ptr::addr_of_mut!(CORE1_STACK.mem).cast::<usize>();
        spawn_riscv_core1(
            &mut pac.PSM,
            &mut fifo,
            stack_start,
            CORE1_STACK_WORDS,
            riscv_core1_startup,
        )
        .unwrap();
    }

    static USB_BUS: StaticCell<UsbBusAllocator<hal::usb::UsbBus>> = StaticCell::new();
    let usb_bus = USB_BUS.init(UsbBusAllocator::new(hal::usb::UsbBus::new(
        pac.USB,
        pac.USB_DPRAM,
        clocks.usb_clock,
        true,
        &mut pac.RESETS,
    )));
    let mut hid = HIDClass::new(usb_bus, REPORT_DESCRIPTOR, CTAPHID_POLL_MS);
    #[cfg(feature = "riscv-dual-core-internal-ccid")]
    let mut ccid = manekey::transport::usb::polling_ccid::PollingCcid::new(
        usb_bus,
        manekey::frontend::ccid::CCID_RESPONSE_MAX as u32,
    );
    let identity = CtaphidUsbDeviceInfo::new("RP2350 RISC-V dual-core FIDO", "riscv-dual-core");
    let mut usb_dev =
        UsbDeviceBuilder::new(usb_bus, UsbVidPid(identity.vendor_id, identity.product_id))
            .strings(&[StringDescriptors::default()
                .manufacturer(identity.manufacturer)
                .product(identity.product)
                .serial_number(identity.serial_number.unwrap_or(""))])
            .unwrap()
            .build();
    let transport = RiscvPollingTransport::new(&ENDPOINT);
    let trusted = MailboxTrustedBackend::new(transport);
    #[cfg(not(feature = "riscv-dual-core-internal-ccid"))]
    let mut ctaphid = CtaphidFrontend::with_trusted_backend(trusted);
    #[cfg(not(feature = "riscv-dual-core-internal-ccid"))]
    let mut next_poll_at = timer.get_counter().ticks();

    #[cfg(all())]
    let mut flash_service = Core0FlashService::with_key_backend(
        RiscvFlashStorage::new(),
        RiscvPinUvAuthFlashStorage::new(),
        manekey_rp::platform::rp::storage::RiscvManagedKeyFlashStorage,
    );
    #[cfg(feature = "riscv-dual-core-flash")]
    static FLASH_REQUEST: StaticCell<[u8; CORE0_FLASH_REQUEST_MAX]> = StaticCell::new();
    #[cfg(feature = "riscv-dual-core-flash")]
    static FLASH_RESPONSE: StaticCell<[u8; CORE0_FLASH_RESPONSE_MAX]> = StaticCell::new();
    #[cfg(feature = "riscv-dual-core-flash")]
    let flash_request = FLASH_REQUEST.init([0; CORE0_FLASH_REQUEST_MAX]);
    #[cfg(feature = "riscv-dual-core-flash")]
    let flash_response = FLASH_RESPONSE.init([0; CORE0_FLASH_RESPONSE_MAX]);

    #[cfg(feature = "riscv-dual-core-internal-ccid")]
    {
        uart.write_full_blocking(b"BOOT Pico 2 dual-core USB/Internal\r\n");
        let uart = core::cell::RefCell::new(uart);
        multi_transport::run(
            trusted,
            &mut || {
                #[cfg(feature = "riscv-dual-core-bootsel")]
                core0_park_for_bootsel_if_requested();
                pump_core0_flash_service(&mut flash_service, flash_request, flash_response);
            },
            timer,
            &mut usb_dev,
            &mut hid,
            &mut ccid,
            |buffer| uart.borrow_mut().read_raw(buffer).ok().unwrap_or(0),
            |bytes| uart.borrow_mut().write_full_blocking(bytes),
        );
    }

    #[cfg(not(feature = "riscv-dual-core-internal-ccid"))]
    loop {
        #[cfg(feature = "riscv-dual-core-bootsel")]
        core0_park_for_bootsel_if_requested();

        #[cfg(feature = "riscv-dual-core-flash")]
        pump_core0_flash_service(&mut flash_service, flash_request, flash_response);

        if usb_dev.poll(&mut [&mut hid]) {
            let mut report = [0u8; CTAPHID_REPORT_SIZE];
            if let Ok(CTAPHID_REPORT_SIZE) = hid.pull_raw_output(&mut report) {
                if let Some(response) = ctaphid.handle_raw(report) {
                    write_response(&mut usb_dev, &mut hid, response);
                }
            }
        }

        #[cfg(feature = "riscv-dual-core-flash")]
        pump_core0_flash_service(&mut flash_service, flash_request, flash_response);

        handle_ctaphid_poll(
            timer,
            &mut next_poll_at,
            &mut ctaphid,
            &mut usb_dev,
            &mut hid,
        );
    }
}

#[cfg(not(feature = "riscv-flash-managed-keys"))]
compile_error!("Public products require riscv-flash-managed-keys");
