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

#[cfg(feature = "riscv-single-core-task-transport")]
use manekey::boundary::{
    mailbox::{LocalMailboxTransport, MailboxEndpoint},
    mailbox_backend::MailboxTrustedBackend,
};
#[cfg(not(any(
    feature = "riscv-single-core-task-transport",
    feature = "riscv-usb-internal-ccid"
)))]
use manekey::ctaphid::Ctaphid;
#[cfg(all(
    feature = "riscv-single-core-task-transport",
    not(feature = "riscv-usb-internal-ccid")
))]
use manekey::ctaphid::CtaphidFrontend;

#[cfg(any(
    feature = "riscv-single-core-task-transport",
    feature = "riscv-usb-internal-ccid"
))]
use manekey::ctaphid::trusted::TrustedDispatcher;
#[cfg(feature = "riscv-single-core-task-transport")]
use manekey::ctaphid::trusted::{TRUSTED_REQUEST_MAX, TRUSTED_RESPONSE_MAX};
use manekey::ctaphid::{
    descriptor::{CtaphidUsbDeviceInfo, POLL_MS as CTAPHID_POLL_MS},
    entropy::HmacDrbgEntropy,
    pin_uv_auth::{JournaledPinUvAuthStorage, StoredPinUvAuthProvider},
    storage::Storage,
    user_verification::UnavailableUserVerification,
};
use manekey_rp::platform::rp2350::riscv_crypto::{self, ClientPinCrypto};
#[cfg(feature = "riscv-usb-internal-ccid")]
#[path = "riscv_usb_internal.rs"]
mod multi_transport;
#[cfg(not(feature = "riscv-usb-internal-ccid"))]
use manekey::ctaphid::descriptor::REPORT_SIZE as CTAPHID_REPORT_SIZE;
use manekey::presence::NoPresenceObserver;
#[cfg(feature = "board-ui-experimental")]
use manekey::user_interface::UiPresenceObserver;
use manekey_rp::platform::rp::storage::{RiscvFlashStorage, RiscvPinUvAuthFlashStorage};
#[cfg(all(feature = "riscv-bootsel-presence", not(feature = "up-always-present")))]
use manekey_rp::platform::rp::user_interface::RiscvBootselPresence;
#[cfg(feature = "board-ui-experimental")]
use manekey_rp::platform::rp::user_interface::RiscvGpio25Led;
#[cfg(not(feature = "riscv-bootsel-presence"))]
use manekey_rp::platform::rp::user_interface::RiscvGpioUserPresence;
use manekey_rp::platform::rp2350::entropy::RiscvTrng;
use manekey_rp::platform::rp2350::riscv_token_clock::Rp2350RiscvTokenClock;
use manekey_rp::platform::rp2350::riscv_usb::CTAPHID_REPORT_DESCRIPTOR;
#[cfg(not(feature = "riscv-usb-internal-ccid"))]
use manekey_rp::platform::rp2350::riscv_usb::write_response;

#[cfg(not(feature = "riscv-usb-internal-ccid"))]
const CTAPHID_POLL_INTERVAL_US: u64 = 100_000;

#[unsafe(link_section = ".start_block")]
#[used]
pub static IMAGE_DEF: hal::block::ImageDef = hal::block::ImageDef::secure_exe();

#[cfg(not(feature = "riscv-bootsel-presence"))]
type ButtonPin = hal::gpio::Pin<
    hal::gpio::bank0::Gpio15,
    hal::gpio::FunctionSio<hal::gpio::SioInput>,
    hal::gpio::PullUp,
>;

#[cfg(all(feature = "riscv-bootsel-presence", not(feature = "up-always-present")))]
type SelectedUserPresence = RiscvBootselPresence;

#[cfg(all(
    not(feature = "riscv-bootsel-presence"),
    not(feature = "up-always-present")
))]
type SelectedUserPresence = RiscvGpioUserPresence<ButtonPin>;
#[cfg(feature = "up-always-present")]
type SelectedUserPresence = manekey::presence::AlwaysPresent;

#[cfg(feature = "board-ui-experimental")]
type SelectedPresenceObserver = UiPresenceObserver<NoPresenceObserver, RiscvGpio25Led>;

#[cfg(not(feature = "board-ui-experimental"))]
type SelectedPresenceObserver = NoPresenceObserver;

#[cfg(all())]
type SelectedPrivateKeyStore = manekey_rp::platform::rp2350::key_store::Keys<
    manekey_rp::platform::rp::storage::RiscvManagedKeyFlashStorage,
>;

#[cfg(any(
    feature = "riscv-single-core-task-transport",
    feature = "riscv-usb-internal-ccid"
))]
type SingleCoreDispatcher = TrustedDispatcher<
    RiscvFlashStorage,
    SelectedUserPresence,
    UnavailableUserVerification,
    StoredPinUvAuthProvider<
        JournaledPinUvAuthStorage<RiscvPinUvAuthFlashStorage>,
        ClientPinCrypto,
        Rp2350RiscvTokenClock,
    >,
    SelectedPrivateKeyStore,
    HmacDrbgEntropy<RiscvTrng>,
    SelectedPresenceObserver,
>;

#[cfg(not(any(
    feature = "riscv-single-core-task-transport",
    feature = "riscv-usb-internal-ccid"
)))]
type SingleCoreCtaphid = Ctaphid<
    RiscvFlashStorage,
    SelectedUserPresence,
    UnavailableUserVerification,
    StoredPinUvAuthProvider<
        JournaledPinUvAuthStorage<RiscvPinUvAuthFlashStorage>,
        ClientPinCrypto,
        Rp2350RiscvTokenClock,
    >,
    SelectedPrivateKeyStore,
    HmacDrbgEntropy<RiscvTrng>,
    SelectedPresenceObserver,
>;

#[cfg(all(
    feature = "riscv-single-core-task-transport",
    not(feature = "riscv-usb-internal-ccid")
))]
type SingleCoreCtaphid = CtaphidFrontend<
    MailboxTrustedBackend<
        LocalMailboxTransport<'static, TRUSTED_REQUEST_MAX, TRUSTED_RESPONSE_MAX>,
    >,
>;

#[cfg(feature = "riscv-single-core-task-transport")]
static MAILBOX_ENDPOINT: MailboxEndpoint<TRUSTED_REQUEST_MAX, TRUSTED_RESPONSE_MAX> =
    MailboxEndpoint::new();

#[cfg(not(feature = "riscv-usb-internal-ccid"))]
/// TIMER0 uses microseconds; exclusively own frontend and USB objects throughout polling and response writes.
fn handle_ctaphid_poll(
    timer: hal::timer::Timer<hal::timer::CopyableTimer0>,
    next_poll_at: &mut u64,
    ctaphid: &mut SingleCoreCtaphid,
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

#[hal::entry]
/// Sole-hart startup and polling owner of USB/UART/TRNG/SHA/Flash; use the selected reserved journal geometry.
/// Local mailbox pumping is functional separation, not independent task execution or hardware isolation.
/// BOOTSEL and Flash mutations require exclusion of every other XIP master.
fn main() -> ! {
    let mut pac = hal::pac::Peripherals::take().unwrap();
    let sio = hal::Sio::new(pac.SIO);
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
    let timer = hal::Timer::new_timer0(pac.TIMER0, &mut pac.RESETS, &clocks);

    let pins = hal::gpio::Pins::new(
        pac.IO_BANK0,
        pac.PADS_BANK0,
        sio.gpio_bank0,
        &mut pac.RESETS,
    );
    #[cfg(feature = "riscv-usb-internal-ccid")]
    use hal::clocks::Clock;
    #[cfg(feature = "riscv-usb-internal-ccid")]
    use hal::fugit::RateExtU32;
    #[cfg(feature = "riscv-usb-internal-ccid")]
    let uart = hal::uart::UartPeripheral::new(
        pac.UART0,
        (pins.gpio0.into_function(), pins.gpio1.into_function()),
        &mut pac.RESETS,
    )
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
    #[cfg(feature = "riscv-usb-internal-ccid")]
    uart.write_full_blocking(b"BOOT Pico 2 RISC-V USB/Internal\r\n");
    #[cfg(feature = "riscv-client-pin-sha256")]
    {
        pac.RESETS.reset().modify(|_, w| w.sha256().set_bit());
        pac.RESETS.reset().modify(|_, w| w.sha256().clear_bit());
        while pac.RESETS.reset_done().read().sha256().bit_is_clear() {}

        assert!(unsafe { riscv_crypto::sha256_known_answers() });
        #[cfg(feature = "riscv-usb-internal-ccid")]
        uart.write_full_blocking(b"SHA256 KAT passed\r\n");
    }
    #[cfg(not(feature = "riscv-bootsel-presence"))]
    let button = pins.gpio15.into_pull_up_input();
    #[cfg(feature = "board-ui-experimental")]
    let led = pins.gpio25.into_push_pull_output();

    static USB_BUS: StaticCell<UsbBusAllocator<hal::usb::UsbBus>> = StaticCell::new();
    let usb_bus = USB_BUS.init(UsbBusAllocator::new(hal::usb::UsbBus::new(
        pac.USB,
        pac.USB_DPRAM,
        clocks.usb_clock,
        true,
        &mut pac.RESETS,
    )));
    let mut hid = HIDClass::new(usb_bus, CTAPHID_REPORT_DESCRIPTOR, CTAPHID_POLL_MS);
    #[cfg(feature = "riscv-usb-internal-ccid")]
    let mut ccid = manekey::transport::usb::polling_ccid::PollingCcid::new(
        usb_bus,
        manekey::frontend::ccid::CCID_RESPONSE_MAX as u32,
    );
    let identity = CtaphidUsbDeviceInfo::new("RP2350 RISC-V single-core", "riscv-single-core");
    let mut usb_dev =
        UsbDeviceBuilder::new(usb_bus, UsbVidPid(identity.vendor_id, identity.product_id))
            .strings(&[StringDescriptors::default()
                .manufacturer(identity.manufacturer)
                .product(identity.product)
                .serial_number(identity.serial_number.unwrap_or(""))])
            .unwrap()
            .build();

    #[allow(unused_mut)]
    let mut entropy = HmacDrbgEntropy::new(RiscvTrng::new(pac.TRNG)).unwrap();
    #[allow(unused_mut)]
    let mut storage = Storage::new(RiscvFlashStorage::new());
    #[cfg(all())]
    let private_key_store = unsafe {
        manekey_rp::platform::rp2350::key_store::open(
            manekey_rp::platform::rp::storage::RiscvManagedKeyFlashStorage,
            &mut storage,
            &mut entropy,
        )
    }
    .expect("RP managed keys");

    #[cfg(all(feature = "riscv-bootsel-presence", not(feature = "up-always-present")))]
    let presence = RiscvBootselPresence::new();
    #[cfg(all(
        not(feature = "riscv-bootsel-presence"),
        not(feature = "up-always-present")
    ))]
    let presence = RiscvGpioUserPresence::new(button, timer);
    #[cfg(feature = "up-always-present")]
    let presence = manekey::presence::AlwaysPresent;
    #[cfg(feature = "board-ui-experimental")]
    let presence_observer = UiPresenceObserver::new(NoPresenceObserver, RiscvGpio25Led::new(led));
    #[cfg(not(feature = "board-ui-experimental"))]
    let presence_observer = NoPresenceObserver;
    let pin_uv_auth = StoredPinUvAuthProvider::new_with_crypto_and_clock(
        JournaledPinUvAuthStorage::new(RiscvPinUvAuthFlashStorage::new()),
        unsafe { riscv_crypto::client_pin_crypto() },
        Rp2350RiscvTokenClock,
    );

    #[cfg(not(feature = "riscv-usb-internal-ccid"))]
    static CTAPHID: StaticCell<SingleCoreCtaphid> = StaticCell::new();
    #[cfg(not(any(
        feature = "riscv-single-core-task-transport",
        feature = "riscv-usb-internal-ccid"
    )))]
    let ctaphid = CTAPHID.init(Ctaphid::new_with_presence_observer(
        storage,
        presence,
        UnavailableUserVerification,
        pin_uv_auth,
        private_key_store,
        entropy,
        presence_observer,
    ));

    #[cfg(any(
        feature = "riscv-single-core-task-transport",
        feature = "riscv-usb-internal-ccid"
    ))]
    static DISPATCHER: StaticCell<SingleCoreDispatcher> = StaticCell::new();
    #[cfg(any(
        feature = "riscv-single-core-task-transport",
        feature = "riscv-usb-internal-ccid"
    ))]
    let dispatcher = DISPATCHER.init(
        TrustedDispatcher::new_with_transports_and_presence_observer(
            storage,
            presence,
            UnavailableUserVerification,
            pin_uv_auth,
            private_key_store,
            entropy,
            manekey::transport::USB_TRANSPORTS,
            presence_observer,
        ),
    );
    #[cfg(all(
        feature = "riscv-single-core-task-transport",
        not(feature = "riscv-usb-internal-ccid")
    ))]
    let ctaphid = CTAPHID.init(CtaphidFrontend::with_trusted_backend(
        MailboxTrustedBackend::new(LocalMailboxTransport::new(&MAILBOX_ENDPOINT)),
    ));

    #[cfg(feature = "riscv-single-core-task-transport")]
    let mut trusted_request = [0; TRUSTED_REQUEST_MAX];
    #[cfg(feature = "riscv-single-core-task-transport")]
    let mut trusted_response = [0; TRUSTED_RESPONSE_MAX];

    #[cfg(feature = "riscv-single-core-task-transport")]
    let mut pump_trusted = || {
        let _ = MAILBOX_ENDPOINT.pump_operation_once(
            dispatcher,
            &mut trusted_request,
            &mut trusted_response,
        );
    };

    #[cfg(feature = "riscv-usb-internal-ccid")]
    let uart = core::cell::RefCell::new(uart);

    #[cfg(all(
        feature = "riscv-usb-internal-ccid",
        feature = "riscv-single-core-task-transport"
    ))]
    multi_transport::run(
        MailboxTrustedBackend::new(LocalMailboxTransport::new(&MAILBOX_ENDPOINT)),
        &mut pump_trusted,
        timer,
        &mut usb_dev,
        &mut hid,
        &mut ccid,
        |buffer| uart.borrow_mut().read_raw(buffer).ok().unwrap_or(0),
        |bytes| uart.borrow_mut().write_full_blocking(bytes),
    );
    #[cfg(all(
        feature = "riscv-usb-internal-ccid",
        not(feature = "riscv-single-core-task-transport")
    ))]
    multi_transport::run(
        multi_transport::BorrowedBackend(dispatcher),
        &mut || {},
        timer,
        &mut usb_dev,
        &mut hid,
        &mut ccid,
        |buffer| uart.borrow_mut().read_raw(buffer).ok().unwrap_or(0),
        |bytes| uart.borrow_mut().write_full_blocking(bytes),
    );

    #[cfg(not(feature = "riscv-usb-internal-ccid"))]
    let mut next_poll_at = timer.get_counter().ticks();

    #[cfg(not(feature = "riscv-usb-internal-ccid"))]
    loop {
        #[cfg(feature = "riscv-single-core-task-transport")]
        pump_trusted();

        if usb_dev.poll(&mut [&mut hid]) {
            let mut report = [0u8; CTAPHID_REPORT_SIZE];
            if let Ok(CTAPHID_REPORT_SIZE) = hid.pull_raw_output(&mut report) {
                if let Some(response) = ctaphid.handle_raw(report) {
                    #[cfg(feature = "riscv-single-core-task-transport")]
                    pump_trusted();
                    write_response(&mut usb_dev, &mut hid, response);
                }
            }
        }

        #[cfg(feature = "riscv-single-core-task-transport")]
        pump_trusted();
        handle_ctaphid_poll(timer, &mut next_poll_at, ctaphid, &mut usb_dev, &mut hid);
    }
}

#[cfg(not(feature = "riscv-flash-managed-keys"))]
compile_error!("Public products require riscv-flash-managed-keys");
