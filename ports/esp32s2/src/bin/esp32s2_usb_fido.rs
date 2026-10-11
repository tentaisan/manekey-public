#![no_std]
#![no_main]

#[cfg(feature = "usb-ccid-experimental")]
use core::cell::RefCell;
use embassy_executor::Spawner;
#[cfg(feature = "usb-ccid-experimental")]
use embassy_sync::blocking_mutex::{Mutex, raw::NoopRawMutex};
#[cfg(any(any(), feature = "usb-dual-task"))]
use embassy_time::Timer;
use esp_alloc as _;
use esp_backtrace as _;
#[cfg(not(feature = "up-always-present"))]
use esp_hal::gpio::{Level, Output};
#[cfg(all(
    feature = "experimental-ml-dsa-fips204",
    not(feature = "ml-dsa-integrated-layout")
))]
use esp_hal::ram;
use esp_hal::{
    interrupt::software::SoftwareInterruptControl,
    rng::TrngSource,
    timer::timg::TimerGroup,
    usb::otg::{
        Usb,
        embassy_usb_device::{Config as UsbConfig, Driver},
    },
};
use esp_println::println;
use esp32s2::board::{USB_DM_GPIO, USB_DP_GPIO, USB_IDENTITY};
#[cfg(all(
    not(feature = "up-always-present"),
    any(feature = "usb-ccid-experimental", feature = "usb-dual-task")
))]
use esp32s2::fido::EspUiSharedTrustedDispatcher;
#[cfg(not(feature = "client-pin-flash"))]
use esp32s2::fido::build_usb_dispatcher_with_ui_from_parts;
#[cfg(all(feature = "client-pin-flash", not(feature = "up-always-present")))]
use esp32s2::fido::build_usb_flash_dispatcher_with_ui_from_parts;
#[cfg(feature = "up-always-present")]
use esp32s2::fido::{
    EspAlwaysSharedTrustedDispatcher, build_shared_dispatcher_with_observer_from_parts,
};
#[cfg(feature = "client-pin-flash")]
use esp32s2::storage::{SharedEspFlash, new_shared_esp_flash};
#[cfg(not(feature = "usb-ccid-experimental"))]
use esp32s2::usb_hid::run_esp_usb_hid;
#[cfg(not(feature = "up-always-present"))]
use esp32s2::{board::USER_LED_ACTIVE_HIGH, presence::EspGpioUserPresence, ui::EspGpioUiOutput};
#[cfg(feature = "usb-ccid-experimental")]
use esp32s2::{
    usb_composite::{CcidIoBuffers, run_esp_usb_ingress},
    usb_ingress::{SharedArbiter, UsbIngressFrontend},
};
#[cfg(not(feature = "usb-ccid-experimental"))]
use manekey::ctaphid::CtaphidFrontend;

#[cfg(feature = "usb-ccid-experimental")]
use manekey::frontend::ingress::IngressArbiter;
#[cfg(feature = "usb-dual-task")]
use manekey::{
    boundary::{
        mailbox::{LocalMailboxTransport, LocalMailboxWorker, MailboxEndpoint},
        mailbox_backend::MailboxTrustedBackend,
    },
    ctaphid::trusted::{TRUSTED_REQUEST_MAX, TRUSTED_RESPONSE_MAX},
};
use static_cell::StaticCell;

#[cfg(feature = "up-always-present")]
type S2Dispatcher = EspAlwaysSharedTrustedDispatcher;
#[cfg(all(feature = "client-pin-flash", not(feature = "up-always-present")))]
type S2Dispatcher = EspUiSharedTrustedDispatcher<EspGpioUiOutput>;
#[cfg(feature = "internal-uart")]
use esp32s2::internal_ingress::{SharedInternalIngressFrontend, run_internal_uart};
#[cfg(feature = "internal-uart")]
use manekey::transport::interconnect::{HEADER_LEN, TRAILER_LEN};

static EP_OUT_BUFFER: StaticCell<[u8; 1024]> = StaticCell::new();
#[cfg(feature = "usb-dual-task")]
type S2Worker = LocalMailboxWorker<S2Dispatcher, TRUSTED_REQUEST_MAX, TRUSTED_RESPONSE_MAX>;
#[cfg(feature = "usb-dual-task")]
static MAILBOX: MailboxEndpoint<TRUSTED_REQUEST_MAX, TRUSTED_RESPONSE_MAX> = MailboxEndpoint::new();
#[cfg(feature = "usb-dual-task")]
static WORKER: StaticCell<S2Worker> = StaticCell::new();
#[cfg(all(feature = "usb-ccid-experimental", feature = "usb-dual-task"))]
type S2MailboxBackend = MailboxTrustedBackend<
    LocalMailboxTransport<'static, TRUSTED_REQUEST_MAX, TRUSTED_RESPONSE_MAX>,
>;

#[cfg(feature = "client-pin-flash")]
static FLASH: StaticCell<SharedEspFlash<'static>> = StaticCell::new();
#[cfg(all(feature = "usb-ccid-experimental", not(feature = "usb-dual-task")))]
static ARBITER: StaticCell<SharedArbiter<S2Dispatcher>> = StaticCell::new();
#[cfg(all(feature = "usb-ccid-experimental", feature = "usb-dual-task"))]
static ARBITER: StaticCell<SharedArbiter<S2MailboxBackend>> = StaticCell::new();
#[cfg(feature = "usb-ccid-experimental")]
static CCID_BUFFERS: StaticCell<CcidIoBuffers> = StaticCell::new();

#[cfg(all(feature = "internal-uart", feature = "usb-dual-task"))]
type S2Backend = S2MailboxBackend;
#[cfg(all(feature = "internal-uart", not(feature = "usb-dual-task")))]
type S2Backend = S2Dispatcher;
#[cfg(feature = "internal-uart")]
const INTERNAL_FRAME_MAX: usize = 1024 + HEADER_LEN + TRAILER_LEN;
#[cfg(feature = "internal-uart")]
const INTERNAL_RESPONSE_MAX: usize =
    manekey::ctaphid::trusted::TRUSTED_RESPONSE_MAX + HEADER_LEN + TRAILER_LEN;
#[cfg(feature = "internal-uart")]
type InternalFrontend = SharedInternalIngressFrontend<S2Backend, INTERNAL_FRAME_MAX>;
#[cfg(feature = "internal-uart")]
static INTERNAL: StaticCell<InternalFrontend> = StaticCell::new();
#[cfg(feature = "internal-uart")]
static INTERNAL_RESPONSE: StaticCell<[u8; INTERNAL_RESPONSE_MAX]> = StaticCell::new();
#[cfg(feature = "internal-uart")]
#[embassy_executor::task]
async fn internal_uart_task(
    uart: esp_hal::uart::Uart<'static, esp_hal::Async>,
    frontend: &'static mut InternalFrontend,
    response: &'static mut [u8; INTERNAL_RESPONSE_MAX],
) {
    run_internal_uart(uart, frontend, response).await;
}

#[cfg(all(
    feature = "usb-dual-task",
    any(
        feature = "experimental-ml-dsa-fips204",
        feature = "experimental-ml-dsa-fips204-scratch",
        feature = "experimental-ml-dsa-mldsa-native"
    ),
    not(feature = "ml-dsa-memory-layout")
))]
compile_error!("S2 dual-task ML-DSA requires the integrated memory layout");

#[cfg(feature = "usb-dual-task")]
#[embassy_executor::task]
async fn trusted_task(worker: &'static mut S2Worker) {
    loop {
        let _ = worker.pump_once(&MAILBOX);
        Timer::after_millis(2).await;
    }
}

esp_bootloader_esp_idf::esp_app_desc!();

#[esp_hal::main]
/// Feature-selected product boot; worker tasks do not enforce hardware RAM isolation.
async fn main(spawner: Spawner) {
    let peripherals = esp_hal::init(esp_hal::Config::default());

    #[cfg(feature = "ml-dsa-memory-layout")]
    esp_alloc::heap_allocator!(#[unsafe(link_section = ".ml_dsa_heap")] size: 8 * 1024);
    #[cfg(all(
        feature = "experimental-ml-dsa-fips204",
        not(feature = "ml-dsa-memory-layout")
    ))]
    esp_alloc::heap_allocator!(#[ram(reclaimed)] size: 32 * 1024);
    #[cfg(all(
        not(feature = "experimental-ml-dsa-fips204"),
        not(feature = "ml-dsa-memory-layout")
    ))]
    esp_alloc::heap_allocator!(size: 64 * 1024);

    let _ = spawner;

    println!("MANEKEY ESP32-S2 USB FIDO");

    println!("USB FS D+ GPIO{USB_DP_GPIO}, D- GPIO{USB_DM_GPIO}");
    let _trng_source = TrngSource::new(peripherals.RNG, peripherals.ADC1);

    let sw_int = SoftwareInterruptControl::new(peripherals.SW_INTERRUPT);
    let timg0 = TimerGroup::new(peripherals.TIMG0);
    esp_rtos::start(timg0.timer0, sw_int.software_interrupt0);

    let usb = Usb::new_fs(peripherals.USB_FS, peripherals.GPIO20, peripherals.GPIO19);
    let driver = Driver::new(usb, EP_OUT_BUFFER.init([0; 1024]), UsbConfig::default());
    #[cfg(feature = "client-pin-flash")]
    let flash = FLASH.init(new_shared_esp_flash(peripherals.FLASH));
    #[cfg(feature = "up-always-present")]
    let dispatcher = build_shared_dispatcher_with_observer_from_parts(
        flash,
        manekey::presence::AlwaysPresent,
        peripherals.SHA,
        peripherals.AES,
        manekey::transport::USB_TRANSPORTS,
        esp32s2::presence::EspTextPresenceObserver,
    );
    #[cfg(all(feature = "client-pin-flash", not(feature = "up-always-present")))]
    let dispatcher = build_usb_flash_dispatcher_with_ui_from_parts(
        flash,
        EspGpioUserPresence::from_gpio0(peripherals.GPIO0),
        EspGpioUiOutput::new(
            Output::new(peripherals.GPIO13, Level::Low, Default::default()),
            USER_LED_ACTIVE_HIGH,
        ),
        peripherals.SHA,
        peripherals.AES,
    );
    #[cfg(not(feature = "client-pin-flash"))]
    let dispatcher = build_usb_dispatcher_with_ui_from_parts(
        peripherals.FLASH,
        EspGpioUserPresence::from_gpio0(peripherals.GPIO0),
        EspGpioUiOutput::new(
            Output::new(peripherals.GPIO13, Level::Low, Default::default()),
            USER_LED_ACTIVE_HIGH,
        ),
        peripherals.SHA,
        peripherals.AES,
    );
    println!("ESP32-S2 USB FIDO initialized");
    #[cfg(feature = "usb-dual-task")]
    let backend = {
        spawner.spawn(trusted_task(WORKER.init(S2Worker::new(dispatcher))).unwrap());
        MailboxTrustedBackend::new(LocalMailboxTransport::new(&MAILBOX))
    };
    #[cfg(not(feature = "usb-dual-task"))]
    let backend = dispatcher;
    #[cfg(feature = "usb-ccid-experimental")]
    {
        let arbiter = ARBITER.init(Mutex::<NoopRawMutex, _>::new(RefCell::new(
            IngressArbiter::new(backend),
        )));
        let mut usb_fido = UsbIngressFrontend::new(arbiter);
        #[cfg(feature = "internal-uart")]
        {
            use esp_hal::uart::{Config, RxConfig, Uart};
            let uart = Uart::new(
                peripherals.UART0,
                Config::default()
                    .with_baudrate(115_200)
                    .with_rx(RxConfig::default().with_fifo_full_threshold(1)),
            )
            .expect("S2 UART0 configuration")
            .with_tx(peripherals.GPIO43)
            .with_rx(peripherals.GPIO44)
            .into_async();
            spawner.spawn(
                internal_uart_task(
                    uart,
                    INTERNAL.init(InternalFrontend::new(0, arbiter)),
                    INTERNAL_RESPONSE.init([0; INTERNAL_RESPONSE_MAX]),
                )
                .expect("create Internal UART task"),
            );
            println!("S2 Internal UART0 GPIO43 TX/GPIO44 RX 115200 8N1");
        }
        run_esp_usb_ingress(
            driver,
            &mut usb_fido,
            &USB_IDENTITY,
            true,
            CCID_BUFFERS.init(CcidIoBuffers::new()),
        )
        .await
    }
    #[cfg(not(feature = "usb-ccid-experimental"))]
    let ctaphid = CtaphidFrontend::with_trusted_backend(backend);
    #[cfg(not(feature = "usb-ccid-experimental"))]
    run_esp_usb_hid(driver, ctaphid, &USB_IDENTITY).await
}
