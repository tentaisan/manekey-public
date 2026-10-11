#![no_std]
#![no_main]

#[cfg(any(
    feature = "trustzone-secure-layout",
    feature = "trustzone-nonsecure-image"
))]
compile_error!("The normal product is not a TrustZone image; select the explicit TZ binary");

use embassy_executor::Spawner;
use embassy_futures::join::join;
use embassy_stm32::{bind_interrupts, peripherals, usb};
use embassy_usb::class::hid::{HidBootProtocol, HidReaderWriter, HidSubclass, State};
use manekey::ctaphid::{
    descriptor::{CtaphidUsbDeviceInfo, REPORT_DESCRIPTOR, REPORT_SIZE},
    entropy::{EntropyError, EntropySource, HmacDrbgEntropy},
    pin_uv_auth::{JournaledPinUvAuthStorage, PinUvAuthTokenClock, StoredPinUvAuthProvider},
    storage::Storage,
    trusted::TrustedDispatcher,
    user_verification::UnavailableUserVerification,
};
use manekey::frontend::ingress::IngressArbiter;
#[cfg(not(feature = "physical-up"))]
use manekey::presence::AlwaysPresent;
use manekey::{
    presence::NoPresenceObserver,
    user_interface::{AtomicUiStatus, UiPresenceObserver},
};
#[cfg(feature = "physical-up")]
type Presence = manekey_stm32u575::ui::PhysicalPresence;
#[cfg(not(feature = "physical-up"))]
type Presence = AlwaysPresent;
#[cfg(feature = "usb-ccid")]
use manekey::transport::usb::embassy::{
    CcidIoBuffers, CcidUsbClass, CcidUsbState, run_ccid_ingress_loop,
};
use manekey::transport::usb::embassy::{
    SharedUsbArbiter, UsbIngressFrontend, run_hid_ingress_loop,
};
use manekey_stm32u575::crypto::ClientPinCrypto;
use manekey_stm32u575::key_store::Keys as KeyStore;
use manekey_stm32u575::storage::{Journal, SharedFlash};

use static_cell::StaticCell;

struct TokenClock;
impl PinUvAuthTokenClock for TokenClock {
    fn now_ms(&self) -> u64 {
        embassy_time::Instant::now().as_millis()
    }
}

bind_interrupts!(struct Irqs {
    OTG_FS => usb::InterruptHandler<peripherals::USB_OTG_FS>;
    #[cfg(feature = "internal-uart")]
    USART1 => embassy_stm32::usart::BufferedInterruptHandler<peripherals::USART1>;
});

struct Stm32Entropy(embassy_stm32::rng::Rng<'static, embassy_stm32::mode::Blocking>);

impl EntropySource for Stm32Entropy {
    fn fill_entropy(&mut self, output: &mut [u8]) -> Result<(), EntropyError> {
        self.0.blocking_fill_bytes(output);
        Ok(())
    }
}

type Dispatcher = TrustedDispatcher<
    Journal,
    Presence,
    UnavailableUserVerification,
    StoredPinUvAuthProvider<JournaledPinUvAuthStorage<Journal>, ClientPinCrypto, TokenClock>,
    KeyStore,
    HmacDrbgEntropy<Stm32Entropy>,
    UiPresenceObserver<NoPresenceObserver, &'static AtomicUiStatus>,
>;

#[cfg(feature = "dual-task")]
use manekey::{
    boundary::{
        mailbox::{LocalMailboxTransport, LocalMailboxWorker, MailboxEndpoint},
        mailbox_backend::MailboxTrustedBackend,
    },
    ctaphid::trusted::{TRUSTED_REQUEST_MAX, TRUSTED_RESPONSE_MAX},
};
#[cfg(feature = "dual-task")]
type Backend = MailboxTrustedBackend<
    LocalMailboxTransport<'static, TRUSTED_REQUEST_MAX, TRUSTED_RESPONSE_MAX>,
>;
#[cfg(not(feature = "dual-task"))]
type Backend = Dispatcher;
#[cfg(feature = "dual-task")]
type Worker = LocalMailboxWorker<Dispatcher, TRUSTED_REQUEST_MAX, TRUSTED_RESPONSE_MAX>;
#[cfg(feature = "dual-task")]
static MAILBOX: MailboxEndpoint<TRUSTED_REQUEST_MAX, TRUSTED_RESPONSE_MAX> = MailboxEndpoint::new();
#[cfg(feature = "dual-task")]
#[embassy_executor::task]
async fn trusted_task(worker: &'static mut Worker) {
    loop {
        let _ = worker.pump_once(&MAILBOX);
        embassy_time::Timer::after_millis(2).await;
    }
}

#[embassy_executor::main]
/// Cooperative worker product, not TrustZone isolation; caller owns USB identity, IRQs and Flash reservations.
async fn main(_spawner: Spawner) {
    let mut config = embassy_stm32::Config::default();

    config.enable_ucpd1_dead_battery = true;
    use embassy_stm32::rcc::*;
    config.rcc.hsi = true;
    config.rcc.pll1 = Some(Pll {
        source: PllSource::Hsi,
        prediv: PllPreDiv::Div1,
        mul: PllMul::Mul10,
        divp: None,
        divq: None,
        divr: Some(PllDiv::Div1),
    });
    config.rcc.sys = Sysclk::Pll1R;
    config.rcc.voltage_range = VoltageScale::Range1;
    config.rcc.hsi48 = Some(embassy_stm32::rcc::Hsi48Config {
        sync_from_usb: true,
    });
    config.rcc.mux.iclksel = embassy_stm32::rcc::mux::Iclksel::Hsi48;
    config.rcc.mux.rngsel = embassy_stm32::rcc::mux::Rngsel::Hsi48;
    let p = embassy_stm32::init(config);

    use embassy_stm32::gpio::{Level, Output, Speed};
    _spawner.spawn(
        manekey_stm32u575::ui::led_task(Output::new(p.PC7, Level::Low, Speed::Low)).unwrap(),
    );
    #[cfg(feature = "physical-up")]
    let presence = manekey_stm32u575::ui::physical_presence(embassy_stm32::gpio::Input::new(
        p.PC13,
        embassy_stm32::gpio::Pull::Down,
    ));
    #[cfg(not(feature = "physical-up"))]
    let presence = AlwaysPresent;

    let mut rng = Stm32Entropy(embassy_stm32::rng::Rng::new_blocking(p.RNG));
    static FLASH: StaticCell<SharedFlash> = StaticCell::new();
    let flash = FLASH.init(critical_section::Mutex::new(core::cell::RefCell::new(
        embassy_stm32::flash::Flash::new_blocking(p.FLASH),
    )));
    #[cfg(feature = "hardware-sha256")]
    manekey_stm32u575::sha256::initialize(p.HASH);

    let mut records = Storage::new(Journal::credentials(flash));
    let keys =
        manekey_stm32u575::key_store::open(flash, &mut rng, &mut records).expect("key store");
    let entropy = HmacDrbgEntropy::new(rng).unwrap();
    let dispatcher = TrustedDispatcher::new_with_transports_and_presence_observer(
        records,
        presence,
        UnavailableUserVerification,
        StoredPinUvAuthProvider::new_with_crypto_and_clock(
            JournaledPinUvAuthStorage::new(Journal::pin(flash)),
            manekey_stm32u575::crypto::client_pin_crypto(),
            TokenClock,
        ),
        keys,
        entropy,
        manekey::transport::USB_TRANSPORTS,
        UiPresenceObserver::new(NoPresenceObserver, &manekey_stm32u575::ui::STATUS),
    );
    #[cfg(feature = "dual-task")]
    let dispatcher = {
        static WORKER: StaticCell<Worker> = StaticCell::new();
        _spawner.spawn(trusted_task(WORKER.init(Worker::new(dispatcher))).unwrap());
        MailboxTrustedBackend::new(LocalMailboxTransport::new(&MAILBOX))
    };
    static ARBITER: StaticCell<SharedUsbArbiter<Backend>> = StaticCell::new();
    let arbiter: &'static SharedUsbArbiter<Backend> =
        ARBITER.init(embassy_sync::blocking_mutex::Mutex::new(
            core::cell::RefCell::new(IngressArbiter::new(dispatcher)),
        ));
    let mut app = UsbIngressFrontend::new(arbiter);
    #[cfg(feature = "internal-uart")]
    let uart = {
        static TX: StaticCell<[u8; 1024]> = StaticCell::new();
        static RX: StaticCell<[u8; 1024]> = StaticCell::new();
        let mut config = embassy_stm32::usart::Config::default();
        config.baudrate = 115200;
        embassy_stm32::usart::BufferedUart::new(
            p.USART1,
            p.PA9,
            p.PA10,
            Irqs,
            TX.init([0; 1024]),
            RX.init([0; 1024]),
            config,
        )
        .unwrap()
    };

    let mut ep_out_buffer = [0; 256];
    let mut usb_config = usb::Config::default();
    usb_config.vbus_detection = false;
    let driver = usb::Driver::new_fs(
        p.USB_OTG_FS,
        p.PA12,
        p.PA11,
        Irqs,
        &mut ep_out_buffer,
        usb_config,
    );
    let identity = CtaphidUsbDeviceInfo::new("ManeKey STM32U575 USB FIDO", "stm32u575-p0");
    let mut config = embassy_usb::Config::new(identity.vendor_id, identity.product_id);
    config.manufacturer = Some(identity.manufacturer);
    config.product = Some(identity.product);
    config.serial_number = identity.serial_number;
    config.max_packet_size_0 = 64;
    config.composite_with_iads = false;
    let mut config_descriptor = [0; 256];
    let mut bos_descriptor = [0; 256];
    let mut control_buf = [0; 64];
    let mut state = State::new();
    #[cfg(feature = "usb-ccid")]
    let mut ccid_state = CcidUsbState::new();
    let mut builder = embassy_usb::Builder::new(
        driver,
        config,
        &mut config_descriptor,
        &mut bos_descriptor,
        &mut [],
        &mut control_buf,
    );
    let hid = HidReaderWriter::<_, REPORT_SIZE, REPORT_SIZE>::new(
        &mut builder,
        &mut state,
        embassy_usb::class::hid::Config {
            hid_subclass: HidSubclass::No,
            hid_boot_protocol: HidBootProtocol::None,
            poll_ms: identity.poll_ms,
            max_packet_size: 64,
            request_handler: None,
            report_descriptor: REPORT_DESCRIPTOR,
        },
    );
    #[cfg(feature = "usb-ccid")]
    let ccid = CcidUsbClass::new(
        &mut builder,
        &mut ccid_state,
        64,
        manekey::frontend::ccid::CCID_RESPONSE_MAX as u32,
    );
    let mut device = builder.build();

    let usb_run = async {
        #[cfg(feature = "usb-ccid")]
        {
            static BUFFERS: StaticCell<CcidIoBuffers> = StaticCell::new();
            join(
                device.run(),
                join(
                    run_hid_ingress_loop(hid, &mut app),
                    run_ccid_ingress_loop(ccid, arbiter, BUFFERS.init(CcidIoBuffers::new())),
                ),
            )
            .await;
        }
        #[cfg(not(feature = "usb-ccid"))]
        join(device.run(), run_hid_ingress_loop(hid, &mut app)).await;
    };
    #[cfg(feature = "internal-uart")]
    join(
        usb_run,
        manekey_stm32u575::internal_uart::run(uart, arbiter),
    )
    .await;
    #[cfg(not(feature = "internal-uart"))]
    usb_run.await;
}

#[panic_handler]
fn panic(_: &core::panic::PanicInfo<'_>) -> ! {
    loop {
        cortex_m::asm::nop();
    }
}
