#![no_std]
#![no_main]

use core::sync::atomic::{AtomicU32, Ordering};
use embassy_executor::Spawner;
use embassy_futures::join::join;
use embassy_stm32::{bind_interrupts, gpio, peripherals, usart, usb};
use embassy_usb::class::hid::{HidBootProtocol, HidReaderWriter, HidSubclass, State};
use manekey::{
    ctaphid::{
        crypto::SoftwareClientPinCrypto,
        descriptor::{CtaphidUsbDeviceInfo, REPORT_DESCRIPTOR, REPORT_SIZE},
        entropy::HmacDrbgEntropy,
        pin_uv_auth::{JournaledPinUvAuthStorage, PinUvAuthTokenClock, StoredPinUvAuthProvider},
        storage::Storage,
        trusted::TrustedDispatcher,
        user_verification::UnavailableUserVerification,
    },
    frontend::ingress::IngressArbiter,
    presence::NoPresenceObserver,
    transport::usb::embassy::{SharedUsbArbiter, UsbIngressFrontend, run_hid_ingress_loop},
    user_interface::{AtomicUiStatus, UiPresenceObserver},
};
use manekey_stm32f411::{
    entropy::ExperimentalEntropy,
    storage::{Journal, SharedFlash},
};
use static_cell::StaticCell;

#[cfg(not(feature = "physical-up"))]
use manekey::presence::AlwaysPresent;
#[cfg(feature = "usb-ccid")]
use manekey::transport::usb::embassy::{
    CcidIoBuffers, CcidUsbClass, CcidUsbState, run_ccid_ingress_loop,
};
#[cfg(feature = "physical-up")]
type Presence = manekey_stm32f411::ui::PhysicalPresence;
#[cfg(not(feature = "physical-up"))]
type Presence = AlwaysPresent;

struct TokenClock;
impl PinUvAuthTokenClock for TokenClock {
    fn now_ms(&self) -> u64 {
        embassy_time::Instant::now().as_millis()
    }
}
type Dispatcher = TrustedDispatcher<
    Journal,
    Presence,
    UnavailableUserVerification,
    StoredPinUvAuthProvider<
        JournaledPinUvAuthStorage<Journal>,
        SoftwareClientPinCrypto,
        TokenClock,
    >,
    manekey_stm32f411::key_store::KeyStore,
    HmacDrbgEntropy<ExperimentalEntropy>,
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
static MAILBOX: MailboxEndpoint<TRUSTED_REQUEST_MAX, TRUSTED_RESPONSE_MAX> = MailboxEndpoint::new();
#[cfg(feature = "dual-task")]
#[embassy_executor::task]
async fn trusted_task(
    worker: &'static mut LocalMailboxWorker<Dispatcher, TRUSTED_REQUEST_MAX, TRUSTED_RESPONSE_MAX>,
) {
    loop {
        let _ = worker.pump_once(&MAILBOX);
        embassy_time::Timer::after_millis(2).await;
    }
}

bind_interrupts!(struct Irqs {
    OTG_FS => usb::InterruptHandler<peripherals::USB_OTG_FS>;
    USART2 => usart::BufferedInterruptHandler<peripherals::USART2>;
});
#[unsafe(no_mangle)]
pub static PRODUCT_STAGE: AtomicU32 = AtomicU32::new(0);

#[embassy_executor::main]
/// Cooperative USB/UART product, not MPU isolation; experimental ADC/LSI entropy remains unqualified.
/// Caller supplies authorized USB identity and exclusive peripheral/IRQ/Flash ownership.
async fn main(spawner: Spawner) {
    PRODUCT_STAGE.store(1, Ordering::Relaxed);
    let p = embassy_stm32::init(manekey_stm32f411::board::config());
    spawner.spawn(
        manekey_stm32f411::ui::led_task(gpio::Output::new(
            p.PA5,
            gpio::Level::Low,
            gpio::Speed::Low,
        ))
        .unwrap(),
    );
    #[cfg(feature = "physical-up")]
    let presence =
        manekey_stm32f411::ui::physical_presence(gpio::Input::new(p.PC13, gpio::Pull::Up));
    #[cfg(not(feature = "physical-up"))]
    let presence = AlwaysPresent;
    let mut source = ExperimentalEntropy::new(p.ADC1, p.TIM5);
    static FLASH: StaticCell<SharedFlash> = StaticCell::new();
    let flash = FLASH.init(critical_section::Mutex::new(core::cell::RefCell::new(
        embassy_stm32::flash::Flash::new_blocking(p.FLASH),
    )));
    manekey_stm32f411::storage::initialize_records(flash).expect("paired records");
    let mut records = Storage::new(Journal::credentials(flash));
    let keys =
        manekey_stm32f411::key_store::open(flash, &mut source, &mut records).expect("key store");
    PRODUCT_STAGE.store(2, Ordering::Relaxed);
    let dispatcher = TrustedDispatcher::new_with_transports_and_presence_observer(
        records,
        presence,
        UnavailableUserVerification,
        StoredPinUvAuthProvider::new_with_clock(
            JournaledPinUvAuthStorage::new(Journal::pin(flash)),
            TokenClock,
        ),
        keys,
        HmacDrbgEntropy::new(source).expect("experimental DRBG health"),
        manekey::transport::USB_TRANSPORTS,
        UiPresenceObserver::new(NoPresenceObserver, &manekey_stm32f411::ui::STATUS),
    );
    #[cfg(feature = "dual-task")]
    let dispatcher = {
        static WORKER: StaticCell<
            LocalMailboxWorker<Dispatcher, TRUSTED_REQUEST_MAX, TRUSTED_RESPONSE_MAX>,
        > = StaticCell::new();
        spawner.spawn(trusted_task(WORKER.init(LocalMailboxWorker::new(dispatcher))).unwrap());
        MailboxTrustedBackend::new(LocalMailboxTransport::new(&MAILBOX))
    };
    static ARBITER: StaticCell<SharedUsbArbiter<Backend>> = StaticCell::new();
    let arbiter: &'static SharedUsbArbiter<Backend> =
        ARBITER.init(embassy_sync::blocking_mutex::Mutex::new(
            core::cell::RefCell::new(IngressArbiter::new(dispatcher)),
        ));
    let mut app = UsbIngressFrontend::new(arbiter);
    static TX: StaticCell<[u8; 1024]> = StaticCell::new();
    static RX: StaticCell<[u8; 1024]> = StaticCell::new();
    let mut uart = usart::BufferedUart::new(
        p.USART2,
        p.PA2,
        p.PA3,
        Irqs,
        TX.init([0; 1024]),
        RX.init([0; 1024]),
        usart::Config::default(),
    )
    .unwrap();
    let mut out = [0; 256];
    let mut usb_config = usb::Config::default();
    usb_config.vbus_detection = false;
    let driver = usb::Driver::new_fs(p.USB_OTG_FS, p.PA12, p.PA11, Irqs, &mut out, usb_config);
    let identity =
        CtaphidUsbDeviceInfo::new("ManeKey F411 experimental entropy FIDO", "stm32f411-p0");
    let mut config = embassy_usb::Config::new(identity.vendor_id, identity.product_id);
    config.manufacturer = Some(identity.manufacturer);
    config.product = Some(identity.product);
    config.serial_number = identity.serial_number;
    config.max_packet_size_0 = 64;
    config.composite_with_iads = false;
    let mut descriptors = [0; 256];
    let mut bos = [0; 256];

    let mut control = [0; 256];
    let mut state = State::new();
    #[cfg(feature = "usb-ccid")]
    let mut ccid_state = CcidUsbState::new();
    let mut builder = embassy_usb::Builder::new(
        driver,
        config,
        &mut descriptors,
        &mut bos,
        &mut [],
        &mut control,
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
    PRODUCT_STAGE.store(3, Ordering::Relaxed);
    uart.blocking_write(b"MK F411 normal worker ready\r\n")
        .unwrap();
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
    join(
        usb_run,
        manekey_stm32f411::internal_uart::run(uart, arbiter),
    )
    .await;
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo<'_>) -> ! {
    PRODUCT_STAGE.store(0xdead, Ordering::Relaxed);
    loop {
        cortex_m::asm::nop();
    }
}
