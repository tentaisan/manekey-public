#![no_std]
#![no_main]

use core::fmt::Write;
use embassy_futures::join::join;
#[cfg(feature = "usb-ccid")]
use embassy_futures::join::join3;
use embassy_usb::{
    Builder, Config,
    class::hid::{Config as HidConfig, HidBootProtocol, HidReaderWriter, HidSubclass, State},
};
use manekey::ctaphid::{
    descriptor::REPORT_DESCRIPTOR,
    entropy::HmacDrbgEntropy,
    pin_uv_auth::{JournaledPinUvAuthStorage, PinUvAuthTokenClock, StoredPinUvAuthProvider},
    storage::Storage,
    trusted::TrustedDispatcher,
    user_verification::UnavailableUserVerification,
};
#[cfg(not(feature = "physical-up"))]
use manekey::presence::AlwaysPresent;
#[cfg(feature = "usb-ccid")]
use manekey::transport::usb::embassy::{
    CcidIoBuffers, CcidUsbClass, CcidUsbState, run_ccid_ingress_loop,
};
use manekey::{
    frontend::ingress::IngressArbiter,
    transport::usb::embassy::{SharedUsbArbiter, UsbIngressFrontend, run_hid_ingress_loop},
};
use manekey::{
    presence::NoPresenceObserver,
    user_interface::{AtomicUiStatus, UiPresenceObserver},
};
use static_cell::StaticCell;
#[path = "../../boot.rs"]
mod boot;
#[path = "../../data_flash.rs"]
mod data_flash;
#[path = "../../entropy.rs"]
mod entropy;



#[cfg(feature = "internal-uart")]
#[path = "../../internal_uart.rs"]
mod internal_uart;
#[path = "../../key_store.rs"]
mod key_store;
#[path = "../../pin_crypto.rs"]
mod pin_crypto;
#[cfg(feature = "sce5-aes")]
#[path = "../../sce_aes.rs"]
mod sce_aes;
#[cfg(feature = "hardware-wrapped-keys")]
#[path = "../../sce_wrapped.rs"]
mod sce_wrapped;
#[path = "../../sci2.rs"]
mod sci2;
#[path = "../../storage.rs"]
mod storage;
#[cfg(feature = "physical-up")]
#[path = "../../ui.rs"]
mod ui;
#[cfg(feature = "hardware-wrapped-keys")]
#[path = "../../wrapped_keys.rs"]
mod wrapped_keys;
use sci2::Sci2;

#[cfg(feature = "physical-up")]
type Presence = ui::PhysicalPresence;
#[cfg(not(feature = "physical-up"))]
type Presence = AlwaysPresent;
#[cfg(not(feature = "mldsa-native-experimental"))]
type KeyStore = key_store::Keys;
#[cfg(feature = "mldsa-native-experimental")]
type KeyStore = manekey::ctaphid::key_store::AdditionalSignaturePrivateKeyStore<
    key_store::Keys,
    manekey::ctaphid::pqc_signature_mldsa_native::MldsaNativeMlDsa44,
>;
#[cfg(not(feature = "physical-up"))]
static STATUS: AtomicUiStatus = AtomicUiStatus::new();

struct Clock;
impl PinUvAuthTokenClock for Clock {
    fn now_ms(&self) -> u64 {
        embassy_time::Instant::now().as_millis()
    }
}
type Pin = StoredPinUvAuthProvider<
    JournaledPinUvAuthStorage<storage::Journal>,
    pin_crypto::ClientPin,
    Clock,
>;
type Dispatcher = TrustedDispatcher<
    storage::Journal,
    Presence,
    UnavailableUserVerification,
    Pin,
    KeyStore,
    HmacDrbgEntropy<entropy::SceEntropy>,
    UiPresenceObserver<NoPresenceObserver, &'static AtomicUiStatus>,
>;
static FLASH: StaticCell<storage::SharedFlash> = StaticCell::new();
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
static ARBITER: StaticCell<SharedUsbArbiter<Backend>> = StaticCell::new();
ra_hal::bind_interrupts!(struct Irqs {
    IEL2 => ra_hal::usb::UsbInterruptHandler<ra_hal::peripherals::USBFS>;
});

#[embassy_executor::main]
async fn main(_spawner: embassy_executor::Spawner) {
    boot::prepare_app_interrupts();
    let p = ra_hal::init(Default::default());
    let mut uart = Sci2::new(p.SCI2, p.P302, p.P301);
    #[cfg(not(feature = "physical-up"))]
    uart.write(b"RA4M1 FIDO boot Always-UP\r\n");
    #[cfg(feature = "physical-up")]
    uart.write(b"RA4M1 FIDO boot physical-UP\r\n");
    #[cfg(not(feature = "physical-up"))]
    let (presence, status) = (AlwaysPresent, &STATUS);
    #[cfg(feature = "physical-up")]
    let (presence, status) = {
        use ra_hal::gpio::Input;
        #[cfg(not(feature = "board-nano-r4"))]
        let button = Input::new_with_pull_up(p.P201, true);
        #[cfg(feature = "board-nano-r4")]
        let button = Input::new_with_pull_up(p.P105, true);
        #[cfg(not(feature = "board-nano-r4"))]
        let led = boot::board::led(p.P011);
        #[cfg(feature = "board-nano-r4")]
        let led = boot::board::led(p.P204);
        _spawner.spawn(ui::led_task(led).unwrap());
        (ui::physical_presence(button), &ui::STATUS)
    };
    entropy::start_watchdog();
    unsafe { cortex_m::interrupt::enable() };
    let mut rng = HmacDrbgEntropy::new(entropy::SceEntropy::new().unwrap()).unwrap();
    uart.write(b"RA4M1 entropy ready\r\n");
    // One Flash owner; borrowed only by the single foreground dispatcher.
    let flash = FLASH.init(core::cell::RefCell::new(unsafe {
        data_flash::DataFlash::new()
    }));
    let mut records = Storage::new(storage::Journal::credentials(flash));
    let key_store = key_store::open(flash, &mut rng, &mut records).expect("RA managed keys");
    #[cfg(feature = "mldsa-native-experimental")]
    let key_store = manekey::ctaphid::key_store::AdditionalSignaturePrivateKeyStore::new(
        key_store,
        manekey::ctaphid::pqc_signature_mldsa_native::MldsaNativeMlDsa44,
    );
    let arbiter: &'static SharedUsbArbiter<Backend> = ARBITER.init_with(|| {
        let dispatcher = TrustedDispatcher::new_with_transports_and_presence_observer(
            records,
            presence,
            UnavailableUserVerification,
            Pin::new_with_crypto_and_clock(
                JournaledPinUvAuthStorage::new(storage::Journal::pin(flash)),
                pin_crypto::client_pin(),
                Clock,
            ),
            key_store,
            rng,
            manekey::transport::USB_TRANSPORTS,
            UiPresenceObserver::new(NoPresenceObserver, status),
        );
        #[cfg(feature = "dual-task")]
        let dispatcher = {
            static WORKER: StaticCell<Worker> = StaticCell::new();
            _spawner.spawn(trusted_task(WORKER.init_with(|| Worker::new(dispatcher))).unwrap());
            MailboxTrustedBackend::new(LocalMailboxTransport::new(&MAILBOX))
        };
        embassy_sync::blocking_mutex::Mutex::new(core::cell::RefCell::new(IngressArbiter::new(
            dispatcher,
        )))
    });
    uart.write(b"RA4M1 storage ready\r\n");
    // Inherited USB status must not dispatch before the new driver is initialized.
    cortex_m::interrupt::disable();
    let driver = ra_hal::usb::Usbfs::new(p.USBFS, p.P914, p.P915, p.P407, Irqs);
    uart.write(b"RA4M1 USB driver ready\r\n");
    let mut config = Config::new(0xcafe, 0x4011);
    config.manufacturer = Some("ManeKey");
    #[cfg(not(feature = "physical-up"))]
    {
        config.product = Some("ManeKey RA4M1 Always-UP test");
    }
    #[cfg(feature = "physical-up")]
    {
        config.product = Some("ManeKey RA4M1 FIDO");
    }
    config.serial_number = Some("ra4m1-fido");
    config.max_power = 100;
    let mut cd = [0; 256];
    let mut bos = [0; 256];
    let mut control = [0; 128];
    let mut state = State::new();
    #[cfg(feature = "usb-ccid")]
    let mut ccid_state = CcidUsbState::new();
    let mut builder = Builder::new(driver, config, &mut cd, &mut bos, &mut [], &mut control);
    let hid = HidReaderWriter::<_, 64, 64>::new(
        &mut builder,
        &mut state,
        HidConfig {
            hid_subclass: HidSubclass::No,
            hid_boot_protocol: HidBootProtocol::None,
            report_descriptor: REPORT_DESCRIPTOR,
            request_handler: None,
            poll_ms: 5,
            max_packet_size: 64,
        },
    );
    #[cfg(feature = "usb-ccid")]
    let ccid = CcidUsbClass::new(
        &mut builder,
        &mut ccid_state,
        64,
        manekey::frontend::ccid::CCID_RESPONSE_MAX as u32,
    );
    let mut usb = builder.build();
    #[cfg(all(
        feature = "usb-bulk-single-buffer",
        not(any()                                   )
    ))]
    {
        // HAL 0.3.1 multi-packet CCID requires single-buffered bulk pipes.
        let r = ra_hal::pac::USBFS;
        for pipe in 1..=9 {
            r.pipesel()
                .modify(|v| v.set_pipesel(ra_hal::pac::usbfs::vals::Pipesel::from_bits(pipe)));
            if r.pipecfg().read().type_() == ra_hal::pac::usbfs::vals::Type::_01 {
                r.pipecfg().modify(|v| v.set_dblb(false));
            }
        }
        r.pipesel()
            .modify(|v| v.set_pipesel(ra_hal::pac::usbfs::vals::Pipesel::from_bits(0)));
    }
    uart.write(b"RA4M1 USB builder ready\r\n");


    unsafe { cortex_m::interrupt::enable() };
    let mut app = UsbIngressFrontend::new(arbiter);
    let usb_run = async {
        #[cfg(feature = "usb-ccid")]
        {
            static BUFFERS: StaticCell<CcidIoBuffers> = StaticCell::new();
            join3(
                usb.run(),
                run_hid_ingress_loop(hid, &mut app),
                run_ccid_ingress_loop(ccid, arbiter, BUFFERS.init_with(CcidIoBuffers::new)),
            )
            .await;
        }
        #[cfg(not(feature = "usb-ccid"))]
        join(usb.run(), run_hid_ingress_loop(hid, &mut app)).await;
    };
    #[cfg(not(feature = "internal-uart"))]
    let commands = async {
        loop {







            embassy_time::Timer::after_millis(1).await;
        }
    };
    #[cfg(feature = "internal-uart")]
    let commands = internal_uart::run(uart, arbiter);
    join(usb_run, commands).await;
}

#[panic_handler]
fn panic(info: &core::panic::PanicInfo<'_>) -> ! {
    cortex_m::interrupt::disable();













    {
        let _ = info;
        loop {
            cortex_m::asm::wfi();
        }
    }
}
