#![no_std]
#![no_main]

use ch32_hal::{self as hal, bind_interrupts, peripherals, rcc, usart};
use core::cell::UnsafeCell;
use core::{cell::RefCell, fmt::Write};
use embassy_futures::join::join;
use embassy_time::Instant;

#[cfg(not(feature = "uart-only"))]
use embassy_usb::class::hid::{HidBootProtocol, HidReaderWriter, HidSubclass, State};
#[cfg(feature = "usb-ccid")]
use manekey::transport::usb::embassy::{
    CcidIoBuffers, CcidUsbClass, CcidUsbState, run_ccid_ingress_loop,
};
#[cfg(feature = "dual-task")]
use manekey::{
    boundary::{
        mailbox::{LocalMailboxTransport, MailboxEndpoint},
        mailbox_backend::MailboxTrustedBackend,
    },
    ctaphid::trusted::TRUSTED_REQUEST_MAX,
};
#[cfg(not(feature = "uart-only"))]
use manekey::{
    ctaphid::descriptor::{REPORT_DESCRIPTOR, REPORT_SIZE},
    transport::usb::embassy::{UsbIngressFrontend, run_hid_ingress_loop},
};
use manekey::{
    ctaphid::trusted::TRUSTED_RESPONSE_MAX,
    frontend::{
        ingress::IngressArbiter,
        internal::{InterconnectCtap2Frontend, InterconnectCtap2Outcome},
    },
    transport::usb::embassy::SharedUsbArbiter,
};
#[cfg(not(all(feature = "dual-task", feature = "flash-managed-keys")))]
use manekey_ch32v203::fido::selected_dispatcher;
#[cfg(not(feature = "uart-only"))]
use manekey_ch32v203::usb_hid::ctaphid_usb_config;
use portable_atomic::{AtomicBool, AtomicUsize, Ordering};

#[cfg(not(feature = "dual-task"))]
type Backend = manekey_ch32v203::fido::SelectedDispatcher;
#[cfg(feature = "dual-task")]
type Backend = MailboxTrustedBackend<
    LocalMailboxTransport<'static, TRUSTED_REQUEST_MAX, TRUSTED_RESPONSE_MAX>,
>;
#[cfg(feature = "dual-task")]
static ENDPOINT: MailboxEndpoint<TRUSTED_REQUEST_MAX, TRUSTED_RESPONSE_MAX> =
    MailboxEndpoint::new();
#[cfg(all(feature = "dual-task", not(feature = "flash-managed-keys")))]
static mut WORKER: manekey_ch32v203::fido::Ch32LocalTrustedWorker =
    manekey_ch32v203::fido::Ch32LocalTrustedWorker::new(selected_dispatcher());
#[cfg(feature = "dual-task")]
static mut ARBITER: SharedUsbArbiter<Backend> =
    SharedUsbArbiter::new(RefCell::new(IngressArbiter::new(
        MailboxTrustedBackend::new(LocalMailboxTransport::new(&ENDPOINT)),
    )));
#[cfg(all(not(feature = "dual-task"), not(feature = "flash-managed-keys")))]
static mut ARBITER: SharedUsbArbiter<Backend> =
    SharedUsbArbiter::new(RefCell::new(IngressArbiter::new(selected_dispatcher())));
#[cfg(all(not(feature = "dual-task"), feature = "flash-managed-keys"))]
static mut ARBITER: core::mem::MaybeUninit<SharedUsbArbiter<Backend>> =
    core::mem::MaybeUninit::uninit();
#[cfg(all(feature = "dual-task", feature = "flash-managed-keys"))]
static mut WORKER: core::mem::MaybeUninit<manekey_ch32v203::fido::Ch32LocalTrustedWorker> =
    core::mem::MaybeUninit::uninit();

#[cfg(feature = "flash-managed-keys")]
#[inline(never)]
fn initialize_managed() {
    #[cfg(feature = "dual-task")]
    unsafe {
        manekey_ch32v203::fido::Ch32LocalTrustedWorker::initialize_at(
            core::ptr::addr_of_mut!(WORKER).cast(),
        );
    }
    #[cfg(not(feature = "dual-task"))]
    unsafe {
        let dispatcher = selected_dispatcher();
        core::ptr::addr_of_mut!(ARBITER).write(core::mem::MaybeUninit::new(SharedUsbArbiter::new(
            RefCell::new(IngressArbiter::new(dispatcher)),
        )));
    }
}
#[cfg(feature = "usb-ccid")]
static mut CCID_BUFFERS: CcidIoBuffers = CcidIoBuffers::new();

bind_interrupts!(struct Irqs {
    USB_LP_CAN1_RX0 => hal::usbd::InterruptHandler<peripherals::USBD>;
});

/// One USART1 IRQ producer and one executor consumer exclusively own the slots; indices publish ownership.
struct RxRing {
    bytes: UnsafeCell<[u8; 512]>,
    head: AtomicUsize,
    tail: AtomicUsize,
    lost: AtomicBool,
}

unsafe impl Sync for RxRing {}
static RX: RxRing = RxRing {
    bytes: UnsafeCell::new([0; 512]),
    head: AtomicUsize::new(0),
    tail: AtomicUsize::new(0),
    lost: AtomicBool::new(false),
};
impl RxRing {
    fn pop(&self) -> Option<u8> {
        let tail = self.tail.load(Ordering::Relaxed);
        if tail == self.head.load(Ordering::Acquire) {
            return None;
        }

        let byte = unsafe { (*self.bytes.get())[tail] };
        self.tail.store((tail + 1) % 512, Ordering::Release);
        Some(byte)
    }
}

#[qingke_rt::interrupt]
fn USART1() {
    let status = hal::pac::USART1.statr().read();
    if status.rxne() || status.ore() {
        let byte = hal::pac::USART1.datar().read().dr() as u8;
        let head = RX.head.load(Ordering::Relaxed);
        let next = (head + 1) % 512;
        if status.ore() || next == RX.tail.load(Ordering::Acquire) {
            RX.lost.store(true, Ordering::Release);
        } else {
            unsafe {
                (*RX.bytes.get())[head] = byte;
            }
            RX.head.store(next, Ordering::Release);
        }
    }
}

struct Log;
impl Write for Log {
    fn write_str(&mut self, text: &str) -> core::fmt::Result {
        for byte in text.bytes() {
            let mut ready = false;
            for _ in 0..1_000_000 {
                if hal::pac::USART1.statr().read().txe() {
                    ready = true;
                    break;
                }
            }
            if !ready {
                return Err(core::fmt::Error);
            }
            hal::pac::USART1
                .datar()
                .write(|r| r.set_dr(u16::from(byte)));
        }
        Ok(())
    }
}

#[cfg(feature = "dual-task")]
#[embassy_executor::task]
async fn trusted_worker_task() {
    loop {
        unsafe {
            &mut *core::ptr::addr_of_mut!(WORKER)
                .cast::<manekey_ch32v203::fido::Ch32LocalTrustedWorker>()
        }
        .pump(&ENDPOINT);
        embassy_futures::yield_now().await;
    }
}

#[embassy_executor::main(entry = "qingke_rt::entry")]
/// Cooperative UART/HID/CCID product, not hardware isolation; entropy remains experimental.
/// Initialize static state once before frontend/worker use; exclude IRQ/DMA access to the Noop arbiter.
async fn main(_spawner: embassy_executor::Spawner) {
    let mut rcc = rcc::Config::SYSCLK_FREQ_96MHZ_HSI;

    {
        rcc.ahb_pre = rcc::AHBPrescaler::DIV2;
    }

    let p = hal::init(hal::Config {
        rcc,
        ..Default::default()
    });
    let uart =
        usart::Uart::new_blocking(p.USART1, p.PA10, p.PA9, usart::Config::default()).unwrap();

    let _ = writeln!(
        Log,
        "CH32 multi boot dual={} ccid={}",
        cfg!(feature = "dual-task"),
        cfg!(feature = "usb-ccid")
    );

    let _adc_owner = manekey_ch32v203::entropy::initialize(p.ADC1).unwrap();
    let _ = writeln!(Log, "CH32 entropy ready (experimental)");
    #[cfg(feature = "flash-managed-keys")]
    {
        initialize_managed();
        let _ = writeln!(Log, "CH32 managed journal ready");
    }

    #[cfg(feature = "up-gpio-pa0")]
    let _up = hal::gpio::Input::new(p.PA0, hal::gpio::Pull::Up);
    #[cfg(feature = "dual-task")]
    _spawner.spawn(trusted_worker_task().unwrap());
    _spawner.spawn(frontend_task(uart, p.USBD, p.PA12, p.PA11).unwrap());

    core::future::pending::<()>().await;
}

#[embassy_executor::task]
async fn frontend_task(
    uart: usart::Uart<'static, peripherals::USART1, hal::mode::Blocking>,
    usbd: hal::Peri<'static, peripherals::USBD>,
    dp: hal::Peri<'static, peripherals::PA12>,
    dm: hal::Peri<'static, peripherals::PA11>,
) {
    let arbiter = unsafe { &*core::ptr::addr_of!(ARBITER).cast::<SharedUsbArbiter<Backend>>() };
    #[cfg(not(feature = "uart-only"))]
    let usb = async {
        let driver = hal::usbd::Driver::new(usbd, Irqs, dp, dm);
        let mut descriptors = [0; 256];
        let mut bos = [0; 64];
        let mut control = [0; 128];
        let mut hid_state = State::new();
        #[cfg(feature = "usb-ccid")]
        let mut ccid_state = CcidUsbState::new();
        let mut builder = embassy_usb::Builder::new(
            driver,
            ctaphid_usb_config("ManeKey CH32V203 multi FIDO", "ch32v203-multi"),
            &mut descriptors,
            &mut bos,
            &mut [],
            &mut control,
        );
        let hid = HidReaderWriter::<_, REPORT_SIZE, REPORT_SIZE>::new(
            &mut builder,
            &mut hid_state,
            embassy_usb::class::hid::Config {
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
        let mut device = builder.build();
        let mut app = UsbIngressFrontend::new(arbiter);
        let _ = writeln!(Log, "CH32 USB ready");
        #[cfg(not(feature = "usb-ccid"))]
        join(device.run(), run_hid_ingress_loop(hid, &mut app)).await;
        #[cfg(feature = "usb-ccid")]
        join(
            device.run(),
            join(
                run_hid_ingress_loop(hid, &mut app),
                run_ccid_ingress_loop(ccid, arbiter, unsafe {
                    &mut *core::ptr::addr_of_mut!(CCID_BUFFERS)
                }),
            ),
        )
        .await;
    };
    #[cfg(feature = "uart-only")]
    let usb = core::future::pending::<()>();
    #[cfg(not(feature = "dual-task"))]
    let worker = async {
        loop {
            embassy_futures::yield_now().await;
        }
    };
    #[cfg(not(feature = "dual-task"))]
    join(usb, join(run_uart(uart, arbiter), worker)).await;
    #[cfg(feature = "dual-task")]
    join(usb, run_uart(uart, arbiter)).await;
}

async fn run_uart(
    uart: usart::Uart<'static, peripherals::USART1, hal::mode::Blocking>,
    arbiter: &'static SharedUsbArbiter<Backend>,
) -> ! {
    let (mut tx, _rx_owner) = uart.split();
    hal::pac::USART1.ctlr1().modify(|w| w.set_rxneie(true));
    let mut frontend = InterconnectCtap2Frontend::<{ TRUSTED_RESPONSE_MAX + 32 }>::new(0);
    let mut response = [0; TRUSTED_RESPONSE_MAX + 32];
    let mut last_rx = Instant::now();
    loop {
        if RX.lost.swap(false, Ordering::AcqRel) {
            frontend.discard_partial_frame();
            while RX.pop().is_some() {}
        }
        arbiter.lock(|a| frontend.poll_cancel(&mut a.borrow_mut()));
        if frontend.is_receiving() && last_rx.elapsed().as_millis() > 250 {
            arbiter.lock(|a| frontend.disconnect(&mut a.borrow_mut()));
        }
        while let Some(byte) = RX.pop() {
            last_rx = Instant::now();

            let outcome =
                arbiter.lock(|a| frontend.push_byte(&mut a.borrow_mut(), byte, &mut response));

            match outcome {
                Ok(Some(InterconnectCtap2Outcome::Response { len })) => {
                    let _ = tx.blocking_write(&response[..len]);
                }
                Err(_) => arbiter.lock(|a| frontend.disconnect(&mut a.borrow_mut())),
                _ => {}
            }
        }

        embassy_futures::yield_now().await;
    }
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo<'_>) -> ! {
    loop {
        core::hint::spin_loop();
    }
}
