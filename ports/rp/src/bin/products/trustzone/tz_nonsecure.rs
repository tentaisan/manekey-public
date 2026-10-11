#![no_std]
#![no_main]

#[cfg(feature = "embassy-rp-rt")]
compile_error!(
    "tz-nonsecure must not enable embassy-rp/rt; use trustzone-nonsecure-image without chip-rp235xa"
);

use core::future::poll_fn;
use core::sync::atomic::{AtomicU32, Ordering};
use core::task::Poll;

use embassy_executor::Spawner;
use embassy_futures::select::{Either, select};
use embassy_rp::usb::{Driver, InterruptHandler};
use embassy_rp::{bind_interrupts, peripherals};
use embassy_sync::waitqueue::AtomicWaker;
use embassy_usb::class::hid::{HidBootProtocol, HidReaderWriter, HidSubclass, State};
use embassy_usb::{Builder, Config};
use manekey::boundary::arm_gateway::ArmGatewayBackend;
use manekey::ctaphid::descriptor::{
    CtaphidUsbDeviceInfo, REPORT_DESCRIPTOR, REPORT_SIZE, REPORT_SIZE_U8, REPORT_SIZE_U16,
};
use manekey::frontend::ctaphid::CtaphidReportFrontend;
use manekey::frontend::ingress::{IngressArbiter, IngressId, IngressKind};
use manekey::transport::usb::embassy::HidTransport;
use static_cell::StaticCell;

const SECURE_GATEWAY_ADDRESS: u32 = 0x100f_f001;
const CTAPHID_POLL_INTERVAL_US: u32 = 100_000;
const USB_INGRESS: IngressId = IngressId::new(IngressKind::UsbHid, 0);
type TrustZoneHidTransport = HidTransport<'static, Driver<'static, peripherals::USB>>;
static TIMER_TICKS: AtomicU32 = AtomicU32::new(0);
static TIMER_WAKER: AtomicWaker = AtomicWaker::new();

bind_interrupts!(struct NonsecureIrqs {
    USBCTRL_IRQ => InterruptHandler<peripherals::USB>;
});

fn arm_next_poll_tick() {
    let deadline = rp_pac::TIMER0
        .timerawl()
        .read()
        .wrapping_add(CTAPHID_POLL_INTERVAL_US);
    rp_pac::TIMER0.alarm(0).write_value(deadline);
}

fn init_poll_timer() {
    rp_pac::TIMER0.intr().write(|w| w.set_alarm(0, true));
    rp_pac::TIMER0.inte().write(|w| w.set_alarm(0, true));
    arm_next_poll_tick();
    unsafe {
        cortex_m::peripheral::NVIC::unmask(rp_pac::Interrupt::TIMER0_IRQ_0);
    }
}

#[unsafe(no_mangle)]
unsafe extern "C" fn TIMER0_IRQ_0() {
    rp_pac::TIMER0.intr().write(|w| w.set_alarm(0, true));
    arm_next_poll_tick();
    TIMER_TICKS.fetch_add(1, Ordering::Release);
    TIMER_WAKER.wake();
}

async fn next_poll_tick(last_tick: &mut u32) {
    poll_fn(|cx| {
        TIMER_WAKER.register(cx.waker());
        let tick = TIMER_TICKS.load(Ordering::Acquire);
        if tick != *last_tick {
            *last_tick = tick;
            Poll::Ready(())
        } else {
            Poll::Pending
        }
    })
    .await
}

#[embassy_executor::main]
/// Initialize once with Secure-configured USB/TIMER0 and delegated IRQs; use the matching validated gateway image.
async fn main(_spawner: Spawner) {
    init_poll_timer();

    let gateway = unsafe { ArmGatewayBackend::new(SECURE_GATEWAY_ADDRESS) };

    let usb_peripheral = unsafe { peripherals::USB::steal() };
    let driver = Driver::new(usb_peripheral, NonsecureIrqs);
    let identity =
        CtaphidUsbDeviceInfo::new("RP2350 TrustZone HID", "12345678").with_manufacturer("You");
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
    let arbiter = IngressArbiter::new(gateway);

    _spawner.spawn(usb_task(usb).unwrap());
    _spawner.spawn(hid_task(transport, arbiter).unwrap());
}

#[embassy_executor::task]
async fn usb_task(mut usb: embassy_usb::UsbDevice<'static, Driver<'static, peripherals::USB>>) {
    usb.run().await;
}

#[embassy_executor::task]
async fn hid_task(
    mut transport: TrustZoneHidTransport,
    mut arbiter: IngressArbiter<ArmGatewayBackend>,
) {
    let mut frontend = CtaphidReportFrontend::new();
    let mut link_lost = false;
    let mut last_tick = TIMER_TICKS.load(Ordering::Acquire);
    loop {
        if let Some(report) = frontend.current_report().copied() {
            if transport.write(&report).await.is_ok() {
                frontend.advance_report();
            } else {
                frontend.on_link_lost(&mut arbiter, USB_INGRESS);
                link_lost = true;
            }
            continue;
        }
        match select(transport.read(), next_poll_tick(&mut last_tick)).await {
            Either::First(Ok(report)) => {
                link_lost = false;
                frontend.handle_report(&mut arbiter, USB_INGRESS, report);
            }
            Either::First(Err(_)) => {
                if link_lost {
                    frontend.poll(&mut arbiter, USB_INGRESS);
                } else {
                    frontend.on_link_lost(&mut arbiter, USB_INGRESS);
                    link_lost = true;
                }
                next_poll_tick(&mut last_tick).await;
            }
            Either::Second(()) => frontend.poll(&mut arbiter, USB_INGRESS),
        }
    }
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo<'_>) -> ! {
    loop {
        cortex_m::asm::wfi();
    }
}
