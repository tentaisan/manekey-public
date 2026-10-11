#![no_std]
#![no_main]

use core::cell::RefCell;
use defmt_rtt as _;
use embassy_executor::Spawner;
use embassy_rp::usb::{Driver, InterruptHandler};
use embassy_rp::{bind_interrupts, peripherals};
use embassy_sync::blocking_mutex::{Mutex, raw::ThreadModeRawMutex};
use manekey::boundary::arm_gateway::ArmGatewayBackend;
use manekey::frontend::ingress::{IngressArbiter, IngressId, IngressKind};
use manekey::security::layout;
use panic_probe as _;
use static_cell::StaticCell;

include!("tz_nonsecure_pre_init.rs");

bind_interrupts!(struct Irqs {
    USBCTRL_IRQ => InterruptHandler<peripherals::USB>;
});

const USB_INGRESS: IngressId = IngressId::new(IngressKind::UsbHid, 0);
const FIDO_PENDING_POLL_MS: u64 = 100;
type SharedArbiter = Mutex<ThreadModeRawMutex, RefCell<IngressArbiter<ArmGatewayBackend>>>;
type InternalUart = manekey_rp::platform::rp2350::nonsecure_uart::NonsecureUart;
fn update_stack_watermark() {}

#[path = "../rp_internal_uart.rs"]
mod uart;
#[path = "../ble/pico_cyw43_multi_transport_usb.rs"]
mod usb;

#[embassy_executor::main]
/// Initialize once after Secure clock/pad/UART/USB/timer delegation and matching gateway handoff.
/// Each frontend owns its peripheral; only the serialized arbiter is shared.
async fn main(spawner: Spawner) {
    unsafe { embassy_rp::time_driver::init() };
    let backend = unsafe { ArmGatewayBackend::new(layout::SECURE_GATEWAY_ADDRESS) };
    static ARBITER: StaticCell<SharedArbiter> = StaticCell::new();
    let arbiter = ARBITER.init(Mutex::new(RefCell::new(IngressArbiter::new(backend))));
    let usb = usb::build_usb(Driver::new(unsafe { peripherals::USB::steal() }, Irqs));
    spawner.spawn(usb::multi_usb_device_task(usb.device).unwrap());
    spawner.spawn(usb::multi_usb_frontend_task(usb.hid, arbiter).unwrap());
    #[cfg(feature = "usb-ccid-experimental")]
    spawner.spawn(usb::multi_ccid_frontend_task(usb.ccid, arbiter).unwrap());
    let uart = unsafe { InternalUart::from_secure_handoff() };
    spawner.spawn(uart::multi_internal_task(uart, arbiter).unwrap());
    defmt::info!("TrustZone NS UART/HID/CCID frontend ready; Secure dispatcher owns crypto");
}
