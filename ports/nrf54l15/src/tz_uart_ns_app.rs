use embassy_nrf::uarte;
use manekey::{
    boundary::arm_gateway::{ArmGatewaySharedBuffers, ArmSharedGatewayBackend},
    frontend::{
        ctaphid::CtaphidReportFrontend,
        ingress::{IngressId, IngressKind},
    },
    transport::samd11_bridge::{Samd11CtaphidBridge, Samd11CtaphidBridgeInput},
};
use {defmt_rtt as _, panic_probe as _};

const NSC_GATEWAY_ADDRESS: u32 = 0x0003_f000;
const UART_INGRESS: IngressId = IngressId::new(IngressKind::UsbHid, 0);
const FRAME_CAPACITY: usize = 80;

#[unsafe(link_section = ".nrf54l15_shared")]
#[unsafe(no_mangle)]
#[used]
static mut TZ_UART_SHARED: ArmGatewaySharedBuffers = ArmGatewaySharedBuffers::new();

const SHARED_CAPACITY: usize = if cfg!(feature = "trustzone-large-layout") {
    8192
} else {
    4096
};
const _: () = assert!(core::mem::size_of::<ArmGatewaySharedBuffers>() <= SHARED_CAPACITY);

pub trait LinkObserver {
    fn ready() {}
    fn response_sent() {}
}

impl LinkObserver for () {}

/// Start once after Secure attribution; exclusively own delegated UART/DMA and shared gateway buffers.
/// UART completion is not peer delivery; this is a virtual HID link, not a USB device driver.
pub fn run<O: LinkObserver>() -> ! {
    let p = unsafe { embassy_nrf::Peripherals::steal() };
    let mut config = uarte::Config::default();
    config.baudrate = uarte::Baudrate::Baud115200;
    config.parity = uarte::Parity::Excluded;
    let mut uart = uarte::Uarte::new_blocking(p.SERIAL21, p.P2_08, p.P2_07, config);

    let shared = unsafe { &mut *core::ptr::addr_of_mut!(TZ_UART_SHARED) };
    let gateway = unsafe { ArmSharedGatewayBackend::new(NSC_GATEWAY_ADDRESS, shared) };
    let mut arbiter = manekey::frontend::ingress::IngressArbiter::new(gateway);
    let mut reports = CtaphidReportFrontend::new();
    let mut link = Samd11CtaphidBridge::new();
    let mut next_sequence = 0u16;
    let mut received = [0u8; 1];
    let mut output = [0u8; FRAME_CAPACITY];

    O::ready();
    loop {
        if uart.blocking_read(&mut received).is_err() {
            link = Samd11CtaphidBridge::new();
            reports.on_link_lost(&mut arbiter, UART_INGRESS);
            continue;
        }
        match link.push_link_byte(received[0]) {
            Ok(Some(Samd11CtaphidBridgeInput::Report(report))) => {
                reports.handle_report(&mut arbiter, UART_INGRESS, *report);
            }
            Ok(Some(Samd11CtaphidBridgeInput::LinkReset)) => {
                reports.on_link_lost(&mut arbiter, UART_INGRESS);
            }
            Ok(Some(Samd11CtaphidBridgeInput::Poll)) => {
                reports.poll(&mut arbiter, UART_INGRESS);
            }
            Ok(None) | Err(_) => {}
        }

        while let Some(report) = reports.current_report().copied() {
            let result = link
                .encode_report(next_sequence, &report, &mut output)
                .map_err(|_| ())
                .and_then(|len| uart.blocking_write(&output[..len]).map_err(|_| ()));
            if result.is_err() {
                link = Samd11CtaphidBridge::new();
                reports.on_link_lost(&mut arbiter, UART_INGRESS);
                break;
            }
            reports.advance_report();
            next_sequence = next_sequence.wrapping_add(1);
            O::response_sent();
        }
    }
}
