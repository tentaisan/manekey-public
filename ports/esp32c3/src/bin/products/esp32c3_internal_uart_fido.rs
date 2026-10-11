#![no_std]
#![no_main]

#[cfg(feature = "log-uart")]
compile_error!("internal UART uses D6/D7; build this product with log-jtag-serial, not log-uart");

use esp_backtrace as _;
use esp_hal::{
    clock::CpuClock,
    main,
    rng::TrngSource,
    uart::{Config as UartConfig, Uart},
};
use esp_println::println;
use esp32c3::{
    fido::{EspSharedTrustedDispatcher, build_internal_dispatcher_from_shared_flash_boot},
    storage::{SharedEspFlash, new_shared_esp_flash},
};
use manekey::{
    frontend::{
        ingress::IngressArbiter,
        internal::{InterconnectCtap2Frontend, InterconnectCtap2Outcome},
    },
    transport::interconnect::{HEADER_LEN, TRAILER_LEN},
};
use static_cell::StaticCell;

const UART_INSTANCE: u8 = 0;
const UART_REQUEST_FRAME_MAX: usize = 1024 + HEADER_LEN + TRAILER_LEN;

const UART_RESPONSE_FRAME_MAX: usize = 4096 + HEADER_LEN + TRAILER_LEN;

type InternalFrontend = InterconnectCtap2Frontend<UART_REQUEST_FRAME_MAX>;

static FLASH: StaticCell<SharedEspFlash<'static>> = StaticCell::new();
static ARBITER: StaticCell<IngressArbiter<EspSharedTrustedDispatcher>> = StaticCell::new();
static FRONTEND: StaticCell<InternalFrontend> = StaticCell::new();
static RESPONSE: StaticCell<[u8; UART_RESPONSE_FRAME_MAX]> = StaticCell::new();

esp_bootloader_esp_idf::esp_app_desc!();

#[main]
/// Direct UART product, not PMP isolation; caller preserves reset-time GPIO9 strapping.
/// Partial writes are not peer delivery acknowledgment.
fn main() -> ! {
    let peripherals = esp_hal::init(esp_hal::Config::default().with_cpu_clock(CpuClock::max()));
    println!("MANEKEY ESP32-C3 InternalTransport UART product");
    println!("UART0: D6/GPIO21 TX, D7/GPIO20 RX, 115200 8N1, MK CTAP2");

    let _trng_source = TrngSource::new(peripherals.RNG, peripherals.ADC1);
    let flash = FLASH.init(new_shared_esp_flash(peripherals.FLASH));
    let dispatcher = build_internal_dispatcher_from_shared_flash_boot(
        flash,
        peripherals.GPIO9,
        peripherals.SHA,
        peripherals.AES,
    );
    let arbiter = ARBITER.init(IngressArbiter::new(dispatcher));
    let frontend = FRONTEND.init(InternalFrontend::new(UART_INSTANCE));
    let response = RESPONSE.init([0; UART_RESPONSE_FRAME_MAX]);
    let mut uart = Uart::new(
        peripherals.UART0,
        UartConfig::default().with_baudrate(115_200),
    )
    .expect("UART0 configuration")
    .with_tx(peripherals.GPIO21)
    .with_rx(peripherals.GPIO20);

    let mut input = [0_u8; 1];
    loop {
        frontend.poll_cancel(arbiter);
        if uart.read(&mut input).is_err() {
            continue;
        }
        match frontend.push_byte(arbiter, input[0], response) {
            Ok(Some(InterconnectCtap2Outcome::Response { len })) => {
                let mut sent = 0;
                while sent < len {
                    match uart.write(&response[sent..len]) {
                        Ok(0) | Err(_) => break,
                        Ok(written) => sent += written,
                    }
                }
                if sent == len {
                    let _ = uart.flush();
                }
            }
            Ok(Some(InterconnectCtap2Outcome::UserPresencePending)) => {
                println!("internal UART: user presence pending; await MK Poll")
            }
            Ok(Some(InterconnectCtap2Outcome::Busy)) => println!("internal UART: ingress busy"),
            Ok(Some(InterconnectCtap2Outcome::InvalidRequest)) => {
                println!("internal UART: invalid trusted request")
            }
            Ok(Some(InterconnectCtap2Outcome::CancelAccepted)) => {
                println!("internal UART: cancel accepted")
            }
            Ok(Some(InterconnectCtap2Outcome::LinkClosed)) => {
                println!("internal UART: peer link reset")
            }
            Ok(Some(InterconnectCtap2Outcome::NoResponse)) | Ok(None) => {}
            Err(error) => println!("internal UART: malformed MK frame: {error:?}"),
        }
    }
}
