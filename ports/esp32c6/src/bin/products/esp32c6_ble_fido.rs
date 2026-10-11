#![no_std]
#![no_main]

#[cfg(feature = "client-pin-flash")]
compile_error!("client-pin-flash requires esp32c6_ble_secure_fido's shared flash dispatcher");

use embassy_executor::Spawner;
use esp_alloc as _;
use esp_backtrace as _;
use esp_hal::{
    clock::CpuClock,
    gpio::{Level, Output},
    rng::TrngSource,
};
use esp_println::println;
use esp32c6::ble_fido::{BLE_PACKET_LEN, build_ble_controller, run_ble_peripheral, start_ble_rtos};

use esp32c6::fido::build_ble_fido_frontend_from_parts;

esp_bootloader_esp_idf::esp_app_desc!();

#[esp_rtos::main]
async fn main(_spawner: Spawner) {
    esp_println::logger::init_logger(log::LevelFilter::Info);
    println!("MANEKEY ESP32-C6 BLE FIDO boot");
    let peripherals = esp_hal::init(esp_hal::Config::default().with_cpu_clock(CpuClock::max()));
    esp_alloc::heap_allocator!(size: 96 * 1024);

    #[allow(unused_mut)]
    let mut led = Output::new(peripherals.GPIO21, Level::Low, Default::default());

    start_ble_rtos(peripherals.TIMG0, peripherals.SW_INTERRUPT);

    let _trng_source = TrngSource::new(peripherals.RNG, peripherals.ADC1);
    let ble_fido = build_ble_fido_frontend_from_parts(
        peripherals.FLASH,
        peripherals.GPIO2,
        peripherals.SHA,
        peripherals.AES,
        peripherals.ECC,
        BLE_PACKET_LEN,
    );

    let controller = build_ble_controller(peripherals.BT);

    run_ble_peripheral(controller, led, ble_fido).await;
}
