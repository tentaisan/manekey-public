#![no_std]
#![no_main]

#[cfg(feature = "ble-security")]
compile_error!("ESP32 BLE security is not wired into this product yet");

use embassy_executor::Spawner;
use esp_alloc as _;
use esp_backtrace as _;
use esp_hal::{
    clock::CpuClock,
    gpio::{Level, Output},
    peripherals::{ADC1, FLASH, GPIO0, GPIO2, GPIO25, RNG, SHA},
    rng::TrngSource,
};
use esp_println::println;
use manekey::transport::ble::BleFidoFrontend;
use manekey_esp32::{
    ble_fido::{
        BLE_PACKET_LEN, EspBleController, build_ble_controller, run_ble_peripheral, start_ble_rtos,
    },
    board_ui::{presence_button, presence_led},
    fido::{EspTrustedDispatcher, build_ble_fido_frontend},
};
use static_cell::StaticCell;

esp_bootloader_esp_idf::esp_app_desc!();

static FIDO: StaticCell<BleFidoFrontend<EspTrustedDispatcher>> = StaticCell::new();

#[esp_rtos::main]
async fn main(spawner: Spawner) {
    esp_println::logger::init_logger(log::LevelFilter::Info);
    println!("MANEKEY ESP32 BLE FIDO boot");
    let peripherals = esp_hal::init(esp_hal::Config::default().with_cpu_clock(CpuClock::_160MHz));
    esp_alloc::heap_allocator!(size: 56 * 1024);
    start_ble_rtos(peripherals.TIMG0, peripherals.SW_INTERRUPT);
    println!("BLE FIDO: esp-rtos started");
    println!("BLE FIDO: heap free={}", esp_alloc::HEAP.free());
    let controller = build_ble_controller(peripherals.BT);
    println!("BLE FIDO: controller initialized");
    spawner.spawn(
        fido_task(
            controller,
            peripherals.FLASH,
            peripherals.GPIO25,
            peripherals.GPIO0,
            peripherals.GPIO2,
            peripherals.SHA,
            peripherals.RNG,
            peripherals.ADC1,
        )
        .unwrap(),
    );
    core::future::pending::<()>().await;
}

#[embassy_executor::task]
async fn fido_task(
    controller: EspBleController,
    flash: FLASH<'static>,
    gpio25: GPIO25<'static>,
    gpio0: GPIO0<'static>,
    gpio2: GPIO2<'static>,
    sha: SHA<'static>,
    rng: RNG<'static>,
    adc1: ADC1<'static>,
) {
    let status = Output::new(gpio25, Level::Low, Default::default());
    let _trng_source = TrngSource::new(rng, adc1);
    let fido = FIDO.init_with(|| {
        build_ble_fido_frontend(
            flash,
            presence_button(gpio0),
            presence_led(gpio2),
            sha,
            BLE_PACKET_LEN,
        )
    });
    println!("BLE FIDO: frontend size={}", core::mem::size_of_val(fido));
    println!("BLE FIDO: dispatcher initialized");
    run_ble_peripheral(controller, status, fido).await;
}
