#![no_std]
#![no_main]

use embassy_executor::Spawner;
use embassy_futures::join::join;
use esp_alloc as _;
use esp_backtrace as _;
use esp_hal::{
    clock::CpuClock,
    gpio::{Level, Output},
};
use esp_println::println;
use esp32c5::{
    ble_fido::{BLE_PACKET_LEN, build_ble_controller, run_ble_peripheral, start_ble_rtos},
    board_ui::run_status_pixel,
    fido::build_ble_fido_frontend_from_parts,
};

esp_bootloader_esp_idf::esp_app_desc!();

#[esp_rtos::main]
async fn main(_spawner: Spawner) {
    esp_println::logger::init_logger(log::LevelFilter::Info);
    println!("MANEKEY ESP32-C5 BLE FIDO boot");
    let peripherals = esp_hal::init(esp_hal::Config::default().with_cpu_clock(CpuClock::max()));
    esp_alloc::heap_allocator!(size: 72 * 1024);

    let activity = Output::new(peripherals.GPIO24, Level::Low, Default::default());
    start_ble_rtos(peripherals.TIMG0, peripherals.SW_INTERRUPT);
    let controller = build_ble_controller(peripherals.BT);
    let ble_fido = build_ble_fido_frontend_from_parts(
        peripherals.FLASH,
        peripherals.GPIO28,
        peripherals.SHA,
        BLE_PACKET_LEN,
    );
    println!("BLE FIDO: dispatcher initialized");
    join(
        run_ble_peripheral(controller, activity, ble_fido),
        run_status_pixel(peripherals.RMT, peripherals.GPIO27),
    )
    .await;
}
