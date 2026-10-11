#![no_std]
#![no_main]

#[cfg(feature = "client-pin-flash")]
compile_error!("client-pin-flash requires esp32c3_ble_secure_fido's shared flash dispatcher");

use embassy_executor::Spawner;
use esp_alloc as _;
use esp_backtrace as _;
use esp_hal::{
    clock::CpuClock,
    gpio::{Level, Output},
    rng::TrngSource,
};
use esp_println::println;

use esp32c3::{
    ble_fido::{BLE_PACKET_LEN, build_ble_controller, run_ble_peripheral, start_ble_rtos},
    fido::{EspTrustedDispatcher, build_ble_dispatcher_from_parts},
    mailbox::{
        EspLocalTrustedWorker, EspMailboxEndpoint, build_mailbox_ble_frontend,
        run_local_trusted_worker,
    },
};
use static_cell::StaticCell;

esp_bootloader_esp_idf::esp_app_desc!();

static MAILBOX: EspMailboxEndpoint = EspMailboxEndpoint::new();
static WORKER: StaticCell<EspLocalTrustedWorker<EspTrustedDispatcher>> = StaticCell::new();

#[esp_rtos::main]
async fn main(spawner: Spawner) {
    esp_println::logger::init_logger(log::LevelFilter::Info);
    println!("MANEKEY ESP32-C3 BLE DUAL TASK FIDO boot");
    let peripherals = esp_hal::init(esp_hal::Config::default().with_cpu_clock(CpuClock::max()));
    esp_alloc::heap_allocator!(size: 48 * 1024);

    let led = Output::new(peripherals.GPIO10, Level::Low, Default::default());

    start_ble_rtos(peripherals.TIMG0, peripherals.SW_INTERRUPT);

    let _trng_source = TrngSource::new(peripherals.RNG, peripherals.ADC1);
    let dispatcher =
        build_ble_dispatcher_from_parts(peripherals.FLASH, peripherals.GPIO2, peripherals.SHA);
    let worker = WORKER.init(EspLocalTrustedWorker::new(dispatcher));
    spawner.spawn(trusted_task(worker).unwrap());
    let ble_fido = build_mailbox_ble_frontend(&MAILBOX, BLE_PACKET_LEN);

    let controller = build_ble_controller(peripherals.BT);

    run_ble_peripheral(controller, led, ble_fido).await;
}

#[embassy_executor::task]
async fn trusted_task(worker: &'static mut EspLocalTrustedWorker<EspTrustedDispatcher>) {
    run_local_trusted_worker(worker, &MAILBOX).await;
}
