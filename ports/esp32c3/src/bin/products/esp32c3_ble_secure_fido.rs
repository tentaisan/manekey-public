#![no_std]
#![no_main]

#[cfg(all(
    feature = "experimental-ml-dsa-fips204",
    not(feature = "ml-dsa-integrated-layout")
))]
compile_error!("C3 BLE ML-DSA requires ml-dsa-integrated-layout");

#[cfg(all(
    feature = "experimental-ml-dsa-mldsa-native",
    not(feature = "ml-dsa-native-integrated-layout")
))]
compile_error!("C3 BLE native ML-DSA requires ml-dsa-native-integrated-layout");

use embassy_executor::Spawner;
use esp_alloc as _;
use esp_backtrace as _;
use esp_hal::{
    clock::CpuClock,
    gpio::{Level, Output},
    rng::TrngSource,
};
use esp_println::println;

#[cfg(not(feature = "ble-dual-task"))]
use esp32c3::fido::build_ble_fido_frontend_from_shared_flash;
use esp32c3::{
    ble_fido::{
        BLE_PACKET_LEN, EspBleHostResources, build_ble_controller,
        run_ble_peripheral_encrypted_with_bond_store_using_resources, start_ble_rtos,
    },
    storage::{EspFlashBondStore, new_shared_esp_flash},
};
#[cfg(feature = "ble-dual-task")]
use esp32c3::{
    fido::{EspSharedTrustedDispatcher, build_ble_dispatcher_from_shared_flash},
    mailbox::{
        EspLocalTrustedWorker, EspMailboxEndpoint, build_mailbox_ble_frontend,
        run_local_trusted_worker,
    },
};
use static_cell::StaticCell;

esp_bootloader_esp_idf::esp_app_desc!();

#[cfg(all(feature = "ble-dual-task", feature = "experimental-ml-dsa-fips204"))]
compile_error!("C3 dual-task ML-DSA needs a separate runtime memory review");

#[cfg(feature = "ble-dual-task")]
static MAILBOX: EspMailboxEndpoint = EspMailboxEndpoint::new();
#[cfg(feature = "ble-dual-task")]
static WORKER: StaticCell<EspLocalTrustedWorker<EspSharedTrustedDispatcher>> = StaticCell::new();

#[cfg(feature = "ble-dual-task")]
#[embassy_executor::task]
async fn trusted_task(worker: &'static mut EspLocalTrustedWorker<EspSharedTrustedDispatcher>) {
    run_local_trusted_worker(worker, &MAILBOX).await;
}

#[esp_rtos::main]
async fn main(spawner: Spawner) {
    esp_println::logger::init_logger(log::LevelFilter::Info);
    println!("MANEKEY ESP32-C3 BLE secure PIN flash boot");
    let peripherals = esp_hal::init(esp_hal::Config::default().with_cpu_clock(CpuClock::max()));
    #[cfg(any(
        feature = "ml-dsa-integrated-layout",
        feature = "ml-dsa-native-integrated-layout"
    ))]
    esp_alloc::heap_allocator!(#[unsafe(link_section = ".ml_dsa_heap")] size: 48 * 1024);
    #[cfg(not(any(
        feature = "ml-dsa-integrated-layout",
        feature = "ml-dsa-native-integrated-layout"
    )))]
    esp_alloc::heap_allocator!(size: 48 * 1024);

    let led = Output::new(peripherals.GPIO10, Level::Low, Default::default());

    start_ble_rtos(peripherals.TIMG0, peripherals.SW_INTERRUPT);

    let _trng_source = TrngSource::new(peripherals.RNG, peripherals.ADC1);
    static FLASH: StaticCell<esp32c3::storage::SharedEspFlash<'static>> = StaticCell::new();
    let flash = FLASH.init(new_shared_esp_flash(peripherals.FLASH));
    #[cfg(not(feature = "ble-dual-task"))]
    let ble_fido = build_ble_fido_frontend_from_shared_flash(
        flash,
        peripherals.GPIO2,
        peripherals.SHA,
        peripherals.AES,
        BLE_PACKET_LEN,
    );
    #[cfg(feature = "ble-dual-task")]
    let ble_fido = {
        let dispatcher = build_ble_dispatcher_from_shared_flash(
            flash,
            peripherals.GPIO2,
            peripherals.SHA,
            peripherals.AES,
        );
        spawner.spawn(trusted_task(WORKER.init(EspLocalTrustedWorker::new(dispatcher))).unwrap());
        build_mailbox_ble_frontend(&MAILBOX, BLE_PACKET_LEN)
    };
    let bond_store = EspFlashBondStore::new(flash);

    let controller = build_ble_controller(peripherals.BT);
    static RESOURCES: StaticCell<EspBleHostResources> = StaticCell::new();
    let resources = RESOURCES.init(EspBleHostResources::new());

    #[cfg(all(not(any()), not(feature = "ble-dual-task")))]
    let _ = spawner;

    run_ble_peripheral_encrypted_with_bond_store_using_resources(
        controller, led, ble_fido, bond_store, resources,
    )
    .await;
}
