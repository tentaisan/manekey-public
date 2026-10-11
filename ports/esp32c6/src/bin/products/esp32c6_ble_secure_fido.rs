#![no_std]
#![no_main]

#[cfg(all(
    any(
        feature = "experimental-ml-dsa-fips204",
        feature = "experimental-ml-dsa-mldsa-native"
    ),
    not(any(
        feature = "ml-dsa-integrated-layout",
        feature = "ml-dsa-native-integrated-layout"
    ))
))]
compile_error!("C6 BLE ML-DSA requires its explicit integrated layout feature");

#[cfg(all(
    feature = "experimental-ml-dsa-fips204",
    feature = "experimental-ml-dsa-mldsa-native"
))]
compile_error!("select exactly one C6 ML-DSA backend");

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
use esp32c6::fido::build_ble_fido_frontend_from_shared_flash;
use esp32c6::{
    ble_fido::{
        BLE_PACKET_LEN, EspBleHostResources, build_ble_controller,
        run_ble_peripheral_encrypted_with_bond_store_using_resources, start_ble_rtos,
    },
    storage::{EspFlashBondStore, new_shared_esp_flash},
};
#[cfg(feature = "ble-dual-task")]
use esp32c6::{
    fido::{EspSharedTrustedDispatcher, build_ble_dispatcher_from_shared_flash},
    mailbox::{
        EspLocalTrustedWorker, EspMailboxEndpoint, build_mailbox_ble_frontend,
        run_local_trusted_worker,
    },
};
use static_cell::StaticCell;

esp_bootloader_esp_idf::esp_app_desc!();

#[cfg(all(
    feature = "ble-dual-task",
    any(
        feature = "experimental-ml-dsa-fips204",
        feature = "experimental-ml-dsa-mldsa-native"
    ),
    not(feature = "ml-dsa-dual-task-experimental")
))]
compile_error!("C6 dual-task ML-DSA requires ml-dsa-dual-task-experimental");

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
/// Encrypted BLE admission is not isolation of the trusted backend.
async fn main(spawner: Spawner) {
    esp_println::logger::init_logger(log::LevelFilter::Info);
    println!("MANEKEY ESP32-C6 BLE secure FIDO boot");
    println!("BLE secure: encrypted GATT access; BLE link is not the trusted boundary");
    let peripherals = esp_hal::init(esp_hal::Config::default().with_cpu_clock(CpuClock::max()));
    #[cfg(any(
        feature = "ml-dsa-integrated-layout",
        feature = "ml-dsa-native-integrated-layout"
    ))]
    esp_alloc::heap_allocator!(#[unsafe(link_section = ".ml_dsa_heap")] size: 32 * 1024);
    #[cfg(not(any(
        feature = "ml-dsa-integrated-layout",
        feature = "ml-dsa-native-integrated-layout"
    )))]
    esp_alloc::heap_allocator!(size: 96 * 1024);

    #[allow(unused_mut)]
    let mut led = Output::new(peripherals.GPIO21, Level::Low, Default::default());

    start_ble_rtos(peripherals.TIMG0, peripherals.SW_INTERRUPT);

    let _trng_source = TrngSource::new(peripherals.RNG, peripherals.ADC1);
    static FLASH: StaticCell<esp32c6::storage::SharedEspFlash<'static>> = StaticCell::new();
    let flash = FLASH.init(new_shared_esp_flash(peripherals.FLASH));
    #[cfg(not(feature = "ble-dual-task"))]
    let ble_fido = build_ble_fido_frontend_from_shared_flash(
        flash,
        peripherals.GPIO2,
        peripherals.SHA,
        peripherals.AES,
        peripherals.ECC,
        BLE_PACKET_LEN,
    );
    #[cfg(feature = "ble-dual-task")]
    let ble_fido = {
        let dispatcher = build_ble_dispatcher_from_shared_flash(
            flash,
            peripherals.GPIO2,
            peripherals.SHA,
            peripherals.AES,
            peripherals.ECC,
        );
        spawner.spawn(trusted_task(WORKER.init(EspLocalTrustedWorker::new(dispatcher))).unwrap());
        build_mailbox_ble_frontend(&MAILBOX, BLE_PACKET_LEN)
    };
    #[cfg(not(feature = "ble-dual-task"))]
    let _ = spawner;
    let bond_store = EspFlashBondStore::new(flash);
    static RESOURCES: StaticCell<EspBleHostResources> = StaticCell::new();
    let resources = RESOURCES.init(EspBleHostResources::new());

    let controller = build_ble_controller(peripherals.BT);

    run_ble_peripheral_encrypted_with_bond_store_using_resources(
        controller, led, ble_fido, bond_store, resources,
    )
    .await;
}
