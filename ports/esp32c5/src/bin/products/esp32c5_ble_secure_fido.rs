#![no_std]
#![no_main]

use embassy_executor::Spawner;
use esp_alloc as _;
use esp_backtrace as _;
use esp_hal::{
    clock::CpuClock,
    gpio::{Level, Output},
    peripherals::{GPIO27, RMT},
};
use esp_println::println;
#[cfg(any(feature = "trusted-call-local-bridge", feature = "ble-dual-task"))]
use esp32c5::fido::EspSharedTrustedDispatcher;
#[cfg(feature = "ble-dual-task")]
use esp32c5::mailbox::{
    EspLocalTrustedWorker, EspMailboxEndpoint, build_mailbox_ble_frontend, run_local_trusted_worker,
};
use esp32c5::{
    ble_fido::{
        BLE_PACKET_LEN, EspBleHostResources, build_ble_controller,
        run_ble_peripheral_encrypted_with_bond_store_using_resources, start_ble_rtos,
    },
    board_ui::run_status_pixel,
    fido::build_ble_dispatcher_from_shared_flash,
    storage::{EspFlashBondStore, SharedEspFlash, new_shared_esp_flash},
};
#[cfg(not(feature = "ble-dual-task"))]
use manekey::transport::ble::BleFidoFrontend;
#[cfg(feature = "trusted-call-local-bridge")]
use manekey::{
    boundary::local_trusted_call::{LocalTrustedCallBackend, SharedTrustedCallState},
    security::SharedMemoryRegion,
};
use static_cell::StaticCell;

esp_bootloader_esp_idf::esp_app_desc!();

#[cfg(all(feature = "ble-dual-task", feature = "trusted-call-local-bridge"))]
compile_error!("C5 dual-task cannot be combined with trusted-call-local-bridge");

#[cfg(all(
    feature = "ble-dual-task",
    feature = "experimental-ml-dsa-fips204",
    not(feature = "ml-dsa-dual-task-experimental")
))]
compile_error!("C5 dual-task ML-DSA requires ml-dsa-dual-task-experimental");

#[cfg(feature = "ble-dual-task")]
static MAILBOX: EspMailboxEndpoint = EspMailboxEndpoint::new();
#[cfg(feature = "ble-dual-task")]
static WORKER: StaticCell<EspLocalTrustedWorker<EspSharedTrustedDispatcher>> = StaticCell::new();

#[cfg(feature = "ble-dual-task")]
#[embassy_executor::task]
async fn trusted_task(worker: &'static mut EspLocalTrustedWorker<EspSharedTrustedDispatcher>) {
    run_local_trusted_worker(worker, &MAILBOX).await;
}

#[embassy_executor::task]
async fn status_pixel(rmt: RMT<'static>, pin: GPIO27<'static>) {
    run_status_pixel(rmt, pin).await;
}

#[esp_rtos::main]
/// Encrypted BLE admission and cooperative/local bridge composition do not provide PMP isolation.
async fn main(spawner: Spawner) {
    esp_println::logger::init_logger(log::LevelFilter::Info);
    println!("MANEKEY ESP32-C5 BLE secure FIDO boot");
    let peripherals = esp_hal::init(esp_hal::Config::default().with_cpu_clock(CpuClock::max()));
    #[cfg(any(feature = "ml-dsa-integrated-layout", feature = "ble-ml-dsa-native"))]
    esp_alloc::heap_allocator!(#[unsafe(link_section = ".ml_dsa_heap")] size: 32 * 1024);
    #[cfg(not(any(feature = "ml-dsa-integrated-layout", feature = "ble-ml-dsa-native")))]
    esp_alloc::heap_allocator!(size: 48 * 1024);

    let activity = Output::new(peripherals.GPIO24, Level::Low, Default::default());
    start_ble_rtos(peripherals.TIMG0, peripherals.SW_INTERRUPT);
    let controller = build_ble_controller(peripherals.BT);
    static FLASH: StaticCell<SharedEspFlash<'static>> = StaticCell::new();
    let flash = FLASH.init(new_shared_esp_flash(peripherals.FLASH));
    let trusted = build_ble_dispatcher_from_shared_flash(
        flash,
        peripherals.GPIO28,
        peripherals.SHA,
        peripherals.AES,
    );
    #[cfg(feature = "trusted-call-local-bridge")]
    let ble_fido = {
        static TRUSTED: StaticCell<EspSharedTrustedDispatcher> = StaticCell::new();
        static SHARED: StaticCell<SharedTrustedCallState> = StaticCell::new();
        let trusted = TRUSTED.init(trusted);
        let shared = SHARED.init(SharedTrustedCallState::new());
        let start = shared as *mut SharedTrustedCallState as u32;
        let end = start + core::mem::size_of::<SharedTrustedCallState>() as u32;
        let region = SharedMemoryRegion::new(start, end).expect("shared call region");

        let backend = unsafe { LocalTrustedCallBackend::new(region, shared, trusted) };
        println!("BLE secure: local trusted-call bridge (M-mode, no U-mode isolation)");
        BleFidoFrontend::new(BLE_PACKET_LEN, backend)
    };
    #[cfg(feature = "ble-dual-task")]
    let ble_fido = {
        spawner.spawn(trusted_task(WORKER.init(EspLocalTrustedWorker::new(trusted))).unwrap());
        build_mailbox_ble_frontend(&MAILBOX, BLE_PACKET_LEN)
    };
    #[cfg(all(
        not(feature = "trusted-call-local-bridge"),
        not(feature = "ble-dual-task")
    ))]
    let ble_fido = BleFidoFrontend::new(BLE_PACKET_LEN, trusted);
    let bond_store = EspFlashBondStore::new(flash);
    static RESOURCES: StaticCell<EspBleHostResources> = StaticCell::new();
    let resources = RESOURCES.init(EspBleHostResources::new());
    println!("BLE secure: trusted dispatcher initialized");
    spawner.spawn(status_pixel(peripherals.RMT, peripherals.GPIO27).expect("status pixel task"));
    run_ble_peripheral_encrypted_with_bond_store_using_resources(
        controller, activity, ble_fido, bond_store, resources,
    )
    .await;
}
