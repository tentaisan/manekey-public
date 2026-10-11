#![no_std]
#![no_main]

#[cfg(feature = "ble-dual-core")]
use core::sync::atomic::AtomicU32;
use embassy_executor::Spawner;
#[cfg(feature = "ble-dual-task")]
use embassy_time::Timer;
use esp_alloc as _;
use esp_backtrace as _;
#[cfg(feature = "ble-dual-core")]
use esp_hal::system::{CpuControl, Stack};
use esp_hal::{
    clock::CpuClock,
    gpio::{Level, Output},
    peripherals::{ADC1, AES, FLASH, GPIO0, GPIO2, GPIO25, RNG, SHA},
    rng::TrngSource,
};
use esp_println::println;
#[cfg(not(any(feature = "ble-dual-task", feature = "ble-dual-core")))]
use manekey::transport::ble::BleFidoFrontend;
#[cfg(feature = "ble-dual-core")]
use manekey_esp32::app_core::AppCoreTrustedWorker;
use manekey_esp32::board_ui::{presence_button, presence_led};
#[cfg(not(feature = "ble-dual-core"))]
use manekey_esp32::fido::EspSharedTrustedDispatcher;
#[cfg(not(any(feature = "ble-dual-task", feature = "ble-dual-core")))]
use manekey_esp32::fido::build_ble_fido_frontend_from_shared_flash;
#[cfg(feature = "ble-dual-task")]
use manekey_esp32::mailbox::EspLocalTrustedWorker;
#[cfg(feature = "ble-dual-core")]
use manekey_esp32::storage::new_multicore_shared_esp_flash;
#[cfg(not(feature = "ble-dual-core"))]
use manekey_esp32::storage::new_shared_esp_flash;
#[cfg(any(feature = "ble-dual-task", feature = "ble-dual-core"))]
use manekey_esp32::{
    ble_fido::BLE_PACKET_LEN,
    fido::build_ble_dispatcher_from_shared_flash,
    mailbox::{EspMailboxBleFrontend, EspMailboxEndpoint, build_mailbox_ble_frontend},
};
use manekey_esp32::{
    ble_fido::{
        EspBleController, EspBleHostResources, build_ble_controller,
        run_ble_peripheral_encrypted_with_bond_store_using_resources, start_ble_rtos,
    },
    storage::{EspFlashBondStore, SharedEspFlash},
};
use static_cell::StaticCell;

esp_bootloader_esp_idf::esp_app_desc!();

#[cfg(all(feature = "ble-dual-task", feature = "ble-dual-core"))]
compile_error!("ble-dual-task and ble-dual-core are separate boundary configurations");

#[cfg(any(feature = "ble-dual-task", feature = "ble-dual-core"))]
static MAILBOX: EspMailboxEndpoint = EspMailboxEndpoint::new();
#[cfg(feature = "ble-dual-core")]
static APP_CORE_STACK: StaticCell<Stack<{ 32 * 1024 }>> = StaticCell::new();
#[cfg(feature = "ble-dual-core")]
static APP_CORE_MARKER: AtomicU32 = AtomicU32::new(0);

#[esp_rtos::main]
async fn main(spawner: Spawner) {
    esp_println::logger::init_logger(log::LevelFilter::Info);
    println!("MANEKEY ESP32 BLE secure PIN flash boot");
    let peripherals = esp_hal::init(esp_hal::Config::default().with_cpu_clock(CpuClock::_160MHz));
    esp_alloc::heap_allocator!(size: 40 * 1024);
    start_ble_rtos(peripherals.TIMG0, peripherals.SW_INTERRUPT);
    println!("BLE secure: esp-rtos started");

    let controller = build_ble_controller(peripherals.BT);
    println!("BLE secure: controller initialized");
    spawner.spawn(
        secure_task(
            spawner,
            controller,
            peripherals.FLASH,
            peripherals.GPIO25,
            peripherals.GPIO0,
            peripherals.GPIO2,
            peripherals.SHA,
            peripherals.AES,
            peripherals.RNG,
            peripherals.ADC1,
            #[cfg(feature = "ble-dual-core")]
            peripherals.CPU_CTRL,
        )
        .unwrap(),
    );
    core::future::pending::<()>().await;
}

#[embassy_executor::task]
async fn secure_task(
    #[cfg_attr(not(feature = "ble-dual-task"), allow(unused_variables))] spawner: Spawner,
    controller: EspBleController,
    flash_peripheral: FLASH<'static>,
    gpio25: GPIO25<'static>,
    gpio0: GPIO0<'static>,
    gpio2: GPIO2<'static>,
    sha: SHA<'static>,
    aes: AES<'static>,
    rng: RNG<'static>,
    adc1: ADC1<'static>,
    #[cfg(feature = "ble-dual-core")] cpu_ctrl: esp_hal::peripherals::CPU_CTRL<'static>,
) {
    let _trng_source = TrngSource::new(rng, adc1);
    static FLASH: StaticCell<SharedEspFlash<'static>> = StaticCell::new();
    #[cfg(not(feature = "ble-dual-core"))]
    let flash = FLASH.init(new_shared_esp_flash(flash_peripheral));
    #[cfg(feature = "ble-dual-core")]
    let flash = FLASH.init(new_multicore_shared_esp_flash(flash_peripheral));
    #[cfg(not(any(feature = "ble-dual-task", feature = "ble-dual-core")))]
    static FIDO: StaticCell<BleFidoFrontend<EspSharedTrustedDispatcher>> = StaticCell::new();
    #[cfg(not(any(feature = "ble-dual-task", feature = "ble-dual-core")))]
    let fido = FIDO.init_with(|| {
        build_ble_fido_frontend_from_shared_flash(
            flash,
            presence_button(gpio0),
            presence_led(gpio2),
            sha,
            aes,
            manekey_esp32::ble_fido::BLE_PACKET_LEN,
        )
    });
    #[cfg(feature = "ble-dual-task")]
    static WORKER: StaticCell<EspLocalTrustedWorker<EspSharedTrustedDispatcher>> =
        StaticCell::new();
    #[cfg(any(feature = "ble-dual-task", feature = "ble-dual-core"))]
    let dispatcher = build_ble_dispatcher_from_shared_flash(
        flash,
        presence_button(gpio0),
        presence_led(gpio2),
        sha,
        aes,
    );
    #[cfg(feature = "ble-dual-task")]
    let worker = WORKER.init(EspLocalTrustedWorker::new(dispatcher));
    #[cfg(any(feature = "ble-dual-task", feature = "ble-dual-core"))]
    static MAILBOX_FIDO: StaticCell<EspMailboxBleFrontend<'static>> = StaticCell::new();
    #[cfg(any(feature = "ble-dual-task", feature = "ble-dual-core"))]
    let fido = MAILBOX_FIDO.init(build_mailbox_ble_frontend(&MAILBOX, BLE_PACKET_LEN));
    #[cfg(feature = "ble-dual-task")]
    spawner.spawn(trusted_task(worker).unwrap());
    #[cfg(feature = "ble-dual-core")]
    let _app_core_guard = {
        let mut cpu_control = CpuControl::new(cpu_ctrl);
        let app_core_worker = AppCoreTrustedWorker::new(
            APP_CORE_STACK.init(Stack::new()),
            &MAILBOX,
            &APP_CORE_MARKER,
        );
        match app_core_worker.start(&mut cpu_control, dispatcher, 4) {
            Ok((guard, marker)) => {
                println!("ESP32 APP trusted worker marker={marker}");
                guard
            }
            Err(_) => {
                println!("ESP32 APP core start failed");
                core::future::pending::<()>().await;
                unreachable!()
            }
        }
    };
    let bond_store = EspFlashBondStore::new(flash);
    println!("BLE secure: trusted dispatcher initialized");

    static RESOURCES: StaticCell<EspBleHostResources> = StaticCell::new();
    let resources = RESOURCES.init(EspBleHostResources::new());
    let status = Output::new(gpio25, Level::Low, Default::default());
    println!("BLE secure: heap free={}", esp_alloc::HEAP.free());
    run_ble_peripheral_encrypted_with_bond_store_using_resources(
        controller, status, fido, bond_store, resources,
    )
    .await;
}

#[cfg(feature = "ble-dual-task")]
#[embassy_executor::task]
async fn trusted_task(worker: &'static mut EspLocalTrustedWorker<EspSharedTrustedDispatcher>) {
    loop {
        worker.pump(&MAILBOX);
        Timer::after_millis(2).await;
    }
}
