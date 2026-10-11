#![no_std]
#![no_main]

#[cfg(feature = "log-uart")]
compile_error!("Internal UART owns UART0; use log-jtag-serial");

use core::cell::RefCell;
use embassy_executor::Spawner;
use embassy_sync::blocking_mutex::Mutex;
use esp_alloc as _;
use esp_backtrace as _;
use esp_hal::{
    Async,
    clock::CpuClock,
    gpio::{Level, Output},
    peripherals::{GPIO27, RMT},
    uart::{ClockSource, Config as UartConfig, RxConfig, Uart},
};
use esp_println::println;
use esp32c5::{
    ble_fido::{
        BLE_PACKET_LEN, EspBleHostResources, build_ble_controller,
        run_ble_peripheral_encrypted_with_bond_store_using_resources, start_ble_rtos,
    },
    ble_ingress::{SharedArbiter, SharedBleIngressFrontend},
    board_ui::run_status_pixel,
    fido::{EspSharedTrustedDispatcher, build_ble_dispatcher_from_shared_flash},
    internal_ingress::{SharedInternalIngressFrontend, run_internal_uart},
    storage::{EspFlashBondStore, SharedEspFlash, new_shared_esp_flash},
};
use manekey::{
    ctaphid::trusted::TRUSTED_RESPONSE_MAX,
    frontend::ingress::{IngressArbiter, IngressId, IngressKind},
    transport::interconnect::{HEADER_LEN, TRAILER_LEN},
};
use static_cell::StaticCell;

#[cfg(not(feature = "ble-dual-task"))]
type Backend = EspSharedTrustedDispatcher;
#[cfg(feature = "ble-dual-task")]
type Backend = manekey::boundary::mailbox_backend::MailboxTrustedBackend<
    manekey::boundary::mailbox::LocalMailboxTransport<
        'static,
        { manekey::ctaphid::trusted::TRUSTED_REQUEST_MAX },
        TRUSTED_RESPONSE_MAX,
    >,
>;
type InternalFrontend = SharedInternalIngressFrontend<Backend, { 1024 + HEADER_LEN + TRAILER_LEN }>;
const RESPONSE_MAX: usize = TRUSTED_RESPONSE_MAX + HEADER_LEN + TRAILER_LEN;
static FLASH: StaticCell<SharedEspFlash<'static>> = StaticCell::new();
static ARBITER: StaticCell<SharedArbiter<Backend>> = StaticCell::new();
static INTERNAL: StaticCell<InternalFrontend> = StaticCell::new();
static RESPONSE: StaticCell<[u8; RESPONSE_MAX]> = StaticCell::new();
static RESOURCES: StaticCell<EspBleHostResources> = StaticCell::new();
#[cfg(feature = "ble-dual-task")]
static MAILBOX: esp32c5::mailbox::EspMailboxEndpoint = esp32c5::mailbox::EspMailboxEndpoint::new();
#[cfg(feature = "ble-dual-task")]
static WORKER: StaticCell<esp32c5::mailbox::EspLocalTrustedWorker<EspSharedTrustedDispatcher>> =
    StaticCell::new();

esp_bootloader_esp_idf::esp_app_desc!();

#[embassy_executor::task]
async fn internal_task(
    uart: Uart<'static, Async>,
    frontend: &'static mut InternalFrontend,
    response: &'static mut [u8; RESPONSE_MAX],
) {
    run_internal_uart(uart, frontend, response).await;
}
#[embassy_executor::task]
async fn status_pixel(rmt: RMT<'static>, pin: GPIO27<'static>) {
    run_status_pixel(rmt, pin).await;
}
#[cfg(feature = "ble-dual-task")]
#[embassy_executor::task]
async fn trusted_task(
    worker: &'static mut esp32c5::mailbox::EspLocalTrustedWorker<EspSharedTrustedDispatcher>,
) {
    esp32c5::mailbox::run_local_trusted_worker(worker, &MAILBOX).await;
}

#[esp_rtos::main]
/// Shared UART/BLE ingress is cooperative, not PMP isolation; queued writes do not guarantee peer delivery.
async fn main(spawner: Spawner) {
    esp_println::logger::init_logger(log::LevelFilter::Info);
    println!("MANEKEY C5 BLE/Internal shared ingress boot");
    let p = esp_hal::init(esp_hal::Config::default().with_cpu_clock(CpuClock::max()));
    #[cfg(any(feature = "ble-ml-dsa-native", feature = "ml-dsa-integrated-layout"))]
    esp_alloc::heap_allocator!(#[unsafe(link_section = ".ml_dsa_heap")] size: 32 * 1024);
    #[cfg(not(any(feature = "ble-ml-dsa-native", feature = "ml-dsa-integrated-layout")))]
    esp_alloc::heap_allocator!(size: 48 * 1024);
    let activity = Output::new(p.GPIO24, Level::Low, Default::default());
    start_ble_rtos(p.TIMG0, p.SW_INTERRUPT);

    let controller = build_ble_controller(p.BT);
    let flash = FLASH.init(new_shared_esp_flash(p.FLASH));
    let trusted = build_ble_dispatcher_from_shared_flash(flash, p.GPIO28, p.SHA, p.AES);
    #[cfg(feature = "ble-dual-task")]
    let backend = {
        spawner.spawn(
            trusted_task(WORKER.init(esp32c5::mailbox::EspLocalTrustedWorker::new(trusted)))
                .unwrap(),
        );
        Backend::new(manekey::boundary::mailbox::LocalMailboxTransport::new(
            &MAILBOX,
        ))
    };
    #[cfg(not(feature = "ble-dual-task"))]
    let backend = trusted;
    let arbiter = ARBITER.init(Mutex::new(RefCell::new(IngressArbiter::new(backend))));
    let ble =
        SharedBleIngressFrontend::new(BLE_PACKET_LEN, IngressId::new(IngressKind::Ble, 0), arbiter);
    let internal = INTERNAL.init(InternalFrontend::new(0, arbiter));
    let response = RESPONSE.init([0; RESPONSE_MAX]);
    let config = UartConfig::default()
        .with_baudrate(115_200)
        .with_clock_source(ClockSource::Xtal)
        .with_rx(RxConfig::default().with_fifo_full_threshold(1));
    let uart = Uart::new(p.UART0, config)
        .expect("UART0 config")
        .with_tx(p.GPIO11)
        .with_rx(p.GPIO12)
        .into_async();
    spawner.spawn(internal_task(uart, internal, response).unwrap());
    spawner.spawn(status_pixel(p.RMT, p.GPIO27).unwrap());
    println!("C5 MK UART GPIO11 TX/GPIO12 RX; BLE arbiter ready");
    run_ble_peripheral_encrypted_with_bond_store_using_resources(
        controller,
        activity,
        ble,
        EspFlashBondStore::new(flash),
        RESOURCES.init(EspBleHostResources::new()),
    )
    .await;
}
