#![no_std]
#![no_main]

#[cfg(feature = "log-uart")]
compile_error!("D6/D7 are the Internal UART; select log-jtag-serial");
#[cfg(any(
    feature = "ml-dsa-fips204-backend",
    feature = "ml-dsa-mldsa-native-backend"
))]
compile_error!("C3 BLE ML-DSA remains pending runtime memory review");

use core::cell::RefCell;
use embassy_executor::Spawner;
use embassy_sync::blocking_mutex::Mutex;
use esp_alloc as _;
use esp_backtrace as _;
use esp_hal::{
    Async,
    clock::CpuClock,
    gpio::{Level, Output},
    rng::TrngSource,
    uart::{ClockSource, Config as UartConfig, RxConfig, Uart},
};
use esp32c3::{
    ble_fido::{
        BLE_PACKET_LEN, EspBleHostResources, build_ble_controller,
        run_ble_peripheral_encrypted_with_bond_store_using_resources, start_ble_rtos,
    },
    ble_ingress::{SharedArbiter, SharedBleIngressFrontend},
    fido::{EspSharedTrustedDispatcher, build_ble_dispatcher_from_shared_flash},
    internal_ingress::SharedInternalIngressFrontend,
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
const FRAME_MAX: usize = 1024 + HEADER_LEN + TRAILER_LEN;
const RESPONSE_MAX: usize = TRUSTED_RESPONSE_MAX + HEADER_LEN + TRAILER_LEN;
type InternalFrontend = SharedInternalIngressFrontend<Backend, FRAME_MAX>;
static FLASH: StaticCell<SharedEspFlash<'static>> = StaticCell::new();
static ARBITER: StaticCell<SharedArbiter<Backend>> = StaticCell::new();
static INTERNAL: StaticCell<InternalFrontend> = StaticCell::new();
static RESPONSE: StaticCell<[u8; RESPONSE_MAX]> = StaticCell::new();
static RESOURCES: StaticCell<EspBleHostResources> = StaticCell::new();
#[cfg(feature = "ble-dual-task")]
static MAILBOX: esp32c3::mailbox::EspMailboxEndpoint = esp32c3::mailbox::EspMailboxEndpoint::new();
#[cfg(feature = "ble-dual-task")]
static WORKER: StaticCell<esp32c3::mailbox::EspLocalTrustedWorker<EspSharedTrustedDispatcher>> =
    StaticCell::new();

esp_bootloader_esp_idf::esp_app_desc!();

#[embassy_executor::task]
async fn internal_uart_task(
    uart: Uart<'static, Async>,
    frontend: &'static mut InternalFrontend,
    response: &'static mut [u8; RESPONSE_MAX],
) {
    esp32c3::internal_ingress::run_internal_uart(uart, frontend, response).await;
}

#[cfg(feature = "ble-dual-task")]
#[embassy_executor::task]
async fn trusted_task(
    worker: &'static mut esp32c3::mailbox::EspLocalTrustedWorker<EspSharedTrustedDispatcher>,
) {
    esp32c3::mailbox::run_local_trusted_worker(worker, &MAILBOX).await;
}

#[esp_rtos::main]
async fn main(spawner: Spawner) {
    esp_println::logger::init_logger(log::LevelFilter::Info);
    let peripherals = esp_hal::init(esp_hal::Config::default().with_cpu_clock(CpuClock::max()));
    esp_alloc::heap_allocator!(size: 48 * 1024);
    esp_println::println!("MANEKEY C3 shared BLE/Internal UART boot; UP=D0/GPIO2");
    start_ble_rtos(peripherals.TIMG0, peripherals.SW_INTERRUPT);
    let _trng_source = TrngSource::new(peripherals.RNG, peripherals.ADC1);
    let flash = FLASH.init(new_shared_esp_flash(peripherals.FLASH));
    let dispatcher = build_ble_dispatcher_from_shared_flash(
        flash,
        peripherals.GPIO2,
        peripherals.SHA,
        peripherals.AES,
    );
    #[cfg(feature = "ble-dual-task")]
    let backend = {
        spawner.spawn(
            trusted_task(WORKER.init(esp32c3::mailbox::EspLocalTrustedWorker::new(dispatcher)))
                .unwrap(),
        );
        Backend::new(manekey::boundary::mailbox::LocalMailboxTransport::new(
            &MAILBOX,
        ))
    };
    #[cfg(not(feature = "ble-dual-task"))]
    let backend = dispatcher;
    let arbiter = ARBITER.init(Mutex::new(RefCell::new(IngressArbiter::new(backend))));
    let ble =
        SharedBleIngressFrontend::new(BLE_PACKET_LEN, IngressId::new(IngressKind::Ble, 0), arbiter);
    let internal = INTERNAL.init(InternalFrontend::new(0, arbiter));
    let response = RESPONSE.init([0; RESPONSE_MAX]);
    let uart = Uart::new(
        peripherals.UART0,
        UartConfig::default()
            .with_baudrate(115_200)
            .with_clock_source(ClockSource::Xtal)
            .with_rx(RxConfig::default().with_fifo_full_threshold(1)),
    )
    .expect("UART0 configuration")
    .with_tx(peripherals.GPIO21)
    .with_rx(peripherals.GPIO20)
    .into_async();
    spawner.spawn(internal_uart_task(uart, internal, response).unwrap());
    let bond = EspFlashBondStore::new(flash);
    let resources = RESOURCES.init(EspBleHostResources::new());
    let controller = build_ble_controller(peripherals.BT);

    let led = Output::new(peripherals.GPIO10, Level::Low, Default::default());
    esp_println::println!("C3 UART/BLE shared ingress initialized");
    run_ble_peripheral_encrypted_with_bond_store_using_resources(
        controller, led, ble, bond, resources,
    )
    .await;
}
