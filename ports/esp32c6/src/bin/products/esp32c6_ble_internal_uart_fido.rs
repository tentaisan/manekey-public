#![no_std]
#![no_main]

#[cfg(feature = "log-uart")]
compile_error!("internal UART uses D6/D7; build this product with log-jtag-serial, not log-uart");

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
compile_error!("C6 internal UART ML-DSA requires its explicit integrated layout feature");

#[cfg(all(
    feature = "experimental-ml-dsa-fips204",
    feature = "experimental-ml-dsa-mldsa-native"
))]
compile_error!("select exactly one C6 ML-DSA backend");

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
use esp_println::println;

use esp32c6::{
    ble_fido::{
        BLE_PACKET_LEN, EspBleHostResources, build_ble_controller,
        run_ble_peripheral_encrypted_with_bond_store_using_resources, start_ble_rtos,
    },
    ble_ingress::{SharedArbiter, SharedBleIngressFrontend},
    fido::{EspSharedTrustedDispatcher, build_ble_dispatcher_from_shared_flash},
    internal_ingress::SharedInternalIngressFrontend,
    storage::{EspFlashBondStore, new_shared_esp_flash},
};

use manekey::{
    ctaphid::trusted::TRUSTED_RESPONSE_MAX,
    frontend::{
        ingress::{IngressArbiter, IngressId, IngressKind},
        internal::INTERNAL_CTAP2_CHANNEL,
    },
    transport::interconnect::{HEADER_LEN, TRAILER_LEN},
};
use static_cell::StaticCell;

const UART_INSTANCE: u8 = 0;
const UART_FRAME_MAX: usize = 1024 + HEADER_LEN + TRAILER_LEN;
const UART_RESPONSE_FRAME_MAX: usize = TRUSTED_RESPONSE_MAX + HEADER_LEN + TRAILER_LEN;
const BLE_INGRESS: IngressId = IngressId::new(IngressKind::Ble, 0);

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
type InternalFrontend = SharedInternalIngressFrontend<Backend, UART_FRAME_MAX>;

static FLASH: StaticCell<esp32c6::storage::SharedEspFlash<'static>> = StaticCell::new();
static ARBITER: StaticCell<SharedArbiter<Backend>> = StaticCell::new();
static INTERNAL: StaticCell<InternalFrontend> = StaticCell::new();
static UART_RESPONSE: StaticCell<[u8; UART_RESPONSE_FRAME_MAX]> = StaticCell::new();
static RESOURCES: StaticCell<EspBleHostResources> = StaticCell::new();
#[cfg(feature = "ble-dual-task")]
static MAILBOX: esp32c6::mailbox::EspMailboxEndpoint = esp32c6::mailbox::EspMailboxEndpoint::new();
#[cfg(feature = "ble-dual-task")]
static WORKER: StaticCell<esp32c6::mailbox::EspLocalTrustedWorker<EspSharedTrustedDispatcher>> =
    StaticCell::new();

esp_bootloader_esp_idf::esp_app_desc!();

#[embassy_executor::task]
async fn internal_uart_task(
    uart: Uart<'static, Async>,
    frontend: &'static mut InternalFrontend,
    response: &'static mut [u8; UART_RESPONSE_FRAME_MAX],
) {
    esp32c6::internal_ingress::run_internal_uart(uart, frontend, response).await;
}

#[cfg(feature = "ble-dual-task")]
#[embassy_executor::task]
async fn trusted_task(
    worker: &'static mut esp32c6::mailbox::EspLocalTrustedWorker<EspSharedTrustedDispatcher>,
) {
    esp32c6::mailbox::run_local_trusted_worker(worker, &MAILBOX).await;
}

#[embassy_executor::task]
async fn status_led(mut led: Output<'static>) {
    loop {
        let active =
            esp32c6::board::UI_STATUS.get() == manekey::presence::PresenceUiHint::TouchRequired;
        led.set_level(if active { Level::Low } else { Level::High });
        embassy_time::Timer::after_millis(2).await;
    }
}

#[esp_rtos::main]
/// Shared UART/BLE ingress is cooperative, not PMP isolation; queued writes do not guarantee peer delivery.
async fn main(spawner: Spawner) {
    esp_println::logger::init_logger(log::LevelFilter::Info);
    println!("MANEKEY ESP32-C6 BLE/internal-UART FIDO boot");
    println!(
        "internal UART: 115200 8N1, D6/GPIO16 TX, D7/GPIO17 RX, MK CTAP2 channel={INTERNAL_CTAP2_CHANNEL}"
    );

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

    let flash = FLASH.init(new_shared_esp_flash(peripherals.FLASH));
    let dispatcher = build_ble_dispatcher_from_shared_flash(
        flash,
        peripherals.GPIO2,
        peripherals.SHA,
        peripherals.AES,
        peripherals.ECC,
    );
    #[cfg(feature = "ble-dual-task")]
    let backend = {
        spawner.spawn(
            trusted_task(WORKER.init(esp32c6::mailbox::EspLocalTrustedWorker::new(dispatcher)))
                .unwrap(),
        );
        Backend::new(manekey::boundary::mailbox::LocalMailboxTransport::new(
            &MAILBOX,
        ))
    };
    #[cfg(not(feature = "ble-dual-task"))]
    let backend = dispatcher;
    let arbiter = ARBITER.init(Mutex::new(RefCell::new(IngressArbiter::new(backend))));
    let ble_fido = SharedBleIngressFrontend::new(BLE_PACKET_LEN, BLE_INGRESS, arbiter);
    let internal = INTERNAL.init(InternalFrontend::new(UART_INSTANCE, arbiter));
    let response = UART_RESPONSE.init([0; UART_RESPONSE_FRAME_MAX]);
    let uart_config = UartConfig::default()
        .with_baudrate(115_200)
        .with_clock_source(ClockSource::Xtal)
        .with_rx(RxConfig::default().with_fifo_full_threshold(1));
    let uart = Uart::new(peripherals.UART0, uart_config)
        .expect("UART0 configuration")
        .with_tx(peripherals.GPIO16)
        .with_rx(peripherals.GPIO17)
        .into_async();
    let bond_store = EspFlashBondStore::new(flash);
    let resources = RESOURCES.init(EspBleHostResources::new());
    let controller = build_ble_controller(peripherals.BT);

    spawner.spawn(internal_uart_task(uart, internal, response).expect("create internal UART task"));
    spawner.spawn(
        status_led(Output::new(
            peripherals.GPIO15,
            Level::High,
            Default::default(),
        ))
        .unwrap(),
    );
    run_ble_peripheral_encrypted_with_bond_store_using_resources(
        controller, led, ble_fido, bond_store, resources,
    )
    .await;
}
