#![no_std]
#![no_main]

use core::cell::RefCell;
use embassy_executor::Spawner;
use embassy_sync::blocking_mutex::Mutex;
use esp_backtrace as _;
use esp_hal::{
    Async,
    clock::CpuClock,
    gpio::{Level, Output},
    rng::TrngSource,
    uart::{Config as UartConfig, RxConfig, Uart},
};
use esp_println::println;
use manekey::{
    ctaphid::trusted::{TRUSTED_RESPONSE_MAX, TrustedDispatcher},
    frontend::ingress::{IngressArbiter, IngressId, IngressKind},
    transport::interconnect::{HEADER_LEN, TRAILER_LEN},
    user_interface::UiPresenceObserver,
};
use manekey_esp32::{
    ble_fido::{
        BLE_PACKET_LEN, EspBleHostResources, build_ble_controller,
        run_ble_peripheral_encrypted_with_bond_store_using_resources, start_ble_rtos,
    },
    ble_ingress::SharedBleIngressFrontend,
    board_ui::presence_led,
    ingress::SharedArbiter,
    internal_ingress::{SharedInternalIngressFrontend, run_internal_uart},
    presence::EspTextPresenceObserver,
    shared_fido::{
        EspPinUvAuth, SelectedSharedEspKeyStore, build_shared_dispatcher_with_observer_from_parts,
    },
    storage::{EspFlashBondStore, SharedEspFlashCredentialStorage, new_shared_esp_flash},
};
use static_cell::StaticCell;

#[cfg(feature = "up-always-present")]
use manekey::presence::AlwaysPresent;
#[cfg(not(feature = "up-always-present"))]
use manekey_esp32::board_ui::presence_button;
#[cfg(feature = "ble-dual-core")]
compile_error!("NodeMCU rev1 Internal product is single-core only");
#[cfg(all(feature = "flash-managed-keys", feature = "board-devkit-v1"))]
compile_error!("NodeMCU managed geometry is not the DEVKIT V1 OTA layout");

#[cfg(feature = "up-always-present")]
type Presence = AlwaysPresent;
#[cfg(not(feature = "up-always-present"))]
type Presence = manekey_esp32::presence::EspGpioUserPresence<'static>;
type Dispatcher = TrustedDispatcher<
    SharedEspFlashCredentialStorage<'static>,
    Presence,
    manekey::ctaphid::user_verification::UnavailableUserVerification,
    EspPinUvAuth,
    SelectedSharedEspKeyStore,
    manekey_esp32::entropy::EspEntropy,
    UiPresenceObserver<EspTextPresenceObserver, manekey_esp32::ui::EspGpioUiOutput>,
>;
#[cfg(feature = "ble-dual-task")]
type Backend = manekey::boundary::mailbox_backend::MailboxTrustedBackend<
    manekey::boundary::mailbox::LocalMailboxTransport<
        'static,
        { manekey::ctaphid::trusted::TRUSTED_REQUEST_MAX },
        TRUSTED_RESPONSE_MAX,
    >,
>;
#[cfg(not(feature = "ble-dual-task"))]
type Backend = Dispatcher;
const FRAME_MAX: usize = 1024 + HEADER_LEN + TRAILER_LEN;
const RESPONSE_MAX: usize = TRUSTED_RESPONSE_MAX + HEADER_LEN + TRAILER_LEN;
type Internal = SharedInternalIngressFrontend<Backend, FRAME_MAX>;
#[cfg(feature = "ble-dual-task")]
static MAILBOX: manekey_esp32::mailbox::EspMailboxEndpoint =
    manekey_esp32::mailbox::EspMailboxEndpoint::new();
static ARBITER: StaticCell<SharedArbiter<Backend>> = StaticCell::new();
static INTERNAL: StaticCell<Internal> = StaticCell::new();
static RESPONSE: StaticCell<[u8; RESPONSE_MAX]> = StaticCell::new();
esp_bootloader_esp_idf::esp_app_desc!();

#[embassy_executor::task]
async fn uart_task(
    uart: Uart<'static, Async>,
    frontend: &'static mut Internal,
    response: &'static mut [u8; RESPONSE_MAX],
) {
    run_internal_uart(uart, frontend, response).await;
}

#[cfg(feature = "ble-dual-task")]
#[embassy_executor::task]
async fn trusted_task(
    worker: &'static mut manekey_esp32::mailbox::EspLocalTrustedWorker<Dispatcher>,
) {
    manekey_esp32::mailbox::run_local_trusted_worker(worker, &MAILBOX).await;
}

#[esp_rtos::main]
async fn main(spawner: Spawner) {
    esp_println::logger::init_logger(log::LevelFilter::Info);
    let p = esp_hal::init(esp_hal::Config::default().with_cpu_clock(CpuClock::_160MHz));

    esp_alloc::heap_allocator!(#[esp_hal::ram(reclaimed)] size: 40 * 1024);
    start_ble_rtos(p.TIMG0, p.SW_INTERRUPT);
    let _entropy = TrngSource::new(p.RNG, p.ADC1);

    static FLASH: StaticCell<manekey_esp32::storage::SharedEspFlash<'static>> = StaticCell::new();
    let flash = FLASH.init_with(|| new_shared_esp_flash(p.FLASH));
    #[cfg(feature = "up-always-present")]
    let presence = {
        let _ = p.GPIO0;
        AlwaysPresent
    };
    #[cfg(not(feature = "up-always-present"))]
    let presence = presence_button(p.GPIO0);
    let dispatcher = build_shared_dispatcher_with_observer_from_parts(
        flash,
        presence,
        p.SHA,
        p.AES,
        manekey::transport::BLE_TRANSPORTS,
        UiPresenceObserver::new(EspTextPresenceObserver, presence_led(p.GPIO2)),
    );
    #[cfg(feature = "ble-dual-task")]
    let backend = {
        static WORKER: StaticCell<manekey_esp32::mailbox::EspLocalTrustedWorker<Dispatcher>> =
            StaticCell::new();
        let worker =
            WORKER.init_with(|| manekey_esp32::mailbox::EspLocalTrustedWorker::new(dispatcher));
        spawner.spawn(trusted_task(worker).unwrap());
        Backend::new(manekey::boundary::mailbox::LocalMailboxTransport::new(
            &MAILBOX,
        ))
    };
    #[cfg(not(feature = "ble-dual-task"))]
    let backend = dispatcher;
    let arbiter = ARBITER.init_with(|| Mutex::new(RefCell::new(IngressArbiter::new(backend))));
    let internal = INTERNAL.init_with(|| Internal::new(2, arbiter));
    let uart = Uart::new(
        p.UART2,
        UartConfig::default()
            .with_baudrate(115_200)
            .with_rx(RxConfig::default().with_fifo_full_threshold(1)),
    )
    .unwrap()
    .with_tx(p.GPIO17)
    .with_rx(p.GPIO16)
    .into_async();
    spawner.spawn(uart_task(uart, internal, RESPONSE.init([0; RESPONSE_MAX])).unwrap());
    let mut ble =
        SharedBleIngressFrontend::new(BLE_PACKET_LEN, IngressId::new(IngressKind::Ble, 0), arbiter);
    static RESOURCES: StaticCell<EspBleHostResources> = StaticCell::new();
    let resources = RESOURCES.init_with(EspBleHostResources::new);
    println!(
        "ESP32 Internal UART2 P17 TX/P16 RX + BLE ready; always-up={}",
        cfg!(feature = "up-always-present")
    );
    run_ble_peripheral_encrypted_with_bond_store_using_resources(
        build_ble_controller(p.BT),
        Output::new(p.GPIO25, Level::Low, Default::default()),
        &mut ble,
        EspFlashBondStore::new(flash),
        resources,
    )
    .await;
}
