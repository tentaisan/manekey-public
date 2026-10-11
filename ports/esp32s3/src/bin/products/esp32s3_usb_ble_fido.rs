#![no_std]
#![no_main]

#[cfg(any(feature = "large-response-layout", feature = "usb-ccid-experimental"))]
use core::mem::MaybeUninit;

use core::cell::RefCell;
#[cfg(feature = "usb-ble-dual-core")]
use core::sync::atomic::AtomicU32;

use embassy_futures::join::join;
use embassy_sync::blocking_mutex::{Mutex, raw::NoopRawMutex};
use esp_alloc as _;
use esp_backtrace as _;
#[cfg(feature = "usb-ble-dual-core")]
use esp_hal::system::{CpuControl, Stack};
#[cfg(feature = "managed-internal-uart")]
use esp_hal::{
    Async,
    uart::{ClockSource, Config as UartConfig, RxConfig, Uart},
};
use esp_hal::{
    clock::CpuClock,
    efuse,
    gpio::{Level, Output},
    rng::TrngSource,
    usb::otg::{
        Usb,
        embassy_usb_device::{Config as UsbConfig, Driver},
    },
};
use esp_println::println;
#[cfg(any(feature = "usb-ble-dual-task", feature = "usb-ble-dual-core"))]
use esp32s3::esp_local_mailbox::EspMailboxEndpoint;
#[cfg(feature = "usb-ble-dual-task")]
use esp32s3::esp_local_mailbox::{EspLocalTrustedWorker, run_local_trusted_worker};
#[cfg(all(feature = "usb-ble-dual-task", feature = "up-always-present"))]
use esp32s3::fido::EspAlwaysSharedTrustedDispatcher as EspSharedTrustedDispatcher;
#[cfg(all(feature = "usb-ble-dual-task", not(feature = "up-always-present")))]
use esp32s3::fido::EspSharedTrustedDispatcher;
#[cfg(feature = "up-always-present")]
use esp32s3::fido::build_usb_ble_direct_dispatcher_always_present_from_parts;
#[cfg(all(not(feature = "board-ui"), not(feature = "up-always-present")))]
use esp32s3::fido::build_usb_ble_direct_dispatcher_from_parts;
#[cfg(feature = "managed-internal-uart")]
use esp32s3::multi_transport::MultiInternalFrontend;
#[cfg(not(feature = "usb-ble-dual-core"))]
use esp32s3::storage::new_shared_esp_flash;
#[cfg(feature = "usb-ccid-experimental")]
use esp32s3::usb_composite::CcidIoBuffers;
#[cfg(feature = "usb-ble-dual-core")]
use esp32s3::{app_core::AppCoreTrustedWorker, storage::new_multicore_shared_esp_flash};
use esp32s3::{
    ble_fido::{
        build_ble_controller, profile_for_esp_mac,
        run_ble_peripheral_encrypted_with_profile_and_bond_store, start_ble_rtos,
    },
    board::USB_IDENTITY,
    ctaphid_usb::run_esp32s3_ctaphid_usb_multi,
    multi_transport::{MultiUsbFrontend, SharedArbiter, build_ble_frontend},
    storage::{EspFlashBondStore, SharedEspFlash},
};
#[cfg(all(feature = "board-ui", not(feature = "up-always-present")))]
use esp32s3::{board_ui::run_status_pixel, fido::build_usb_ble_direct_dispatcher_with_boot};
#[cfg(feature = "managed-internal-uart")]
use manekey::{
    ctaphid::trusted::TRUSTED_RESPONSE_MAX,
    transport::interconnect::{HEADER_LEN, TRAILER_LEN},
};

#[cfg(all(feature = "managed-internal-uart", feature = "log-uart"))]
compile_error!("Internal UART owns the WCH COM link; select log-jtag-serial");
#[cfg(feature = "managed-internal-uart")]
const INTERNAL_FRAME_MAX: usize = 1024 + HEADER_LEN + TRAILER_LEN;
#[cfg(feature = "managed-internal-uart")]
const INTERNAL_RESPONSE_MAX: usize = TRUSTED_RESPONSE_MAX + HEADER_LEN + TRAILER_LEN;
#[cfg(feature = "managed-internal-uart")]
static INTERNAL: StaticCell<MultiInternalFrontend<INTERNAL_FRAME_MAX>> = StaticCell::new();
#[cfg(feature = "managed-internal-uart")]
static INTERNAL_RESPONSE: StaticCell<[u8; INTERNAL_RESPONSE_MAX]> = StaticCell::new();
#[cfg(any(feature = "usb-ble-dual-task", feature = "usb-ble-dual-core"))]
use manekey::boundary::{mailbox::LocalMailboxTransport, mailbox_backend::MailboxTrustedBackend};
use manekey::frontend::ingress::IngressArbiter;
use static_cell::StaticCell;

static EP_OUT_BUFFER: StaticCell<[u8; 1024]> = StaticCell::new();
static FLASH: StaticCell<SharedEspFlash<'static>> = StaticCell::new();
#[cfg(all(feature = "usb-ble-dual-task", feature = "usb-ble-dual-core"))]
compile_error!("S3 dual-task and dual-core are separate boundary configurations");
#[cfg(all(
    feature = "up-always-present",
    any(feature = "usb-ble-dual-task", feature = "usb-ble-dual-core"),
    not(feature = "flash-managed-keys")
))]
compile_error!("S3 Always-UP is limited to the direct transport experiment");
#[cfg(all(feature = "up-always-present", feature = "board-ui"))]
compile_error!("S3 Always-UP does not carry the physical GPIO/LED board UI");

#[cfg(any(feature = "usb-ble-dual-task", feature = "usb-ble-dual-core"))]
static MAILBOX: EspMailboxEndpoint = EspMailboxEndpoint::new();
#[cfg(feature = "usb-ble-dual-task")]
static WORKER: StaticCell<EspLocalTrustedWorker<EspSharedTrustedDispatcher>> = StaticCell::new();
#[cfg(feature = "usb-ble-dual-core")]
const APP_CORE_STACK_SIZE: usize = if cfg!(feature = "flash-managed-keys") {
    96 * 1024
} else {
    64 * 1024
};
#[cfg(feature = "usb-ble-dual-core")]
static APP_CORE_STACK: StaticCell<Stack<APP_CORE_STACK_SIZE>> = StaticCell::new();
#[cfg(feature = "usb-ble-dual-core")]
static APP_CORE_MARKER: AtomicU32 = AtomicU32::new(0);
#[cfg(feature = "usb-ccid-experimental")]
#[unsafe(link_section = ".dram2_uninit")]
static mut CCID_BUFFERS: MaybeUninit<CcidIoBuffers> = MaybeUninit::uninit();
#[cfg(not(feature = "large-response-layout"))]
static ARBITER: StaticCell<SharedArbiter> = StaticCell::new();

#[cfg(feature = "large-response-layout")]
#[unsafe(link_section = ".dram2_uninit")]
static mut ARBITER: MaybeUninit<StaticCell<SharedArbiter>> = MaybeUninit::uninit();
#[cfg(all(
    feature = "large-response-layout",
    not(feature = "usb-ccid-experimental")
))]
const ML_DSA_HEAP_SIZE: usize = 48 * 1024;
#[cfg(all(
    feature = "large-response-layout",
    feature = "usb-ccid-experimental",
    not(feature = "flash-managed-keys")
))]
const ML_DSA_HEAP_SIZE: usize = 40 * 1024;
#[cfg(all(
    feature = "large-response-layout",
    feature = "usb-ccid-experimental",
    feature = "flash-managed-keys"
))]
const ML_DSA_HEAP_SIZE: usize = 39 * 1024;

#[cfg(feature = "large-response-layout")]
#[unsafe(link_section = ".dram2_uninit")]
static mut ML_DSA_HEAP: MaybeUninit<[u8; ML_DSA_HEAP_SIZE]> = MaybeUninit::uninit();

esp_bootloader_esp_idf::esp_app_desc!();

#[cfg(all(
    any(feature = "usb-ble-dual-task", feature = "usb-ble-dual-core"),
    not(feature = "flash-managed-keys"),
    any(
        feature = "experimental-ml-dsa-fips204",
        feature = "usb-ccid-experimental"
    )
))]
compile_error!("S3 mailbox ML-DSA/CCID needs a separate memory and response-size review");

#[cfg(feature = "managed-internal-uart")]
#[embassy_executor::task]
async fn internal_uart_task(
    uart: Uart<'static, Async>,
    frontend: &'static mut MultiInternalFrontend<INTERNAL_FRAME_MAX>,
    response: &'static mut [u8; INTERNAL_RESPONSE_MAX],
) {
    esp32s3::internal_ingress::run_internal_uart(uart, frontend, response).await;
}

#[cfg(feature = "usb-ble-dual-task")]
#[embassy_executor::task]
async fn trusted_task(worker: &'static mut EspLocalTrustedWorker<EspSharedTrustedDispatcher>) {
    run_local_trusted_worker(worker, &MAILBOX).await;
}

#[esp_rtos::main]
/// Cooperative or APP-core product, not PMS isolation.
/// Port must reserve NOLOAD buffers exclusively and initialize them once before shared use.
async fn main(spawner: embassy_executor::Spawner) {
    #[cfg(not(any(feature = "usb-ble-dual-task", feature = "managed-internal-uart")))]
    let _ = spawner;
    esp_println::logger::init_logger(log::LevelFilter::Info);
    println!("MANEKEY ESP32-S3 USB/BLE FIDO boot");
    let peripherals = esp_hal::init(esp_hal::Config::default().with_cpu_clock(CpuClock::max()));
    #[cfg(not(feature = "large-response-layout"))]
    esp_alloc::heap_allocator!(size: 64 * 1024);
    #[cfg(feature = "large-response-layout")]
    unsafe {
        esp_alloc::HEAP.add_region(esp_alloc::HeapRegion::new(
            (&raw mut ML_DSA_HEAP).cast::<u8>(),
            ML_DSA_HEAP_SIZE,
            esp_alloc::MemoryCapability::Internal.into(),
        ));
    }
    let _trng_source = TrngSource::new(peripherals.RNG, peripherals.ADC1);
    start_ble_rtos(peripherals.TIMG0, peripherals.SW_INTERRUPT);

    let usb = Usb::new_fs(peripherals.USB_FS, peripherals.GPIO20, peripherals.GPIO19);
    let driver = Driver::new(usb, EP_OUT_BUFFER.init([0; 1024]), UsbConfig::default());
    #[cfg(not(feature = "usb-ble-dual-core"))]
    let flash: &'static SharedEspFlash<'static> =
        FLASH.init(new_shared_esp_flash(peripherals.FLASH));
    #[cfg(feature = "usb-ble-dual-core")]
    let flash: &'static SharedEspFlash<'static> =
        FLASH.init(new_multicore_shared_esp_flash(peripherals.FLASH));
    #[cfg(all(not(feature = "board-ui"), not(feature = "up-always-present")))]
    let dispatcher = build_usb_ble_direct_dispatcher_from_parts(
        flash,
        peripherals.GPIO2,
        peripherals.SHA,
        peripherals.AES,
    );
    #[cfg(all(feature = "board-ui", not(feature = "up-always-present")))]
    let dispatcher = build_usb_ble_direct_dispatcher_with_boot(
        flash,
        peripherals.GPIO0,
        peripherals.SHA,
        peripherals.AES,
    );
    #[cfg(feature = "up-always-present")]
    let dispatcher = build_usb_ble_direct_dispatcher_always_present_from_parts(
        flash,
        peripherals.SHA,
        peripherals.AES,
    );
    #[cfg(feature = "usb-ble-dual-task")]
    let backend = {
        spawner.spawn(trusted_task(WORKER.init(EspLocalTrustedWorker::new(dispatcher))).unwrap());
        MailboxTrustedBackend::new(LocalMailboxTransport::new(&MAILBOX))
    };
    #[cfg(feature = "usb-ble-dual-core")]
    let _app_core_guard = {
        let mut cpu_control = CpuControl::new(peripherals.CPU_CTRL);
        let app_core_worker = AppCoreTrustedWorker::new(
            APP_CORE_STACK.init(Stack::new()),
            &MAILBOX,
            &APP_CORE_MARKER,
        );
        match app_core_worker.start(&mut cpu_control, dispatcher, 4) {
            Ok((guard, marker)) => {
                println!("ESP32-S3 APP trusted worker marker={marker}");
                guard
            }
            Err(_) => {
                println!("ESP32-S3 APP core start failed");
                core::future::pending::<()>().await;
                unreachable!()
            }
        }
    };
    #[cfg(feature = "usb-ble-dual-core")]
    let backend = MailboxTrustedBackend::new(LocalMailboxTransport::new(&MAILBOX));
    #[cfg(not(any(feature = "usb-ble-dual-task", feature = "usb-ble-dual-core")))]
    let backend = dispatcher;
    #[cfg(not(feature = "large-response-layout"))]
    let arbiter_cell = &ARBITER;
    #[cfg(feature = "large-response-layout")]
    let arbiter_cell = unsafe {
        let cell = (&raw mut ARBITER).cast::<StaticCell<SharedArbiter>>();
        cell.write(StaticCell::new());
        &*cell
    };
    let arbiter = arbiter_cell.init(Mutex::<NoopRawMutex, _>::new(RefCell::new(
        IngressArbiter::new(backend),
    )));
    #[cfg(feature = "managed-internal-uart")]
    {
        let uart = Uart::new(
            peripherals.UART0,
            UartConfig::default()
                .with_baudrate(115_200)
                .with_clock_source(ClockSource::Xtal)
                .with_rx(RxConfig::default().with_fifo_full_threshold(1)),
        )
        .expect("UART0 configuration")
        .with_tx(peripherals.GPIO43)
        .with_rx(peripherals.GPIO44)
        .into_async();
        spawner.spawn(
            internal_uart_task(
                uart,
                INTERNAL.init(MultiInternalFrontend::new(0, arbiter)),
                INTERNAL_RESPONSE.init([0; INTERNAL_RESPONSE_MAX]),
            )
            .unwrap(),
        );
    }

    let profile = profile_for_esp_mac(
        efuse::base_mac_address()
            .as_bytes()
            .try_into()
            .expect("ESP base MAC has six bytes"),
    );
    let led = Output::new(peripherals.GPIO21, Level::Low, Default::default());
    let controller = build_ble_controller(peripherals.BT);
    let mut usb_fido = MultiUsbFrontend::new(arbiter);
    let ble_fido = build_ble_frontend(arbiter);
    println!("USB/BLE FIDO frontends initialized");

    #[cfg(feature = "usb-ccid-experimental")]
    let ccid_buffers = unsafe {
        let ptr = (&raw mut CCID_BUFFERS).cast::<CcidIoBuffers>();

        ptr.write(CcidIoBuffers::new());
        &mut *ptr
    };
    let usb_task = run_esp32s3_ctaphid_usb_multi(
        driver,
        &mut usb_fido,
        &USB_IDENTITY,
        #[cfg(feature = "usb-ccid-experimental")]
        ccid_buffers,
    );
    let ble_task = run_ble_peripheral_encrypted_with_profile_and_bond_store(
        controller,
        led,
        ble_fido,
        profile,
        EspFlashBondStore::new(flash),
    );
    #[cfg(not(feature = "board-ui"))]
    join(usb_task, ble_task).await;
    #[cfg(all(feature = "board-ui", not(any())))]
    join(
        join(usb_task, ble_task),
        run_status_pixel(peripherals.RMT, peripherals.GPIO48),
    )
    .await;

    unreachable!()
}
