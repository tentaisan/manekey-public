#![no_std]
#![no_main]

#[cfg(feature = "client-pin-flash")]
compile_error!("client-pin-flash requires esp32c6_ble_secure_fido's shared flash dispatcher");

use core::mem::MaybeUninit;

use embassy_executor::Spawner;
use esp_alloc as _;
use esp_backtrace as _;
use esp_hal::{
    clock::CpuClock,
    gpio::{Level, Output},
    rng::TrngSource,
};
use esp_println::println;

use esp32c6::{
    ble_fido::{BLE_PACKET_LEN, build_ble_controller, run_ble_peripheral, start_ble_rtos},
    fido::{EspTrustedDispatcher, build_ble_dispatcher_from_parts},
    pmp_boundary::{self, BoundaryLayout, TorRegion},
    pmp_local_adapter::{C6PmpMonitorBackend, C6PmpSharedCallState},
    pmp_monitor,
};
use manekey::transport::ble::BleFidoFrontend;

esp_bootloader_esp_idf::esp_app_desc!();

#[unsafe(link_section = ".c6_pmp_shared")]
static mut PMP_SHARED_CALL: C6PmpSharedCallState = C6PmpSharedCallState::new();

#[unsafe(link_section = ".c6_pmp_machine_private")]
static mut TRUSTED_DISPATCHER: MaybeUninit<EspTrustedDispatcher> = MaybeUninit::uninit();

unsafe extern "C" {
    static __c6_pmp_user_text_start: u8;
    static __c6_pmp_user_text_end: u8;
    static __c6_pmp_shared_start: u8;
    static __c6_pmp_shared_end: u8;
    static __c6_pmp_machine_private_start: u8;
    static __c6_pmp_machine_private_end: u8;
}

#[esp_rtos::main]
/// Descriptor bridge only: BLE, RTOS and CTAP remain M-mode; no U-mode BLE isolation.
/// Initialize reserved NOLOAD state once before exclusive use.
async fn main(_spawner: Spawner) {
    esp_println::logger::init_logger(log::LevelFilter::Info);
    println!("MANEKEY ESP32-C6 BLE PMP FIDO boot");
    println!("BLE PMP: BLE runtime stays in M-mode; CTAP backend uses PMP monitor ABI");
    let peripherals = esp_hal::init(esp_hal::Config::default().with_cpu_clock(CpuClock::max()));
    esp_alloc::heap_allocator!(size: 96 * 1024);

    #[allow(unused_mut)]
    let mut led = Output::new(peripherals.GPIO21, Level::Low, Default::default());

    start_ble_rtos(peripherals.TIMG0, peripherals.SW_INTERRUPT);

    let _trng_source = TrngSource::new(peripherals.RNG, peripherals.ADC1);
    let dispatcher = build_ble_dispatcher_from_parts(
        peripherals.FLASH,
        peripherals.GPIO2,
        peripherals.SHA,
        peripherals.AES,
        peripherals.ECC,
    );
    unsafe {
        (&raw mut TRUSTED_DISPATCHER).write(MaybeUninit::new(dispatcher));
    }
    install_boundary();

    let shared_memory = pmp_monitor::shared_memory_region(
        (&raw const __c6_pmp_shared_start).cast(),
        (&raw const __c6_pmp_shared_end).cast(),
    );
    let shared = unsafe {
        (&raw mut PMP_SHARED_CALL)
            .as_mut()
            .expect("PMP shared call state must exist")
    };
    let trusted = unsafe {
        (&raw mut TRUSTED_DISPATCHER)
            .cast::<EspTrustedDispatcher>()
            .as_mut()
            .expect("trusted dispatcher must be initialized")
    };
    let backend = unsafe { C6PmpMonitorBackend::new(shared_memory, shared, trusted) };
    let ble_fido = BleFidoFrontend::new(BLE_PACKET_LEN, backend);

    let controller = build_ble_controller(peripherals.BT);

    run_ble_peripheral(controller, led, ble_fido).await;
}

fn install_boundary() {
    let user_text_start = (&raw const __c6_pmp_user_text_start) as usize;
    let user_text_end = (&raw const __c6_pmp_user_text_end) as usize;
    let shared_start = (&raw const __c6_pmp_shared_start) as usize;
    let shared_end = (&raw const __c6_pmp_shared_end) as usize;
    let machine_private_start = (&raw const __c6_pmp_machine_private_start) as usize;
    let machine_private_end = (&raw const __c6_pmp_machine_private_end) as usize;

    #[allow(unused_variables)]
    let readback = unsafe {
        pmp_boundary::install(BoundaryLayout {
            machine_private: TorRegion {
                start: machine_private_start,
                end: machine_private_end,
            },
            shared: TorRegion {
                start: shared_start,
                end: shared_end,
            },
            user_text: TorRegion {
                start: user_text_start,
                end: user_text_end,
            },
        })
    };
}
