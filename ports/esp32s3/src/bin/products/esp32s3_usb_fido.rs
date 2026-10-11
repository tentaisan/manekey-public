#![no_std]
#![no_main]

use core::sync::atomic::AtomicU32;

use embassy_executor::Spawner;
use esp_alloc as _;
use esp_backtrace as _;
use esp_hal::{
    interrupt::software::SoftwareInterruptControl,
    rng::TrngSource,
    system::{CpuControl, Stack},
    timer::timg::TimerGroup,
    usb::otg::{
        Usb,
        embassy_usb_device::{Config as UsbConfig, Driver},
    },
};
use esp_println::println;
#[cfg(not(feature = "client-pin-flash"))]
use esp32s3::fido::build_usb_dispatcher_from_parts;
use esp32s3::{
    app_core::AppCoreTrustedWorker, board::USB_IDENTITY, ctaphid_usb::run_esp32s3_ctaphid_usb,
};
#[cfg(feature = "client-pin-flash")]
use esp32s3::{
    fido::build_usb_flash_dispatcher_from_parts,
    storage::{SharedEspFlash, new_multicore_shared_esp_flash},
};
use manekey::boundary::mailbox::MailboxEndpoint;
use manekey::ctaphid::trusted::{TRUSTED_REQUEST_MAX, TRUSTED_RESPONSE_MAX};
use static_cell::StaticCell;

static EP_OUT_BUFFER: StaticCell<[u8; 1024]> = StaticCell::new();
#[cfg(all(
    not(feature = "experimental-ml-dsa-fips204"),
    not(feature = "client-pin-flash")
))]
const APP_CORE_STACK_BYTES: usize = 32 * 1024;
#[cfg(all(
    not(feature = "experimental-ml-dsa-fips204"),
    feature = "client-pin-flash"
))]
const APP_CORE_STACK_BYTES: usize = 64 * 1024;
#[cfg(feature = "experimental-ml-dsa-fips204")]
const APP_CORE_STACK_BYTES: usize = 192 * 1024;
static APP_CORE_STACK: StaticCell<Stack<APP_CORE_STACK_BYTES>> = StaticCell::new();
static APP_CORE_MARKER: AtomicU32 = AtomicU32::new(0);
static TRUSTED_ENDPOINT: MailboxEndpoint<TRUSTED_REQUEST_MAX, TRUSTED_RESPONSE_MAX> =
    MailboxEndpoint::new();
#[cfg(feature = "client-pin-flash")]
static FLASH: StaticCell<SharedEspFlash<'static>> = StaticCell::new();

esp_bootloader_esp_idf::esp_app_desc!();

#[esp_hal::main]
/// Software APP-core mailbox product, not PMS RAM isolation; retain guard and exclusive endpoint ownership.
async fn main(_spawner: Spawner) {
    let peripherals = esp_hal::init(esp_hal::Config::default());
    #[cfg(all(
        not(feature = "experimental-ml-dsa-fips204"),
        not(feature = "client-pin-flash")
    ))]
    esp_alloc::heap_allocator!(size: 96 * 1024);
    #[cfg(all(
        not(feature = "experimental-ml-dsa-fips204"),
        feature = "client-pin-flash"
    ))]
    esp_alloc::heap_allocator!(size: 64 * 1024);
    #[cfg(feature = "experimental-ml-dsa-fips204")]
    esp_alloc::heap_allocator!(size: 32 * 1024);
    println!("MANEKEY ESP32-S3 USB FIDO");
    let _trng_source = TrngSource::new(peripherals.RNG, peripherals.ADC1);

    let sw_int = SoftwareInterruptControl::new(peripherals.SW_INTERRUPT);
    let timg0 = TimerGroup::new(peripherals.TIMG0);
    esp_rtos::start(timg0.timer0, sw_int.software_interrupt0);

    let usb = Usb::new_fs(peripherals.USB_FS, peripherals.GPIO20, peripherals.GPIO19);
    let driver = Driver::new(usb, EP_OUT_BUFFER.init([0; 1024]), UsbConfig::default());
    #[cfg(feature = "client-pin-flash")]
    let flash = FLASH.init(new_multicore_shared_esp_flash(peripherals.FLASH));
    #[cfg(feature = "client-pin-flash")]
    let dispatcher = build_usb_flash_dispatcher_from_parts(
        flash,
        peripherals.GPIO2,
        peripherals.SHA,
        peripherals.AES,
    );
    #[cfg(not(feature = "client-pin-flash"))]
    let dispatcher = build_usb_dispatcher_from_parts(
        peripherals.FLASH,
        peripherals.GPIO2,
        peripherals.SHA,
        peripherals.AES,
    );
    let mut cpu_control = CpuControl::new(peripherals.CPU_CTRL);
    let app_core_worker = AppCoreTrustedWorker::new(
        APP_CORE_STACK.init(Stack::new()),
        &TRUSTED_ENDPOINT,
        &APP_CORE_MARKER,
    );
    let _app_core_guard = match app_core_worker.start(&mut cpu_control, dispatcher, 4) {
        Ok((guard, marker)) => {
            println!("ESP32-S3 APP trusted worker marker={marker}");
            guard
        }
        Err(_) => {
            println!("ESP32-S3 APP core start failed");
            loop {
                core::hint::spin_loop();
            }
        }
    };
    run_esp32s3_ctaphid_usb(driver, &TRUSTED_ENDPOINT, &USB_IDENTITY).await
}
