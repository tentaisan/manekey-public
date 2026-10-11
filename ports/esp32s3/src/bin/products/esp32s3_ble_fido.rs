#![no_std]
#![no_main]

use embassy_executor::Spawner;
use esp_alloc as _;
use esp_backtrace as _;
use esp_hal::{
    clock::CpuClock,
    efuse,
    gpio::{Level, Output},
    rng::TrngSource,
};
use esp_println::println;
#[cfg(feature = "ble-security")]
use esp32s3::ble_fido::run_ble_peripheral_encrypted_with_profile_and_bond_store;
#[cfg(not(feature = "ble-security"))]
use esp32s3::ble_fido::run_ble_peripheral_with_profile;
use esp32s3::ble_fido::{
    BLE_PACKET_LEN, build_ble_controller, profile_for_esp_mac, start_ble_rtos,
};

#[cfg(not(feature = "ble-security"))]
use esp32s3::fido::build_ble_fido_frontend_from_parts;
#[cfg(feature = "ble-security")]
use esp32s3::{
    fido::build_ble_secure_fido_frontend_from_parts,
    storage::{EspFlashBondStore, SharedEspFlash, new_shared_esp_flash},
};
#[cfg(feature = "ble-security")]
use static_cell::StaticCell;

esp_bootloader_esp_idf::esp_app_desc!();

#[esp_rtos::main]
async fn main(_spawner: Spawner) {
    esp_println::logger::init_logger(log::LevelFilter::Info);
    println!("MANEKEY ESP32-S3 BLE FIDO boot");
    let peripherals = esp_hal::init(esp_hal::Config::default().with_cpu_clock(CpuClock::max()));
    #[cfg(feature = "client-pin-flash")]
    esp_alloc::heap_allocator!(size: 64 * 1024);
    #[cfg(not(feature = "client-pin-flash"))]
    esp_alloc::heap_allocator!(size: 96 * 1024);

    let led = Output::new(peripherals.GPIO21, Level::Low, Default::default());

    start_ble_rtos(peripherals.TIMG0, peripherals.SW_INTERRUPT);

    let _trng_source = TrngSource::new(peripherals.RNG, peripherals.ADC1);
    let profile = profile_for_esp_mac(
        efuse::base_mac_address()
            .as_bytes()
            .try_into()
            .expect("ESP base MAC has six bytes"),
    );
    #[cfg(feature = "ble-security")]
    static FLASH: StaticCell<SharedEspFlash<'static>> = StaticCell::new();
    #[cfg(feature = "ble-security")]
    let flash = FLASH.init(new_shared_esp_flash(peripherals.FLASH));
    #[cfg(feature = "ble-security")]
    let ble_fido = build_ble_secure_fido_frontend_from_parts(
        flash,
        peripherals.GPIO2,
        peripherals.SHA,
        peripherals.AES,
        BLE_PACKET_LEN,
    );
    #[cfg(not(feature = "ble-security"))]
    let ble_fido = build_ble_fido_frontend_from_parts(
        peripherals.FLASH,
        peripherals.GPIO2,
        peripherals.SHA,
        peripherals.AES,
        BLE_PACKET_LEN,
    );

    let controller = build_ble_controller(peripherals.BT);

    #[cfg(feature = "ble-security")]
    run_ble_peripheral_encrypted_with_profile_and_bond_store(
        controller,
        led,
        ble_fido,
        profile,
        EspFlashBondStore::new(flash),
    )
    .await;
    #[cfg(not(feature = "ble-security"))]
    run_ble_peripheral_with_profile(controller, led, ble_fido, profile).await;
}
