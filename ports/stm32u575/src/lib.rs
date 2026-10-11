#![no_std]

#[cfg(all(feature = "hardware-sha256", feature = "trustzone-nonsecure-image"))]
compile_error!("HASH belongs to Secure; do not link a hardware backend into NS");

pub mod crypto;

pub mod flash_layout;
#[cfg(not(feature = "trustzone-nonsecure-image"))]
pub mod key_store;
#[cfg(all(feature = "flash-managed-keys", feature = "trustzone-nonsecure-image"))]
compile_error!("managed key storage belongs to Secure, not the NS frontend");

#[cfg(all(feature = "hardware-sha256", not(feature = "trustzone-secure-layout")))]
#[path = "../../stm32-common/src/sha256.rs"]
pub mod sha256;

#[cfg(all(
    feature = "trustzone-secure-layout",
    feature = "trustzone-nonsecure-image"
))]
compile_error!("Select exactly one TrustZone image layout");
#[cfg(all(
    feature = "trustzone-usb",
    feature = "trustzone-nonsecure-image",
    feature = "hal-time"
))]
compile_error!("The Non-Secure USB image supplies its own time driver; disable hal-time");

#[cfg(all(
    feature = "trustzone-uart-runtime",
    not(any(
        feature = "trustzone-secure-layout",
        feature = "trustzone-nonsecure-image"
    ))
))]
compile_error!("The UART attribution runtime requires an explicit TrustZone image layout");

#[cfg(feature = "internal-uart")]
#[path = "../../stm32-common/src/internal_uart.rs"]
pub mod internal_uart;
#[cfg(all(feature = "trustzone-usb", feature = "trustzone-nonsecure-image"))]
pub mod nonsecure_usb;
#[cfg(feature = "trustzone-secure-layout")]
pub mod secure_hal;
pub mod storage;
#[cfg(any(
    feature = "trustzone-secure-layout",
    feature = "trustzone-nonsecure-image"
))]
pub mod trustzone;
pub mod ui;
