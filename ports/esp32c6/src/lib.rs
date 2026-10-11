#![no_std]

#[cfg(feature = "ble")]
#[path = "../../esp-common/src/ingress.rs"]
pub mod ingress;

#[cfg(all(
    feature = "ml-dsa-fips204-backend",
    feature = "ml-dsa-mldsa-native-backend"
))]
compile_error!("select exactly one ESP32-C6 ML-DSA backend");

#[cfg(feature = "ble")]
#[path = "../../esp-common/src/ble_fido.rs"]
pub mod ble_fido;
#[cfg(feature = "ble")]
#[path = "../../esp-common/src/ble_ingress.rs"]
pub mod ble_ingress;
pub mod board;
#[cfg(feature = "client-pin-volatile")]
#[path = "../../esp-common/src/client_pin.rs"]
pub mod client_pin;
#[path = "../../esp-common/src/crypto.rs"]
pub mod crypto;

#[path = "../../esp-common/src/entropy.rs"]
pub mod entropy;
pub mod fido;
#[path = "../../esp-common/src/flash_region.rs"]
pub mod flash_region;
#[cfg(feature = "ble")]
#[path = "../../esp-common/src/internal_ingress.rs"]
pub mod internal_ingress;
#[cfg(feature = "ble")]
#[path = "../../esp-common/src/mailbox.rs"]
pub mod mailbox;
#[cfg(feature = "flash-managed-keys")]
#[path = "../../esp-common/src/managed_key_storage.rs"]
pub mod managed_key_storage;

#[cfg(feature = "p256-ecc")]
pub mod p256;
#[cfg(any(feature = "client-pin-flash", feature = "pmp-persistent-pin"))]
#[path = "../../esp-common/src/pin_flash_storage.rs"]
pub mod pin_flash_storage;
pub mod pmp_boundary;
pub mod pmp_local_adapter;
pub mod pmp_monitor;
pub mod pmp_runtime;
#[path = "../../esp-common/src/presence.rs"]
pub mod presence;
#[cfg(any(feature = "ble-security", feature = "shared-flash"))]
#[path = "../../esp-common/src/shared_flash_storage.rs"]
pub mod shared_flash_storage;
#[path = "../../esp-common/src/storage.rs"]
pub mod storage;
#[path = "../../esp-common/src/ui.rs"]
pub mod ui;
