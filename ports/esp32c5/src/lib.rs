#![no_std]

#[cfg(feature = "adc-entropy")]
pub mod adc_entropy;
#[cfg(feature = "ble")]
#[path = "../../esp-common/src/ble_fido.rs"]
pub mod ble_fido;
#[cfg(feature = "internal-uart")]
#[path = "../../esp-common/src/ble_ingress.rs"]
pub mod ble_ingress;
pub mod board;
#[cfg(feature = "ble")]
pub mod board_ui;
#[cfg(feature = "client-pin-volatile")]
#[path = "../../esp-common/src/client_pin.rs"]
pub mod client_pin;
#[path = "../../esp-common/src/crypto.rs"]
pub mod crypto;
pub mod entropy;
pub mod fido;
#[path = "../../esp-common/src/flash_region.rs"]
pub mod flash_region;
#[cfg(feature = "internal-uart")]
#[path = "../../esp-common/src/ingress.rs"]
pub mod ingress;
#[cfg(feature = "internal-uart")]
#[path = "../../esp-common/src/internal_ingress.rs"]
pub mod internal_ingress;
#[cfg(feature = "ble-dual-task")]
#[path = "../../esp-common/src/mailbox.rs"]
pub mod mailbox;
#[cfg(feature = "flash-managed-keys")]
#[path = "../../esp-common/src/managed_key_storage.rs"]
pub mod managed_key_storage;
#[cfg(any(
    feature = "experimental-ml-dsa-fips204",
    feature = "ble-ml-dsa-native",
    feature = "pmp-internal-uart-ml-dsa"
))]
pub mod ml_dsa_backend;

#[cfg(any(feature = "client-pin-flash", feature = "pmp-persistent-pin"))]
#[path = "../../esp-common/src/pin_flash_storage.rs"]
pub mod pin_flash_storage;
#[cfg(feature = "pmp-baremetal")]
pub mod pmp_boundary;
#[cfg(any(feature = "pmp-baremetal", any()))]
pub mod pmp_memory;
#[cfg(feature = "pmp-baremetal")]
pub mod pmp_monitor;
#[cfg(feature = "pmp-baremetal")]
pub mod pmp_runtime;
#[path = "../../esp-common/src/presence.rs"]
pub mod presence;
#[cfg(any(feature = "ble-security", feature = "shared-flash"))]
#[path = "../../esp-common/src/shared_flash_storage.rs"]
pub mod shared_flash_storage;
#[cfg(any(feature = "ble", feature = "pmp-internal-uart-fido"))]
pub mod status_pixel;
#[path = "../../esp-common/src/storage.rs"]
pub mod storage;
#[path = "../../esp-common/src/ui.rs"]
pub mod ui;
