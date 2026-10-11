#![no_std]

#[cfg(any(feature = "usb-ble-multi", feature = "usb-ccid-experimental"))]
#[path = "../../esp-common/src/ingress.rs"]
pub mod ingress;

#[path = "../../esp-common/src/app_core.rs"]
pub mod app_core;
#[cfg(feature = "ble")]
#[path = "../../esp-common/src/ble_fido.rs"]
pub mod ble_fido;
#[cfg(feature = "usb-ble-multi")]
#[path = "../../esp-common/src/ble_ingress.rs"]
pub mod ble_ingress;
pub mod board;
#[cfg(feature = "board-ui")]
pub mod board_ui;
#[path = "../../esp-common/src/crypto.rs"]
pub mod crypto;
#[cfg(feature = "usb-hid")]
pub mod ctaphid_usb;

pub mod entropy;
#[cfg(any(feature = "usb-ble-dual-task", feature = "usb-ble-dual-core"))]
#[path = "../../esp-common/src/mailbox.rs"]
pub mod esp_local_mailbox;
#[path = "../../esp-common/src/fido.rs"]
pub mod fido;
#[path = "../../esp-common/src/flash_region.rs"]
pub mod flash_region;
#[cfg(feature = "managed-internal-uart")]
#[path = "../../esp-common/src/internal_ingress.rs"]
pub mod internal_ingress;
pub mod mailbox;
#[cfg(feature = "flash-managed-keys")]
#[path = "../../esp-common/src/managed_key_storage.rs"]
pub mod managed_key_storage;
#[cfg(feature = "experimental-ml-dsa-fips204-scratch")]
pub mod ml_dsa_scratch;
#[cfg(feature = "usb-ble-multi")]
pub mod multi_transport;
#[cfg(feature = "client-pin-flash")]
#[path = "../../esp-common/src/pin_flash_storage.rs"]
pub mod pin_flash_storage;
#[path = "../../esp-common/src/presence.rs"]
pub mod presence;
#[cfg(any(feature = "ble-security", feature = "client-pin-flash"))]
#[path = "../../esp-common/src/shared_flash_storage.rs"]
pub mod shared_flash_storage;
pub mod storage;
#[path = "../../esp-common/src/ui.rs"]
pub mod ui;
#[cfg(feature = "usb-ble-multi")]
#[path = "../../esp-common/src/usb_composite.rs"]
pub mod usb_composite;
#[cfg(feature = "usb-hid")]
#[path = "../../esp-common/src/usb_hid.rs"]
pub mod usb_hid;
#[cfg(feature = "usb-ble-multi")]
#[path = "../../esp-common/src/usb_ingress.rs"]
pub mod usb_ingress;
