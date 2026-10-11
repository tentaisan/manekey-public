#![no_std]

#[cfg(feature = "experimental-ml-dsa-fips204-scratch")]
pub mod ml_dsa_scratch;

#[cfg(any(feature = "usb-ccid-experimental", feature = "internal-uart"))]
#[path = "../../esp-common/src/ingress.rs"]
pub mod ingress;
#[cfg(feature = "internal-uart")]
#[path = "../../esp-common/src/internal_ingress.rs"]
pub mod internal_ingress;

#[path = "../../esp-common/src/crypto.rs"]
pub mod crypto;
#[path = "../../esp-common/src/entropy.rs"]
pub mod entropy;
#[path = "../../esp-common/src/fido.rs"]
#[allow(dead_code, unexpected_cfgs)]
pub mod fido;
#[path = "../../esp-common/src/flash_region.rs"]
pub mod flash_region;
#[cfg(feature = "flash-managed-keys")]
#[path = "../../esp-common/src/managed_key_storage.rs"]
pub mod managed_key_storage;
#[cfg(feature = "client-pin-flash")]
#[path = "../../esp-common/src/pin_flash_storage.rs"]
pub mod pin_flash_storage;
#[path = "../../esp-common/src/presence.rs"]
pub mod presence;
#[cfg(feature = "client-pin-flash")]
#[path = "../../esp-common/src/shared_flash_storage.rs"]
pub mod shared_flash_storage;
pub mod storage;
#[path = "../../esp-common/src/ui.rs"]
pub mod ui;
#[cfg(feature = "usb-ccid-experimental")]
#[path = "../../esp-common/src/usb_composite.rs"]
pub mod usb_composite;
#[cfg(feature = "usb-hid")]
#[path = "../../esp-common/src/usb_hid.rs"]
pub mod usb_hid;
#[cfg(feature = "usb-ccid-experimental")]
#[path = "../../esp-common/src/usb_ingress.rs"]
pub mod usb_ingress;

pub mod board {
    use manekey::ctaphid::descriptor::CtaphidUsbDeviceInfo;

    pub const USB_DP_GPIO: u8 = 20;
    pub const USB_DM_GPIO: u8 = 19;
    pub const USER_PRESENCE_GPIO: u8 = 0;
    pub const USER_LED_GPIO: u8 = 13;
    pub const USER_LED_ACTIVE_HIGH: bool = true;
    pub const FLASH_PAGE_SIZE: usize = 4096;
    pub const FLASH_STORAGE_PAGES: usize = 2;
    pub const FLASH_STORAGE_SIZE: u32 = (FLASH_PAGE_SIZE * FLASH_STORAGE_PAGES) as u32;
    pub const FLASH_PARTITION_LABEL: &str = "manekey";
    pub const FLASH_PARTITION_PROBE_ENABLED: bool = true;
    pub const FLASH_FALLBACK_STORAGE_BASE: u32 = 0x003f_e000;
    pub const FLASH_BOND_STORAGE_SIZE: u32 = 0;
    pub const FLASH_FALLBACK_BOND_STORAGE_BASE: u32 = FLASH_FALLBACK_STORAGE_BASE;
    pub const FLASH_PIN_STORAGE_REQUIRE_PARTITION: bool = true;
    pub const FLASH_MANAGED_BASE: u32 = 0x003f_a000;
    pub const FLASH_MANAGED_SIZE: u32 = 0x2000;
    pub const USB_IDENTITY: CtaphidUsbDeviceInfo =
        CtaphidUsbDeviceInfo::new("ESP32-S2 USB FIDO", "esp32s2-usb-fido");
}
