#[cfg(feature = "usb-hid")]
use manekey::ctaphid::descriptor::CtaphidUsbDeviceInfo;

pub const USB_PRODUCT: &str = "ESP32-S3 USB FIDO";
pub const USB_SERIAL: &str = "esp32s3-usb-fido";
#[cfg(feature = "usb-hid")]
pub const USB_IDENTITY: CtaphidUsbDeviceInfo = CtaphidUsbDeviceInfo::new(USB_PRODUCT, USB_SERIAL);

pub const USB_DP_GPIO: u8 = 20;
pub const USB_DM_GPIO: u8 = 19;
pub const USER_PRESENCE_GPIO: u8 = 2;
pub const DIAGNOSTIC_LED_GPIO: u8 = 21;

pub const INTERNAL_UART_TX_GPIO: u8 = 43;
pub const INTERNAL_UART_RX_GPIO: u8 = 44;

pub const FLASH_PAGE_SIZE: usize = 4096;
pub const FLASH_MANAGED_BASE: u32 = 0x003f_9000;
pub const FLASH_MANAGED_SIZE: u32 = 8192;
pub const FLASH_STORAGE_PAGES: usize = 2;
pub const FLASH_STORAGE_SIZE: u32 = (FLASH_PAGE_SIZE * FLASH_STORAGE_PAGES) as u32;
pub const FLASH_BOND_STORAGE_PAGES: usize = 1;
pub const FLASH_BOND_STORAGE_SIZE: u32 = (FLASH_PAGE_SIZE * FLASH_BOND_STORAGE_PAGES) as u32;
pub const FLASH_PARTITION_LABEL: &str = "manekey";
pub const FLASH_PIN_STORAGE_REQUIRE_PARTITION: bool = false;
pub const FLASH_PARTITION_PROBE_ENABLED: bool = true;

pub const FLASH_FALLBACK_STORAGE_BASE: u32 = 0x003f_e000;
pub const FLASH_FALLBACK_BOND_STORAGE_BASE: u32 =
    FLASH_FALLBACK_STORAGE_BASE - FLASH_BOND_STORAGE_SIZE;
