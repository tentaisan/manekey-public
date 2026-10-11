pub const USER_PRESENCE_GPIO: u8 = 0;
pub const USER_PRESENCE_LED_GPIO: u8 = 2;
pub const DIAGNOSTIC_OUTPUT_GPIO: u8 = 25;

pub const FLASH_PAGE_SIZE: usize = 4096;
pub const FLASH_STORAGE_PAGES: usize = 2;
pub const FLASH_STORAGE_SIZE: u32 = (FLASH_PAGE_SIZE * FLASH_STORAGE_PAGES) as u32;
pub const FLASH_BOND_STORAGE_SIZE: u32 = FLASH_PAGE_SIZE as u32;
pub const FLASH_PARTITION_LABEL: &str = "manekey";
pub const FLASH_PIN_STORAGE_REQUIRE_PARTITION: bool = cfg!(feature = "flash-managed-keys");

pub const FLASH_PARTITION_PROBE_ENABLED: bool = cfg!(feature = "flash-managed-keys");
pub const FLASH_MANAGED_BASE: u32 = 0x001f_9000;
pub const FLASH_MANAGED_SIZE: u32 = 0x2000;

#[cfg(not(feature = "board-devkit-v1"))]
pub const FLASH_FALLBACK_STORAGE_BASE: u32 = 0x001f_e000;

#[cfg(feature = "board-devkit-v1")]
pub const FLASH_FALLBACK_STORAGE_BASE: u32 = 0x000f_e000;
pub const FLASH_FALLBACK_BOND_STORAGE_BASE: u32 =
    FLASH_FALLBACK_STORAGE_BASE - FLASH_BOND_STORAGE_SIZE;
