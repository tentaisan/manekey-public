pub const USER_PRESENCE_GPIO: u8 = 28;
pub const RGB_LED_GPIO: u8 = 27;

pub const FLASH_PAGE_SIZE: usize = 4096;
pub const FLASH_STORAGE_PAGES: usize = 2;
pub const FLASH_STORAGE_SIZE: u32 = (FLASH_PAGE_SIZE * FLASH_STORAGE_PAGES) as u32;
pub const FLASH_BOND_STORAGE_SIZE: u32 = FLASH_PAGE_SIZE as u32;
pub const FLASH_PARTITION_LABEL: &str = "manekey";
pub const FLASH_PIN_STORAGE_REQUIRE_PARTITION: bool = false;
pub const FLASH_PARTITION_PROBE_ENABLED: bool = true;

pub const FLASH_FALLBACK_STORAGE_BASE: u32 = 0x001f_e000;
pub const FLASH_FALLBACK_BOND_STORAGE_BASE: u32 =
    FLASH_FALLBACK_STORAGE_BASE - FLASH_BOND_STORAGE_SIZE;

#[cfg(feature = "flash-managed-keys")]
pub const FLASH_MANAGED_BASE: u32 = 0x001f_9000;
#[cfg(feature = "flash-managed-keys")]
const _: () = {
    assert!(0x110000 <= FLASH_MANAGED_BASE);
    assert!(FLASH_MANAGED_BASE + 8192 <= FLASH_FALLBACK_BOND_STORAGE_BASE - 8192);
};
