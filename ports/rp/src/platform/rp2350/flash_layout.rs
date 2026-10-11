use manekey::storage_region::FixedPageRegion;

pub const FLASH_SIZE: usize = 4 * 1024 * 1024;
pub const MANAGED_KEYS: FixedPageRegion = FixedPageRegion::new(0x3f9000, 4096, 2);
