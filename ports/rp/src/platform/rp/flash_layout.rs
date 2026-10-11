use manekey::storage_region::FixedPageRegion;

/// Caller supplies actual Flash size at least seven 4096-byte pages and reserves the returned tail outside code.
pub const fn managed_keys_region(flash_size: usize) -> FixedPageRegion {
    FixedPageRegion::new(flash_size - 7 * 4096, 4096, 2)
}

#[cfg(feature = "chip-rp2040")]
pub const FLASH_SIZE: usize = 2 * 1024 * 1024;
#[cfg(not(feature = "chip-rp2040"))]
pub const FLASH_SIZE: usize = 4 * 1024 * 1024;
pub const MANAGED_KEYS: FixedPageRegion = managed_keys_region(FLASH_SIZE);
