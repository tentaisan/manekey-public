use esp_hal::peripherals::FLASH;
use esp_println::println;
use esp_storage::FlashStorage;
use manekey::ctaphid::storage::{StorageBackend, StorageError};

use crate::{
    board::{
        FLASH_FALLBACK_STORAGE_BASE, FLASH_PAGE_SIZE, FLASH_PARTITION_LABEL, FLASH_STORAGE_PAGES,
        FLASH_STORAGE_SIZE,
    },
    flash_region::{
        EspFlashRegion, clear_region, commit_page, find_region_or_fallback, read_page, write_page,
    },
};

#[cfg(feature = "client-pin-flash")]
pub use crate::shared_flash_storage::{
    SharedEspFlash, SharedEspFlashCredentialStorage, new_shared_esp_flash,
};

/// Plain flash journal; board owns exclusive partition/fallback layout and hardware protection.
pub struct EspFlashCredentialStorage<'d> {
    flash: FlashStorage<'d>,
    region: EspFlashRegion,
}

impl<'d> EspFlashCredentialStorage<'d> {
    pub fn new(flash: FLASH<'d>) -> Self {
        let mut flash = FlashStorage::new(flash);
        let region = find_region_or_fallback(
            &mut flash,
            FLASH_PARTITION_LABEL,
            FLASH_STORAGE_SIZE,
            FLASH_FALLBACK_STORAGE_BASE,
            FLASH_STORAGE_SIZE,
        );
        println!(
            "ESP32-S2 credential storage: {:?} offset=0x{:08x} size=0x{:x}",
            region.source, region.base, region.len
        );
        Self { flash, region }
    }
}

impl StorageBackend for EspFlashCredentialStorage<'_> {
    fn read_page(
        &mut self,
        page: usize,
        buf: &mut [u8; FLASH_PAGE_SIZE],
    ) -> Result<(), StorageError> {
        read_page::<FLASH_PAGE_SIZE, FLASH_STORAGE_PAGES>(&mut self.flash, self.region, page, buf)
    }

    fn write_page(&mut self, page: usize, buf: &[u8; FLASH_PAGE_SIZE]) -> Result<(), StorageError> {
        write_page::<FLASH_PAGE_SIZE, FLASH_STORAGE_PAGES>(&mut self.flash, self.region, page, buf)
    }

    fn commit_page(&mut self, page: usize) -> Result<(), StorageError> {
        commit_page::<FLASH_PAGE_SIZE, FLASH_STORAGE_PAGES>(&mut self.flash, self.region, page)
    }

    fn clear_pages(&mut self) -> Result<(), StorageError> {
        clear_region(&mut self.flash, self.region, FLASH_STORAGE_SIZE)
    }
}
