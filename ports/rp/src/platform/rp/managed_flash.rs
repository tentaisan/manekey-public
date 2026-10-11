use super::flash_layout::MANAGED_KEYS;
use super::storage::SharedRpFlash;
use manekey::ctaphid::storage::{
    FLASH_SECTOR_SIZE, STORAGE_PAGE_COMMIT_MARKER, STORAGE_PAGE_COMMIT_OFFSET, StorageBackend,
    StorageError,
};

const _: () = assert!(FLASH_SECTOR_SIZE == MANAGED_KEYS.page_size());
#[cfg(feature = "chip-rp235xa")]
const _: () = assert!(
    0x1000_0000 + MANAGED_KEYS.base()
        == manekey::security::layout::SECURE_MANAGED_KEYS_START as usize
);
#[cfg(feature = "chip-rp235xa")]
const _: () = assert!(
    0x1000_0000 + MANAGED_KEYS.base() + MANAGED_KEYS.len()
        == manekey::security::layout::SECURE_BLE_BOND_START as usize
);

/// Reserved plaintext key journal; raw clear_pages erases root assets and is not CTAP reset.
/// Requires the shared Flash service's execution/IRQ/core exclusion contract.
pub struct SharedManagedKeyFlashStorage<'a> {
    flash: &'a SharedRpFlash<'a>,
}

impl<'a> SharedManagedKeyFlashStorage<'a> {
    pub const fn new(flash: &'a SharedRpFlash<'a>) -> Self {
        Self { flash }
    }
}

fn offset(page: usize) -> Result<usize, StorageError> {
    MANAGED_KEYS
        .page_offset_for_len(page, FLASH_SECTOR_SIZE)
        .ok_or(StorageError::ReadFailed)
}

impl StorageBackend for SharedManagedKeyFlashStorage<'_> {
    fn read_page(
        &mut self,
        page: usize,
        buf: &mut [u8; FLASH_SECTOR_SIZE],
    ) -> Result<(), StorageError> {
        let start = offset(page)?;
        self.flash
            .lock(|flash| flash.borrow_mut().blocking_read(start as u32, buf))
            .map_err(|_| StorageError::ReadFailed)
    }

    fn write_page(
        &mut self,
        page: usize,
        buf: &[u8; FLASH_SECTOR_SIZE],
    ) -> Result<(), StorageError> {
        let start = offset(page).map_err(|_| StorageError::WriteFailed)?;
        self.flash
            .lock(|flash| {
                let mut flash = flash.borrow_mut();
                flash.blocking_erase(start as u32, (start + FLASH_SECTOR_SIZE) as u32)?;
                flash.blocking_write(start as u32, buf)
            })
            .map_err(|_| StorageError::WriteFailed)
    }

    fn commit_page(&mut self, page: usize) -> Result<(), StorageError> {
        let start =
            offset(page).map_err(|_| StorageError::WriteFailed)? + STORAGE_PAGE_COMMIT_OFFSET;
        self.flash
            .lock(|flash| {
                flash
                    .borrow_mut()
                    .blocking_write(start as u32, &STORAGE_PAGE_COMMIT_MARKER)
            })
            .map_err(|_| StorageError::WriteFailed)
    }

    fn clear_pages(&mut self) -> Result<(), StorageError> {
        self.flash
            .lock(|flash| {
                flash.borrow_mut().blocking_erase(
                    MANAGED_KEYS.base() as u32,
                    MANAGED_KEYS.end().unwrap() as u32,
                )
            })
            .map_err(|_| StorageError::WriteFailed)
    }
}
