use esp_println::println;
use manekey::ctaphid::pin_uv_auth::{
    PIN_PAGE_COMMIT_MARKER, PIN_PAGE_COMMIT_OFFSET, PIN_UV_AUTH_PAGE_SIZE, PinStorageError,
    PinUvAuthPageBackend,
};

use crate::{
    board::{
        FLASH_BOND_STORAGE_SIZE, FLASH_FALLBACK_BOND_STORAGE_BASE, FLASH_PARTITION_LABEL,
        FLASH_PIN_STORAGE_REQUIRE_PARTITION, FLASH_STORAGE_SIZE,
    },
    flash_region::{EspFlashRegion, EspFlashStorageSource, find_partition_region},
    shared_flash_storage::SharedEspFlash,
};

const PIN_PAGE_COUNT: usize = 2;
const PIN_STORAGE_SIZE: u32 = (PIN_UV_AUTH_PAGE_SIZE * PIN_PAGE_COUNT) as u32;

/// Plaintext PIN pages; board owns dedicated or fallback layout and cross-core flash exclusion.
/// Required-partition absence leaves operations unavailable, not a usable fallback.
pub struct EspFlashPinUvAuthStorage<'d> {
    flash: &'d SharedEspFlash<'d>,
    region: EspFlashRegion,
}

impl<'d> EspFlashPinUvAuthStorage<'d> {
    pub fn new(flash: &'d SharedEspFlash<'d>) -> Self {
        let region = flash.lock(|cell| {
            let mut flash = cell.borrow_mut();
            if let Some(partition) =
                find_partition_region(&mut flash, "manekey_pin", PIN_STORAGE_SIZE)
            {
                return partition;
            }
            if FLASH_PIN_STORAGE_REQUIRE_PARTITION {
                return EspFlashRegion {
                    base: 0,
                    len: 0,
                    source: EspFlashStorageSource::Fallback,
                };
            }
            find_partition_region(
                &mut flash,
                FLASH_PARTITION_LABEL,
                FLASH_STORAGE_SIZE + FLASH_BOND_STORAGE_SIZE + PIN_STORAGE_SIZE,
            )
            .map(|partition| EspFlashRegion {
                base: partition.base + FLASH_STORAGE_SIZE + FLASH_BOND_STORAGE_SIZE,
                len: PIN_STORAGE_SIZE,
                source: partition.source,
            })
            .unwrap_or(EspFlashRegion {
                base: FLASH_FALLBACK_BOND_STORAGE_BASE - PIN_STORAGE_SIZE,
                len: PIN_STORAGE_SIZE,
                source: EspFlashStorageSource::Fallback,
            })
        });
        println!(
            "ESP PIN storage: {:?} offset=0x{:08x} size=0x{:x}",
            region.source, region.base, region.len
        );
        Self { flash, region }
    }

    fn page_offset(&self, page: usize) -> Result<(u32, u32), PinStorageError> {
        self.region
            .page_range(page, PIN_UV_AUTH_PAGE_SIZE, PIN_PAGE_COUNT)
            .map_err(|_| PinStorageError::ReadFailed)
    }
}

impl PinUvAuthPageBackend for EspFlashPinUvAuthStorage<'_> {
    fn read_pin_page(
        &mut self,
        page: usize,
        buf: &mut [u8; PIN_UV_AUTH_PAGE_SIZE],
    ) -> Result<(), PinStorageError> {
        let (offset, _) = self.page_offset(page)?;
        self.flash.lock(|cell| {
            cell.borrow_mut()
                .read(offset, buf)
                .map(|_| ())
                .map_err(|_| PinStorageError::ReadFailed)
        })
    }

    fn write_pin_page(
        &mut self,
        page: usize,
        buf: &[u8; PIN_UV_AUTH_PAGE_SIZE],
    ) -> Result<(), PinStorageError> {
        let (start, end) = self
            .page_offset(page)
            .map_err(|_| PinStorageError::WriteFailed)?;
        self.flash.lock(|cell| {
            let mut flash = cell.borrow_mut();
            flash
                .erase(start, end)
                .map_err(|_| PinStorageError::WriteFailed)?;
            flash
                .write(start, buf)
                .map_err(|_| PinStorageError::WriteFailed)
        })
    }

    fn commit_pin_page(&mut self, page: usize) -> Result<(), PinStorageError> {
        let (start, _) = self
            .page_offset(page)
            .map_err(|_| PinStorageError::WriteFailed)?;
        let offset = start + PIN_PAGE_COMMIT_OFFSET as u32;
        self.flash.lock(|cell| {
            cell.borrow_mut()
                .write(offset, &PIN_PAGE_COMMIT_MARKER)
                .map_err(|_| PinStorageError::WriteFailed)
        })
    }
}
