use core::cell::RefCell;

use embassy_sync::{blocking_mutex::Mutex, blocking_mutex::raw::CriticalSectionRawMutex};
use esp_hal::peripherals::FLASH;
use esp_println::println;
use esp_storage::FlashStorage;
use manekey::ctaphid::storage::{StorageBackend, StorageError};
#[cfg(feature = "ble-security")]
use manekey::transport::ble::{BLE_BOND_RECORD_LEN, BleBondStore, StoredBleBond};

use crate::board::{
    FLASH_FALLBACK_STORAGE_BASE, FLASH_PAGE_SIZE, FLASH_PARTITION_LABEL, FLASH_STORAGE_PAGES,
    FLASH_STORAGE_SIZE,
};
use crate::flash_region::{
    EspFlashRegion, clear_region, commit_page, find_region_or_fallback, read_page, write_page,
};
#[cfg(feature = "ble-security")]
use crate::{
    board::{FLASH_BOND_STORAGE_SIZE, FLASH_FALLBACK_BOND_STORAGE_BASE},
    flash_region::{EspFlashStorageSource, find_partition_region},
};

/// Platform critical-section exclusion; board owns flash layout and safe other-core/XIP coordination.
pub type SharedEspFlash<'d> = Mutex<CriticalSectionRawMutex, RefCell<FlashStorage<'d>>>;

/// Plain flash pages with board-provided partition/fallback reservation, not encrypted or rollback protected.
pub struct SharedEspFlashCredentialStorage<'d> {
    flash: &'d SharedEspFlash<'d>,
    region: EspFlashRegion,
}

#[cfg(feature = "ble-security")]
/// One plaintext bond record; read failure/invalid record behaves as no loaded bond.
/// Erase/write is not atomic power-loss persistence or physical secure erasure.
pub struct EspFlashBondStore<'d> {
    flash: &'d SharedEspFlash<'d>,
    region: EspFlashRegion,
}

pub fn new_shared_esp_flash(flash: FLASH<'static>) -> SharedEspFlash<'static> {
    Mutex::new(RefCell::new(FlashStorage::new(flash)))
}

#[cfg(feature = "multicore-flash")]
pub fn new_multicore_shared_esp_flash(flash: FLASH<'static>) -> SharedEspFlash<'static> {
    Mutex::new(RefCell::new(FlashStorage::new(flash).multicore_auto_park()))
}

impl<'d> SharedEspFlashCredentialStorage<'d> {
    pub fn new(flash: &'d SharedEspFlash<'d>) -> Self {
        let region = flash.lock(|cell| {
            find_region_or_fallback(
                &mut cell.borrow_mut(),
                FLASH_PARTITION_LABEL,
                FLASH_STORAGE_SIZE,
                FLASH_FALLBACK_STORAGE_BASE,
                FLASH_STORAGE_SIZE,
            )
        });
        println!(
            "ESP shared credential storage: {:?} offset=0x{:08x} size=0x{:x}",
            region.source, region.base, region.len
        );
        Self { flash, region }
    }
}

#[cfg(feature = "ble-security")]
impl<'d> EspFlashBondStore<'d> {
    pub fn new(flash: &'d SharedEspFlash<'d>) -> Self {
        let region = flash.lock(|cell| {
            let mut flash = cell.borrow_mut();
            find_partition_region(
                &mut flash,
                FLASH_PARTITION_LABEL,
                FLASH_STORAGE_SIZE + FLASH_BOND_STORAGE_SIZE,
            )
            .map(|partition| EspFlashRegion {
                base: partition.base + FLASH_STORAGE_SIZE,
                len: FLASH_BOND_STORAGE_SIZE,
                source: partition.source,
            })
            .unwrap_or(EspFlashRegion {
                base: FLASH_FALLBACK_BOND_STORAGE_BASE,
                len: FLASH_BOND_STORAGE_SIZE,
                source: EspFlashStorageSource::Fallback,
            })
        });
        println!(
            "ESP BLE bond storage: {:?} offset=0x{:08x} size=0x{:x}",
            region.source, region.base, region.len
        );
        Self { flash, region }
    }
}

impl StorageBackend for SharedEspFlashCredentialStorage<'_> {
    fn read_page(
        &mut self,
        page: usize,
        buf: &mut [u8; FLASH_PAGE_SIZE],
    ) -> Result<(), StorageError> {
        self.flash.lock(|cell| {
            read_page::<FLASH_PAGE_SIZE, FLASH_STORAGE_PAGES>(
                &mut cell.borrow_mut(),
                self.region,
                page,
                buf,
            )
        })
    }

    fn write_page(&mut self, page: usize, buf: &[u8; FLASH_PAGE_SIZE]) -> Result<(), StorageError> {
        self.flash.lock(|cell| {
            write_page::<FLASH_PAGE_SIZE, FLASH_STORAGE_PAGES>(
                &mut cell.borrow_mut(),
                self.region,
                page,
                buf,
            )
        })
    }

    fn commit_page(&mut self, page: usize) -> Result<(), StorageError> {
        self.flash.lock(|cell| {
            commit_page::<FLASH_PAGE_SIZE, FLASH_STORAGE_PAGES>(
                &mut cell.borrow_mut(),
                self.region,
                page,
            )
        })
    }

    fn clear_pages(&mut self) -> Result<(), StorageError> {
        self.flash
            .lock(|cell| clear_region(&mut cell.borrow_mut(), self.region, FLASH_STORAGE_SIZE))
    }
}

#[cfg(feature = "ble-security")]
impl BleBondStore for EspFlashBondStore<'_> {
    fn load_bonds<F>(&mut self, mut visit: F)
    where
        F: FnMut(StoredBleBond),
    {
        let mut record = [0xff; BLE_BOND_RECORD_LEN];
        let read_ok = self.flash.lock(|cell| {
            cell.borrow_mut()
                .read(self.region.base, &mut record)
                .map(|_| ())
                .is_ok()
        });
        if read_ok {
            if let Some(bond) = StoredBleBond::decode(&record) {
                println!(
                    "ESP BLE bond storage: valid record found has_irk={}",
                    bond.irk.is_some()
                );
                visit(bond);
            } else {
                println!("ESP BLE bond storage: no valid record");
            }
        } else {
            println!("ESP BLE bond storage: read failed");
        }
    }

    fn store_bond(&mut self, bond: StoredBleBond) -> bool {
        let record = bond.encode();
        let result = self.flash.lock(|cell| {
            let mut flash = cell.borrow_mut();
            if self.region.len < FLASH_BOND_STORAGE_SIZE {
                return Err(());
            }
            flash
                .erase(self.region.base, self.region.base + FLASH_BOND_STORAGE_SIZE)
                .map_err(|_| ())?;
            flash.write(self.region.base, &record).map_err(|_| ())
        });
        match result {
            Ok(()) => {
                println!("ESP BLE bond storage: stored record");
                true
            }
            Err(()) => {
                println!("ESP BLE bond storage: store failed");
                false
            }
        }
    }

    fn clear_bonds(&mut self) -> bool {
        let result = self.flash.lock(|cell| {
            if self.region.len < FLASH_BOND_STORAGE_SIZE {
                return Err(());
            }
            cell.borrow_mut()
                .erase(self.region.base, self.region.base + FLASH_BOND_STORAGE_SIZE)
                .map_err(|_| ())
        });
        match result {
            Ok(()) => {
                println!("ESP BLE bond storage: cleared records");
                true
            }
            Err(()) => {
                println!("ESP BLE bond storage: clear failed");
                false
            }
        }
    }
}
