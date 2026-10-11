use core::cell::UnsafeCell;

use embassy_nrf::rramc::Nvmc;
use embedded_storage::nor_flash::{NorFlash, ReadNorFlash};
use manekey::{
    ctaphid::{
        pin_uv_auth::{
            PIN_PAGE_COMMIT_MARKER, PIN_PAGE_COMMIT_OFFSET, PIN_UV_AUTH_PAGE_SIZE, PinStorageError,
            PinUvAuthPageBackend,
        },
        storage::{
            FLASH_SECTOR_SIZE, STORAGE_PAGE_COMMIT_MARKER, STORAGE_PAGE_COMMIT_OFFSET,
            StorageBackend, StorageError,
        },
    },
    storage_region::FixedPageRegion,
    transport::ble::{BLE_BOND_RECORD_LEN, BleBondStore, StoredBleBond},
};
use static_cell::StaticCell;

const RRAM_SIZE: usize = 1524 * 1024;
const JOURNAL_PAGE_COUNT: usize = 2;
const COMMIT_WRITE_LINE_SIZE: usize = 16;
const JOURNAL_REGION_SIZE: usize = JOURNAL_PAGE_COUNT * FLASH_SECTOR_SIZE;
const BOND_REGION_PAGE_COUNT: usize = 1;
const BOND_REGION_SIZE: usize = BOND_REGION_PAGE_COUNT * FLASH_SECTOR_SIZE;
const TOTAL_RESERVED_SIZE: usize = BOND_REGION_SIZE + JOURNAL_REGION_SIZE * 2;

pub const NRF54_RRAM_KEY_REGION: FixedPageRegion = FixedPageRegion::new(
    RRAM_SIZE - TOTAL_RESERVED_SIZE - JOURNAL_REGION_SIZE,
    FLASH_SECTOR_SIZE,
    JOURNAL_PAGE_COUNT,
);
const _: () = assert!(NRF54_RRAM_KEY_REGION.base() == 0x0017_6000);
const _: () =
    assert!(NRF54_RRAM_KEY_REGION.base() + JOURNAL_REGION_SIZE == NRF54_RRAM_BOND_REGION.base());

pub const NRF54_RRAM_BOND_REGION: FixedPageRegion = FixedPageRegion::new(
    RRAM_SIZE - TOTAL_RESERVED_SIZE,
    FLASH_SECTOR_SIZE,
    BOND_REGION_PAGE_COUNT,
);

pub const NRF54_RRAM_PIN_REGION: FixedPageRegion = FixedPageRegion::new(
    RRAM_SIZE - TOTAL_RESERVED_SIZE + BOND_REGION_SIZE,
    PIN_UV_AUTH_PAGE_SIZE,
    JOURNAL_PAGE_COUNT,
);

pub const NRF54_RRAM_CREDENTIAL_REGION: FixedPageRegion =
    FixedPageRegion::from_end(RRAM_SIZE, FLASH_SECTOR_SIZE, JOURNAL_PAGE_COUNT);

const _: () = assert!(NRF54_RRAM_PIN_REGION.base() % PIN_UV_AUTH_PAGE_SIZE == 0);
const _: () = assert!(
    RRAM_SIZE - TOTAL_RESERVED_SIZE + BOND_REGION_SIZE + JOURNAL_REGION_SIZE
        == RRAM_SIZE - JOURNAL_REGION_SIZE
);
const _: () = assert!(RRAM_SIZE - JOURNAL_REGION_SIZE + JOURNAL_REGION_SIZE == RRAM_SIZE);
const _: () =
    assert!(RRAM_SIZE - TOTAL_RESERVED_SIZE + BOND_REGION_SIZE == NRF54_RRAM_PIN_REGION.base());

/// Single-core synchronous RRAM owner; exclude IRQ/MPSL/multicore access, reentry and yielding mutations.
/// Not a general concurrent storage service; reserve all journal regions outside code.
pub struct Nrf54SharedRram {
    rramc: UnsafeCell<Nvmc<'static>>,
}

unsafe impl Sync for Nrf54SharedRram {}

static SHARED_RRAM: StaticCell<Nrf54SharedRram> = StaticCell::new();

/// Initialize the unique shared controller once before any journal or KMU access.
pub fn init_shared_rram(rramc: Nvmc<'static>) -> &'static Nrf54SharedRram {
    SHARED_RRAM.init(Nrf54SharedRram {
        rramc: UnsafeCell::new(rramc),
    })
}

impl Nrf54SharedRram {
    #[cfg(feature = "kmu-key-store")]
    pub(crate) fn with_controller<R>(&self, operation: impl FnOnce() -> R) -> R {
        self.with_rramc(|_| operation())
    }
    fn with_rramc<R>(&self, operation: impl FnOnce(&mut Nvmc<'static>) -> R) -> R {
        unsafe { operation(&mut *self.rramc.get()) }
    }

    fn page_offset(region: FixedPageRegion, page: usize, page_size: usize) -> Option<usize> {
        region.page_offset_for_len(page, page_size)
    }

    fn read_page(&self, region: FixedPageRegion, page: usize, buf: &mut [u8]) -> Result<(), ()> {
        let offset = Self::page_offset(region, page, buf.len()).ok_or(())?;
        self.with_rramc(|rramc| rramc.read(offset as u32, buf))
            .map_err(|_| ())
    }

    fn write_page(&self, region: FixedPageRegion, page: usize, image: &[u8]) -> Result<(), ()> {
        let offset = Self::page_offset(region, page, image.len()).ok_or(())?;
        self.with_rramc(|rramc| {
            rramc.erase(offset as u32, (offset + image.len()) as u32)?;
            rramc.write(offset as u32, image)
        })
        .map_err(|_| ())
    }

    fn commit_page(
        &self,
        region: FixedPageRegion,
        page: usize,
        marker_offset: usize,
        marker: &[u8; 4],
    ) -> Result<(), ()> {
        let page_offset = Self::page_offset(region, page, region.page_size()).ok_or(())?;
        let commit_offset = page_offset.checked_add(marker_offset).ok_or(())?;
        if commit_offset % COMMIT_WRITE_LINE_SIZE != 0 {
            return Err(());
        }
        let mut line = [0u8; COMMIT_WRITE_LINE_SIZE];
        self.with_rramc(|rramc| {
            rramc.read(commit_offset as u32, &mut line)?;
            line[..marker.len()].copy_from_slice(marker);
            rramc.write(commit_offset as u32, &line)
        })
        .map_err(|_| ())
    }

    fn clear_region(&self, region: FixedPageRegion) -> Result<(), ()> {
        for page in 0..region.page_count() {
            let offset = Self::page_offset(region, page, region.page_size()).ok_or(())?;
            self.with_rramc(|rramc| {
                rramc.erase(offset as u32, (offset + region.page_size()) as u32)
            })
            .map_err(|_| ())?;
        }
        Ok(())
    }
}

#[derive(Clone, Copy)]
pub struct Nrf54RramCredentialStorage {
    rram: &'static Nrf54SharedRram,
}

impl Nrf54RramCredentialStorage {
    pub const fn new(rram: &'static Nrf54SharedRram) -> Self {
        Self { rram }
    }
}

impl StorageBackend for Nrf54RramCredentialStorage {
    fn read_page(
        &mut self,
        page: usize,
        buf: &mut [u8; FLASH_SECTOR_SIZE],
    ) -> Result<(), StorageError> {
        self.rram
            .read_page(NRF54_RRAM_CREDENTIAL_REGION, page, buf)
            .map_err(|_| StorageError::ReadFailed)
    }

    fn write_page(
        &mut self,
        page: usize,
        buf: &[u8; FLASH_SECTOR_SIZE],
    ) -> Result<(), StorageError> {
        self.rram
            .write_page(NRF54_RRAM_CREDENTIAL_REGION, page, buf)
            .map_err(|_| StorageError::WriteFailed)
    }

    fn commit_page(&mut self, page: usize) -> Result<(), StorageError> {
        self.rram
            .commit_page(
                NRF54_RRAM_CREDENTIAL_REGION,
                page,
                STORAGE_PAGE_COMMIT_OFFSET,
                &STORAGE_PAGE_COMMIT_MARKER,
            )
            .map_err(|_| StorageError::WriteFailed)
    }

    fn clear_pages(&mut self) -> Result<(), StorageError> {
        self.rram
            .clear_region(NRF54_RRAM_CREDENTIAL_REGION)
            .map_err(|_| StorageError::WriteFailed)
    }
}

#[cfg(any(feature = "flash-managed-keys", any()))]
#[derive(Clone, Copy)]
/// Reserved plaintext asset journal; raw clear_pages also erases root assets and is not CTAP reset.
pub struct Nrf54RramKeyStorage {
    rram: &'static Nrf54SharedRram,
    region: FixedPageRegion,
}

#[cfg(any(feature = "flash-managed-keys", any()))]
impl Nrf54RramKeyStorage {
    #[cfg(feature = "flash-managed-keys")]
    pub const fn new(rram: &'static Nrf54SharedRram) -> Self {
        Self {
            rram,
            region: NRF54_RRAM_KEY_REGION,
        }
    }
}

#[cfg(any(feature = "flash-managed-keys", any()))]
impl StorageBackend for Nrf54RramKeyStorage {
    fn read_page(
        &mut self,
        page: usize,
        buf: &mut [u8; FLASH_SECTOR_SIZE],
    ) -> Result<(), StorageError> {
        self.rram
            .read_page(self.region, page, buf)
            .map_err(|_| StorageError::ReadFailed)
    }
    fn write_page(
        &mut self,
        page: usize,
        buf: &[u8; FLASH_SECTOR_SIZE],
    ) -> Result<(), StorageError> {
        self.rram
            .write_page(self.region, page, buf)
            .map_err(|_| StorageError::WriteFailed)
    }
    fn commit_page(&mut self, page: usize) -> Result<(), StorageError> {
        self.rram
            .commit_page(
                self.region,
                page,
                STORAGE_PAGE_COMMIT_OFFSET,
                &STORAGE_PAGE_COMMIT_MARKER,
            )
            .map_err(|_| StorageError::WriteFailed)
    }

    fn clear_pages(&mut self) -> Result<(), StorageError> {
        self.rram
            .clear_region(self.region)
            .map_err(|_| StorageError::WriteFailed)
    }
}

#[derive(Clone, Copy)]
pub struct Nrf54RramPinStorage {
    rram: &'static Nrf54SharedRram,
}

impl Nrf54RramPinStorage {
    pub const fn new(rram: &'static Nrf54SharedRram) -> Self {
        Self { rram }
    }
}

impl PinUvAuthPageBackend for Nrf54RramPinStorage {
    fn read_pin_page(
        &mut self,
        page: usize,
        buf: &mut [u8; PIN_UV_AUTH_PAGE_SIZE],
    ) -> Result<(), PinStorageError> {
        self.rram
            .read_page(NRF54_RRAM_PIN_REGION, page, buf)
            .map_err(|_| PinStorageError::ReadFailed)
    }

    fn write_pin_page(
        &mut self,
        page: usize,
        buf: &[u8; PIN_UV_AUTH_PAGE_SIZE],
    ) -> Result<(), PinStorageError> {
        self.rram
            .write_page(NRF54_RRAM_PIN_REGION, page, buf)
            .map_err(|_| PinStorageError::WriteFailed)
    }

    fn commit_pin_page(&mut self, page: usize) -> Result<(), PinStorageError> {
        self.rram
            .commit_page(
                NRF54_RRAM_PIN_REGION,
                page,
                PIN_PAGE_COMMIT_OFFSET,
                &PIN_PAGE_COMMIT_MARKER,
            )
            .map_err(|_| PinStorageError::WriteFailed)
    }
}

#[derive(Clone, Copy)]
/// One plaintext bond record in a single rewritten page; no power-loss atomicity guarantee.
pub struct Nrf54RramBondStore {
    rram: &'static Nrf54SharedRram,
}

impl Nrf54RramBondStore {
    pub const fn new(rram: &'static Nrf54SharedRram) -> Self {
        Self { rram }
    }
}

impl BleBondStore for Nrf54RramBondStore {
    fn load_bonds<F>(&mut self, mut visit: F)
    where
        F: FnMut(StoredBleBond),
    {
        let mut record = [0xff; BLE_BOND_RECORD_LEN];
        if self
            .rram
            .read_page(NRF54_RRAM_BOND_REGION, 0, &mut record)
            .is_ok()
        {
            if let Some(bond) = StoredBleBond::decode(&record) {
                visit(bond);
            }
        }
    }

    fn store_bond(&mut self, bond: StoredBleBond) -> bool {
        let mut page = [0xff; FLASH_SECTOR_SIZE];
        page[..BLE_BOND_RECORD_LEN].copy_from_slice(&bond.encode());
        self.rram
            .write_page(NRF54_RRAM_BOND_REGION, 0, &page)
            .is_ok()
    }

    fn clear_bonds(&mut self) -> bool {
        self.rram.clear_region(NRF54_RRAM_BOND_REGION).is_ok()
    }
}
