use core::cell::RefCell;
use critical_section::Mutex;
#[cfg(not(all(feature = "trustzone-product", feature = "trustzone-secure-layout")))]
use embassy_stm32::flash::{Blocking, Flash};
use manekey::ctaphid::{
    pin_uv_auth::{PIN_UV_AUTH_PAGE_SIZE, PinStorageError, PinUvAuthPageBackend},
    storage::{FLASH_SECTOR_SIZE, StorageBackend, StorageError},
};
use manekey::storage_region::FixedPageRegion;

const ERASE: usize = 8192;
const WRITE: usize = 16;
const BASE: usize = 2 * 1024 * 1024 - 5 * ERASE;
const _: () = assert!(embassy_stm32::flash::WRITE_SIZE == WRITE);
const _: () = assert!(embassy_stm32::flash::MAX_ERASE_SIZE == ERASE);
const _: () = assert!(manekey::ctaphid::storage::STORAGE_PAGE_COMMIT_OFFSET == WRITE);
const _: () = assert!(manekey::ctaphid::pin_uv_auth::PIN_PAGE_COMMIT_OFFSET == WRITE);
#[cfg(not(all(feature = "trustzone-product", feature = "trustzone-secure-layout")))]
pub type SharedFlash = Mutex<RefCell<Flash<'static, Blocking>>>;
#[cfg(all(feature = "trustzone-product", feature = "trustzone-secure-layout"))]
pub type SharedFlash = Mutex<RefCell<crate::secure_hal::PrivateFlash>>;

/// Plain Flash root; blank state initializes, invalid marker/read/write failure panics.
/// Caller exclusively reserves the whole physical erase page.
pub fn device_secret(flash: &SharedFlash, candidate: [u8; 32]) -> [u8; 32] {
    let mut image = [0xff; 48];
    critical_section::with(|cs| {
        let mut flash = flash.borrow(cs).borrow_mut();
        flash.blocking_read(BASE as u32, &mut image).unwrap();
        if image.iter().all(|b| *b == 0xff) {
            image[..8].copy_from_slice(b"MKU5KEY1");
            image[16..].copy_from_slice(&candidate);
            flash
                .blocking_erase(BASE as u32, (BASE + ERASE) as u32)
                .unwrap();

            flash
                .blocking_write((BASE + WRITE) as u32, &image[WRITE..])
                .unwrap();
            flash.blocking_write(BASE as u32, &image[..WRITE]).unwrap();
            let expected = image;
            flash.blocking_read(BASE as u32, &mut image).unwrap();
            assert_eq!(image, expected);
        }
    });
    assert_eq!(&image[..8], b"MKU5KEY1");
    image[16..].try_into().unwrap()
}

/// Caller reserves complete erase pages and excludes other Flash/DMA owners.
/// Plain media has no encryption, rollback protection or physical secure-erasure guarantee.
pub struct Journal {
    flash: &'static SharedFlash,
    region: FixedPageRegion,
    pending: Option<(usize, [u8; WRITE])>,
}

impl Journal {
    pub const fn credentials(flash: &'static SharedFlash) -> Self {
        Self::new(flash, BASE + 3 * ERASE)
    }

    pub const fn pin(flash: &'static SharedFlash) -> Self {
        Self::new(flash, BASE + ERASE)
    }

    #[cfg(feature = "flash-managed-keys")]
    pub const fn keys(flash: &'static SharedFlash) -> Self {
        Self::new(flash, crate::flash_layout::MANAGED_START as usize)
    }

    const fn new(flash: &'static SharedFlash, base: usize) -> Self {
        Self {
            flash,
            region: FixedPageRegion::new(base, ERASE, 2),
            pending: None,
        }
    }

    fn address(&self, page: usize) -> Result<u32, ()> {
        self.region
            .page_offset_for_len(page, ERASE)
            .map(|a| a as u32)
            .ok_or(())
    }

    fn read(&mut self, page: usize, bytes: &mut [u8]) -> Result<(), ()> {
        let address = self.address(page)?;
        if bytes.len() > ERASE {
            return Err(());
        }
        critical_section::with(|cs| {
            self.flash
                .borrow(cs)
                .borrow_mut()
                .blocking_read(address, bytes)
                .map_err(|_| ())
        })
    }

    fn write(&mut self, page: usize, bytes: &[u8]) -> Result<(), ()> {
        let address = self.address(page)?;
        if bytes.len() < 2 * WRITE || bytes.len() > ERASE || bytes.len() % WRITE != 0 {
            return Err(());
        }
        self.pending = None;
        critical_section::with(|cs| {
            let mut flash = self.flash.borrow(cs).borrow_mut();
            flash
                .blocking_erase(address, address + ERASE as u32)
                .map_err(|_| ())?;
            flash
                .blocking_write(address, &bytes[..WRITE])
                .map_err(|_| ())?;
            flash
                .blocking_write(address + 2 * WRITE as u32, &bytes[2 * WRITE..])
                .map_err(|_| ())
        })?;
        let mut commit_line = [0; WRITE];
        commit_line.copy_from_slice(&bytes[WRITE..2 * WRITE]);
        commit_line[..4].copy_from_slice(b"CMIT");
        self.pending = Some((page, commit_line));
        Ok(())
    }

    fn commit(&mut self, page: usize) -> Result<(), ()> {
        let address = self.address(page)?;
        let (pending_page, bytes) = self.pending.take().ok_or(())?;
        if pending_page != page {
            return Err(());
        }

        critical_section::with(|cs| {
            self.flash
                .borrow(cs)
                .borrow_mut()
                .blocking_write(address + WRITE as u32, &bytes)
                .map_err(|_| ())
        })
    }
}

impl StorageBackend for Journal {
    fn read_page(
        &mut self,
        page: usize,
        bytes: &mut [u8; FLASH_SECTOR_SIZE],
    ) -> Result<(), StorageError> {
        self.read(page, bytes).map_err(|_| StorageError::ReadFailed)
    }
    fn write_page(
        &mut self,
        page: usize,
        bytes: &[u8; FLASH_SECTOR_SIZE],
    ) -> Result<(), StorageError> {
        self.write(page, bytes)
            .map_err(|_| StorageError::WriteFailed)
    }
    fn commit_page(&mut self, page: usize) -> Result<(), StorageError> {
        self.commit(page).map_err(|_| StorageError::WriteFailed)
    }
    fn clear_pages(&mut self) -> Result<(), StorageError> {
        self.pending = None;
        for page in 0..2 {
            let address = self.address(page).map_err(|_| StorageError::WriteFailed)?;
            critical_section::with(|cs| {
                self.flash
                    .borrow(cs)
                    .borrow_mut()
                    .blocking_erase(address, address + ERASE as u32)
            })
            .map_err(|_| StorageError::WriteFailed)?;
        }
        Ok(())
    }
}

impl PinUvAuthPageBackend for Journal {
    fn read_pin_page(
        &mut self,
        page: usize,
        bytes: &mut [u8; PIN_UV_AUTH_PAGE_SIZE],
    ) -> Result<(), PinStorageError> {
        self.read(page, bytes)
            .map_err(|_| PinStorageError::ReadFailed)
    }
    fn write_pin_page(
        &mut self,
        page: usize,
        bytes: &[u8; PIN_UV_AUTH_PAGE_SIZE],
    ) -> Result<(), PinStorageError> {
        self.write(page, bytes)
            .map_err(|_| PinStorageError::WriteFailed)
    }
    fn commit_pin_page(&mut self, page: usize) -> Result<(), PinStorageError> {
        self.commit(page).map_err(|_| PinStorageError::WriteFailed)
    }
}
