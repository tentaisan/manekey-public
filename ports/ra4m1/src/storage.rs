use crate::data_flash::{BLOCK, DataFlash};
use core::cell::RefCell;
use manekey::ctaphid::{
    pin_uv_auth::{
        PIN_PAGE_COMMIT_MARKER, PIN_PAGE_COMMIT_OFFSET, PIN_UV_AUTH_PAGE_SIZE, PinStorageError,
        PinUvAuthPageBackend,
    },
    storage::{
        FLASH_SECTOR_SIZE, STORAGE_PAGE_COMMIT_MARKER, STORAGE_PAGE_COMMIT_OFFSET, StorageBackend,
        StorageError,
    },
};
use manekey::storage_region::FixedPageRegion;
use zeroize::{Zeroize, Zeroizing};

pub type SharedFlash = RefCell<DataFlash>;
const _: () = assert!(FLASH_SECTOR_SIZE == BLOCK && PIN_UV_AUTH_PAGE_SIZE == BLOCK);

pub fn device_secret(flash: &SharedFlash, candidate: &[u8; 32]) -> Result<[u8; 32], ()> {
    let mut page = Zeroizing::new([0xff; BLOCK]);
    let mut flash = flash.try_borrow_mut().map_err(|_| ())?;
    flash.read(0, &mut *page).map_err(|_| ())?;
    if page.iter().all(|b| *b == 0xff) {
        page[..8].copy_from_slice(b"MKRAKEY1");
        page[16..48].copy_from_slice(candidate);
        // Secret first, validity marker last. Torn initialization must not rekey.
        flash.program(16, &page[16..48]).map_err(|_| ())?;
        flash.program(0, &page[..8]).map_err(|_| ())?;
        let mut verify = Zeroizing::new([0; 48]);
        flash.read(0, &mut *verify).map_err(|_| ())?;
        let valid = verify[..] == page[..48];
        if !valid {
            page.zeroize();
            return Err(());
        }
    }
    if &page[..8] != b"MKRAKEY1"
        || page[8..16] != [0xff; 8]
        || page[48..].iter().any(|b| *b != 0xff)
        || page[16..48].iter().all(|b| *b == 0xff)
        || page[16..48].iter().all(|b| *b == 0)
    {
        page.zeroize();
        return Err(());
    }
    let secret = page[16..48].try_into().map_err(|_| ())?;
    page.zeroize();
    Ok(secret)
}

pub struct Journal {
    flash: &'static SharedFlash,
    region: FixedPageRegion,
    pending: Option<usize>,
}

impl Journal {
    pub const fn credentials(flash: &'static SharedFlash) -> Self {
        Self::new(flash, 3 * BLOCK)
    }
    pub const fn pin(flash: &'static SharedFlash) -> Self {
        Self::new(flash, BLOCK)
    }
    #[cfg(feature = "flash-managed-keys")]
    pub const fn keys(flash: &'static SharedFlash) -> Self {
        Self::new(flash, 5 * BLOCK)
    }
    const fn new(flash: &'static SharedFlash, base: usize) -> Self {
        Self {
            flash,
            region: FixedPageRegion::new(base, BLOCK, 2),
            pending: None,
        }
    }
    fn read(&mut self, page: usize, output: &mut [u8]) -> Result<(), ()> {
        let offset = self
            .region
            .page_offset_for_len(page, output.len())
            .ok_or(())?;
        self.flash
            .try_borrow()
            .map_err(|_| ())?
            .read(offset, output)
            .map_err(|_| ())
    }
    fn write(&mut self, page: usize, bytes: &[u8]) -> Result<(), ()> {
        self.pending = None;
        if bytes.len() != BLOCK || bytes[16..20] != [0xff; 4] {
            return Err(());
        }
        let offset = self.region.page_offset(page).ok_or(())?;
        let mut flash = self.flash.try_borrow_mut().map_err(|_| ())?;
        flash.erase_block(offset).map_err(|_| ())?;
        flash.program(offset, bytes).map_err(|_| ())?;
        let mut verify = [0; BLOCK];
        flash.read(offset, &mut verify).map_err(|_| ())?;
        let matches = verify == bytes;
        verify.zeroize();
        if !matches {
            return Err(());
        }
        self.pending = Some(page);
        Ok(())
    }
    fn commit(&mut self, page: usize, marker: &[u8; 4], at: usize) -> Result<(), ()> {
        if self.pending.take() != Some(page) {
            return Err(());
        }
        let offset = self.region.page_offset(page).ok_or(())?;
        let mut flash = self.flash.try_borrow_mut().map_err(|_| ())?;
        flash.program(offset + at, marker).map_err(|_| ())?;
        let mut verify = [0; 4];
        flash.read(offset + at, &mut verify).map_err(|_| ())?;
        if verify != *marker {
            return Err(());
        }
        Ok(())
    }
}

impl StorageBackend for Journal {
    fn read_page(
        &mut self,
        page: usize,
        out: &mut [u8; FLASH_SECTOR_SIZE],
    ) -> Result<(), StorageError> {
        self.read(page, out).map_err(|_| StorageError::ReadFailed)
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
        self.commit(
            page,
            &STORAGE_PAGE_COMMIT_MARKER,
            STORAGE_PAGE_COMMIT_OFFSET,
        )
        .map_err(|_| StorageError::WriteFailed)
    }
    fn clear_pages(&mut self) -> Result<(), StorageError> {
        self.pending = None;
        let mut flash = self
            .flash
            .try_borrow_mut()
            .map_err(|_| StorageError::WriteFailed)?;
        for page in 0..2 {
            let offset = self
                .region
                .page_offset(page)
                .ok_or(StorageError::WriteFailed)?;
            flash
                .erase_block(offset)
                .map_err(|_| StorageError::WriteFailed)?;
            let mut verify = [0; 64];
            for start in (0..BLOCK).step_by(verify.len()) {
                flash
                    .read(offset + start, &mut verify)
                    .map_err(|_| StorageError::ReadFailed)?;
                if verify.iter().any(|byte| *byte != 0xff) {
                    verify.zeroize();
                    return Err(StorageError::WriteFailed);
                }
            }
        }
        Ok(())
    }
}

impl PinUvAuthPageBackend for Journal {
    fn read_pin_page(
        &mut self,
        page: usize,
        out: &mut [u8; PIN_UV_AUTH_PAGE_SIZE],
    ) -> Result<(), PinStorageError> {
        self.read(page, out)
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
        self.commit(page, &PIN_PAGE_COMMIT_MARKER, PIN_PAGE_COMMIT_OFFSET)
            .map_err(|_| PinStorageError::WriteFailed)
    }
}
