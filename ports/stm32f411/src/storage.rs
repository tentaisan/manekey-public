use core::cell::RefCell;
use critical_section::Mutex;
use embassy_stm32::flash::{Blocking, Flash};
use manekey::{
    ctaphid::{
        pin_uv_auth::{
            PIN_PAGE_COMMIT_OFFSET, PIN_UV_AUTH_PAGE_SIZE, PinStorageError, PinUvAuthPageBackend,
        },
        storage::{FLASH_SECTOR_SIZE, STORAGE_PAGE_COMMIT_OFFSET, StorageBackend, StorageError},
    },
    storage_region::FixedPageRegion,
};

pub type SharedFlash = Mutex<RefCell<Flash<'static, Blocking>>>;
const WRITE: usize = 4;
const SECRET_BASE: u32 = 0xc000;
const SECRET_END: u32 = 0x10000;
const _: () = assert!(embassy_stm32::flash::WRITE_SIZE == WRITE);
const _: () = assert!(PIN_PAGE_COMMIT_OFFSET == STORAGE_PAGE_COMMIT_OFFSET);

/// Plain Flash root; blank state initializes, invalid marker/read/write failure panics.
/// Caller reserves the whole physical sector exclusively.
pub fn device_secret(flash: &SharedFlash, candidate: [u8; 32]) -> [u8; 32] {
    let mut image = [0xff; 48];
    critical_section::with(|cs| {
        let mut flash = flash.borrow(cs).borrow_mut();
        flash.blocking_read(SECRET_BASE, &mut image).unwrap();
        if image.iter().all(|b| *b == 0xff) {
            image[..8].copy_from_slice(b"MKF4KEY1");
            image[16..].copy_from_slice(&candidate);
            flash.blocking_erase(SECRET_BASE, SECRET_END).unwrap();
            flash
                .blocking_write(SECRET_BASE + 16, &image[16..])
                .unwrap();
            flash.blocking_write(SECRET_BASE, &image[..16]).unwrap();
            let expected = image;
            flash.blocking_read(SECRET_BASE, &mut image).unwrap();
            assert_eq!(image, expected);
        }
    });

    assert_eq!(&image[..8], b"MKF4KEY1");
    image[16..].try_into().unwrap()
}

/// Caller exclusively reserves physical erase sectors and excludes other Flash/DMA owners.
/// Plain media has no encryption, rollback protection or physical secure-erasure guarantee.
pub struct Journal {
    flash: &'static SharedFlash,
    pages: [FixedPageRegion; 2],
    pending: Option<usize>,
    channel: Option<usize>,
}
impl Journal {
    pub const fn credentials(flash: &'static SharedFlash) -> Self {
        Self {
            flash,
            pages: [
                FixedPageRegion::new(0x4000, 0x4000, 1),
                FixedPageRegion::new(0x8000, 0x4000, 1),
            ],
            pending: None,
            channel: if cfg!(feature = "flash-managed-keys") {
                Some(0)
            } else {
                None
            },
        }
    }
    pub const fn pin(flash: &'static SharedFlash) -> Self {
        Self {
            flash,
            pages: [
                FixedPageRegion::new(0x10000, 0x10000, 1),
                FixedPageRegion::new(0x20000, 0x20000, 1),
            ],
            pending: None,
            channel: if cfg!(feature = "flash-managed-keys") {
                Some(1)
            } else {
                None
            },
        }
    }
    #[cfg(feature = "flash-managed-keys")]
    pub const fn keys(flash: &'static SharedFlash) -> Self {
        Self {
            flash,
            pages: [
                FixedPageRegion::new(0x10000, 0x10000, 1),
                FixedPageRegion::new(0x20000, 0x20000, 1),
            ],
            pending: None,
            channel: None,
        }
    }
    fn region(&self, page: usize) -> Result<FixedPageRegion, ()> {
        self.pages.get(page).copied().ok_or(())
    }
    fn read(&mut self, page: usize, bytes: &mut [u8]) -> Result<(), ()> {
        if let Some(channel) = self.channel {
            let bytes: &mut [u8; FLASH_SECTOR_SIZE] = bytes.try_into().map_err(|_| ())?;
            return paired(|j| j.read(channel, page, bytes));
        }
        if bytes.len() > FLASH_SECTOR_SIZE {
            return Err(());
        }
        let address = self
            .region(page)?
            .page_offset_for_len(0, bytes.len())
            .ok_or(())?;
        critical_section::with(|cs| {
            self.flash
                .borrow(cs)
                .borrow_mut()
                .blocking_read(address as u32, bytes)
                .map_err(|_| ())
        })
    }
    fn erase(&mut self, page: usize) -> Result<(), ()> {
        let region = self.region(page)?;
        critical_section::with(|cs| {
            self.flash
                .borrow(cs)
                .borrow_mut()
                .blocking_erase(region.base() as u32, region.end().ok_or(())? as u32)
                .map_err(|_| ())
        })
    }
    fn write(&mut self, page: usize, bytes: &[u8]) -> Result<(), ()> {
        if let Some(channel) = self.channel {
            let bytes = bytes.try_into().map_err(|_| ())?;
            return paired(|j| j.stage(channel, page, bytes));
        }
        if bytes.len() != FLASH_SECTOR_SIZE || bytes.len() % WRITE != 0 {
            return Err(());
        }
        self.pending = None;
        let address = self
            .region(page)?
            .page_offset_for_len(0, bytes.len())
            .ok_or(())? as u32;
        self.erase(page)?;
        critical_section::with(|cs| {
            let mut flash = self.flash.borrow(cs).borrow_mut();
            flash
                .blocking_write(address, &bytes[..STORAGE_PAGE_COMMIT_OFFSET])
                .map_err(|_| ())?;
            flash
                .blocking_write(
                    address + STORAGE_PAGE_COMMIT_OFFSET as u32 + 4,
                    &bytes[STORAGE_PAGE_COMMIT_OFFSET + 4..],
                )
                .map_err(|_| ())
        })?;
        self.pending = Some(page);
        Ok(())
    }
    fn commit(&mut self, page: usize) -> Result<(), ()> {
        if let Some(channel) = self.channel {
            return paired(|j| j.commit(channel, page));
        }
        if self.pending.take() != Some(page) {
            return Err(());
        }
        let address = self
            .region(page)?
            .page_offset_for_len(0, FLASH_SECTOR_SIZE)
            .ok_or(())? as u32;
        critical_section::with(|cs| {
            self.flash
                .borrow(cs)
                .borrow_mut()
                .blocking_write(address + STORAGE_PAGE_COMMIT_OFFSET as u32, b"CMIT")
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
        if let Some(channel) = self.channel {
            return paired(|j| j.clear(channel)).map_err(|_| StorageError::WriteFailed);
        }
        self.pending = None;
        for page in 0..2 {
            self.erase(page).map_err(|_| StorageError::WriteFailed)?;
        }
        Ok(())
    }
}

#[cfg(feature = "flash-managed-keys")]
type Paired = manekey::paired_journal::PairedJournal<FlashBanks, FLASH_SECTOR_SIZE>;
#[cfg(feature = "flash-managed-keys")]
static PAIRED: Mutex<RefCell<Option<Paired>>> = Mutex::new(RefCell::new(None));

/// Initialize the shared paired journal once before managed credential/PIN use.
pub fn initialize_records(flash: &'static SharedFlash) -> Result<(), ()> {
    #[cfg(feature = "flash-managed-keys")]
    {
        let journal = Paired::open(FlashBanks(flash), *b"F4-PAIR1").map_err(|_| ())?;
        critical_section::with(|cs| {
            let mut slot = PAIRED.borrow(cs).borrow_mut();
            if slot.is_some() {
                return Err(());
            }
            *slot = Some(journal);
            Ok(())
        })?;
    }
    let _ = flash;
    Ok(())
}

#[cfg(feature = "flash-managed-keys")]
fn paired<T>(
    f: impl FnOnce(&mut Paired) -> Result<T, manekey::paired_journal::Error>,
) -> Result<T, ()> {
    critical_section::with(|cs| {
        f(PAIRED.borrow(cs).borrow_mut().as_mut().ok_or(())?).map_err(|_| ())
    })
}

#[cfg(not(feature = "flash-managed-keys"))]
fn paired<T>(
    _: impl FnOnce(
        &mut manekey::paired_journal::PairedJournal<FlashBanks, FLASH_SECTOR_SIZE>,
    ) -> Result<T, manekey::paired_journal::Error>,
) -> Result<T, ()> {
    Err(())
}

struct FlashBanks(&'static SharedFlash);
impl manekey::paired_journal::Banks for FlashBanks {
    fn read(
        &mut self,
        bank: usize,
        offset: usize,
        bytes: &mut [u8],
    ) -> Result<(), manekey::paired_journal::Error> {
        let address = bank_address(bank, offset, bytes.len())?;
        critical_section::with(|cs| {
            self.0
                .borrow(cs)
                .borrow_mut()
                .blocking_read(address, bytes)
                .map_err(|_| manekey::paired_journal::Error::Io)
        })
    }
    fn erase(&mut self, bank: usize) -> Result<(), manekey::paired_journal::Error> {
        let address = bank_address(bank, 0, 0x4000)?;
        critical_section::with(|cs| {
            self.0
                .borrow(cs)
                .borrow_mut()
                .blocking_erase(address, address + 0x4000)
                .map_err(|_| manekey::paired_journal::Error::Io)
        })
    }
    fn program(
        &mut self,
        bank: usize,
        offset: usize,
        bytes: &[u8],
    ) -> Result<(), manekey::paired_journal::Error> {
        if offset % WRITE != 0 || bytes.len() % WRITE != 0 {
            return Err(manekey::paired_journal::Error::Invalid);
        }
        let address = bank_address(bank, offset, bytes.len())?;
        critical_section::with(|cs| {
            self.0
                .borrow(cs)
                .borrow_mut()
                .blocking_write(address, bytes)
                .map_err(|_| manekey::paired_journal::Error::Io)
        })
    }
}
fn bank_address(
    bank: usize,
    offset: usize,
    len: usize,
) -> Result<u32, manekey::paired_journal::Error> {
    if bank >= 2 || offset.checked_add(len).is_none_or(|end| end > 0x4000) {
        return Err(manekey::paired_journal::Error::Invalid);
    }
    Ok((0x4000 + bank * 0x4000 + offset) as u32)
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
