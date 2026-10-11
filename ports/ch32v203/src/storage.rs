#[cfg(feature = "flash-storage")]
use ch32_hal as hal;
#[cfg(feature = "flash-storage")]
use core::ptr::write_volatile;
#[cfg(feature = "flash-storage")]
use core::sync::atomic::{Ordering, fence};
#[cfg(feature = "client-pin-flash")]
use manekey::ctaphid::pin_uv_auth::{
    COMPACT_PIN_UV_AUTH_SLOT_SIZE, CompactPinUvAuthSlot, PinStorageError, PinUvAuthState,
    PinUvAuthStateStorage,
};
use manekey::ctaphid::storage::{StorageBackend, StorageError, mark_storage_page_committed};
#[cfg(feature = "flash-storage")]
use manekey::storage_region::{FixedPageRegion, normalize_repeated_erased_pattern};

const CH32_STORAGE_PAGE_SIZE: usize = manekey::ctaphid::storage::FLASH_SECTOR_SIZE;
#[cfg(feature = "flash-storage")]
const CH32_STORAGE_PAGE_COUNT: usize = 2;
#[cfg(feature = "client-pin-flash")]
const CH32_PIN_SLOT_COUNT: usize = 2;
#[cfg(feature = "client-pin-flash")]
const CH32_PIN_SLOT_SIZE: usize = COMPACT_PIN_UV_AUTH_SLOT_SIZE;

#[cfg(not(feature = "flash-storage"))]
/// One committed image only; no power-loss durability.
pub struct TinyVolatileStorage {
    page: [u8; CH32_STORAGE_PAGE_SIZE],
}

#[cfg(not(feature = "flash-storage"))]
impl TinyVolatileStorage {
    pub const fn new() -> Self {
        Self {
            page: [0xff; CH32_STORAGE_PAGE_SIZE],
        }
    }
}

#[cfg(not(feature = "flash-storage"))]
impl StorageBackend for TinyVolatileStorage {
    fn read_page(
        &mut self,
        _page: usize,
        buf: &mut [u8; CH32_STORAGE_PAGE_SIZE],
    ) -> Result<(), StorageError> {
        buf.copy_from_slice(&self.page);
        Ok(())
    }

    fn write_page(
        &mut self,
        _page: usize,
        buf: &[u8; CH32_STORAGE_PAGE_SIZE],
    ) -> Result<(), StorageError> {
        self.page.copy_from_slice(buf);
        Ok(())
    }

    fn commit_page(&mut self, _page: usize) -> Result<(), StorageError> {
        mark_storage_page_committed(&mut self.page)
    }

    fn clear_pages(&mut self) -> Result<(), StorageError> {
        self.page = [0xff; CH32_STORAGE_PAGE_SIZE];
        Ok(())
    }
}

#[cfg(feature = "flash-storage")]
/// Caller exclusively reserves the full region and prevents other Flash/IRQ/DMA owners.
/// Plain Flash has no encryption, rollback protection or physical secure-erasure guarantee; busy waits have no timeout.
/// write_page includes its commit marker; commit_page is a validation no-op, not a separate durable commit.
/// Power-cut behavior remains unqualified.
pub struct Ch32FlashRegion<const BASE: usize> {
    _private: (),
}

#[cfg(feature = "flash-storage")]
pub type Ch32FlashStorage =
    Ch32FlashRegion<{ 229_376 - CH32_STORAGE_PAGE_SIZE * CH32_STORAGE_PAGE_COUNT }>;

#[cfg(feature = "flash-managed-keys")]
pub type Ch32ManagedFlashStorage = Ch32FlashRegion<0x36e00>;

#[cfg(feature = "flash-managed-keys")]
const _: () = {
    assert!(CH32_STORAGE_PAGE_SIZE == 1024);
    assert!(0x36e00 + 2 * CH32_STORAGE_PAGE_SIZE == 0x37600);
};

#[cfg(feature = "flash-storage")]
impl<const BASE: usize> Ch32FlashRegion<BASE> {
    const FLASH_BASE: usize = 0x0800_0000;
    const FLASH_SIZE: usize = 229_376;
    const ERASED_PATTERN: [u8; 2] = [0x39, 0xe3];
    const STORAGE_REGION: FixedPageRegion =
        FixedPageRegion::new(BASE, CH32_STORAGE_PAGE_SIZE, CH32_STORAGE_PAGE_COUNT);
    const STORAGE_OFFSET: usize = Self::STORAGE_REGION.base();

    pub const fn new() -> Self {
        assert!(BASE >= 0x35e00);
        assert!(BASE % 256 == 0);
        assert!(BASE + CH32_STORAGE_PAGE_SIZE * CH32_STORAGE_PAGE_COUNT <= Self::FLASH_SIZE);
        Self { _private: () }
    }

    fn page_offset(page: usize) -> Result<u32, StorageError> {
        Self::STORAGE_REGION
            .page_offset_for_len(page, CH32_STORAGE_PAGE_SIZE)
            .and_then(|offset| u32::try_from(offset).ok())
            .ok_or(StorageError::ReadFailed)
    }

    fn contains_storage_range(offset: u32, len: usize) -> bool {
        Self::STORAGE_REGION.contains_range(offset as usize, len)
    }

    fn read(offset: u32, buf: &mut [u8]) -> Result<(), StorageError> {
        if !Self::contains_storage_range(offset, buf.len()) {
            return Err(StorageError::ReadFailed);
        }

        let source = unsafe {
            core::slice::from_raw_parts(
                (Self::FLASH_BASE + offset as usize) as *const u8,
                buf.len(),
            )
        };
        buf.copy_from_slice(source);
        Ok(())
    }

    fn erase(offset: u32, len: usize) -> Result<(), StorageError> {
        if offset as usize % 256 != 0 || len % 256 != 0 {
            return Err(StorageError::WriteFailed);
        }
        if !Self::contains_storage_range(offset, len) {
            return Err(StorageError::WriteFailed);
        }

        let mut current = offset;
        let end = offset
            .checked_add(u32::try_from(len).map_err(|_| StorageError::WriteFailed)?)
            .ok_or(StorageError::WriteFailed)?;
        while current < end {
            Self::erase_256(current)?;
            current += 256;
        }
        Ok(())
    }

    fn write(offset: u32, data: &[u8]) -> Result<(), StorageError> {
        if offset as usize % 256 != 0 || data.len() % 256 != 0 {
            return Err(StorageError::WriteFailed);
        }
        if !Self::contains_storage_range(offset, data.len()) {
            return Err(StorageError::WriteFailed);
        }

        let mut current = offset;
        for chunk in data.chunks_exact(256) {
            Self::write_256(current, chunk)?;
            current += 256;
        }
        Ok(())
    }

    #[unsafe(link_section = ".data.flash")]
    #[inline(never)]
    fn unlock() {
        if hal::pac::FLASH.ctlr().read().lock() {
            hal::pac::FLASH.keyr().write(|w| w.set_keyr(0x4567_0123));
            fence(Ordering::SeqCst);
            hal::pac::FLASH.keyr().write(|w| w.set_keyr(0xCDEF_89AB));
            fence(Ordering::SeqCst);
        }
        if hal::pac::FLASH.ctlr().read().flock() {
            hal::pac::FLASH
                .modekeyr()
                .write(|w| w.set_modekeyr(0x4567_0123));
            fence(Ordering::SeqCst);
            hal::pac::FLASH
                .modekeyr()
                .write(|w| w.set_modekeyr(0xCDEF_89AB));
            fence(Ordering::SeqCst);
        }
    }

    #[unsafe(link_section = ".data.flash")]
    #[inline(never)]
    fn lock() {
        hal::pac::FLASH.ctlr().modify(|w| {
            w.set_lock(true);
            w.set_flock(true);
        });
    }

    #[unsafe(link_section = ".data.flash")]
    #[inline(never)]
    fn clear_errors() {
        hal::pac::FLASH.statr().modify(|w| w.set_wrprterr(true));
    }

    #[unsafe(link_section = ".data.flash")]
    #[inline(never)]
    fn wait_ready() -> Result<(), StorageError> {
        loop {
            let status = hal::pac::FLASH.statr().read();
            if !status.bsy() {
                return if status.wrprterr() {
                    Err(StorageError::WriteFailed)
                } else {
                    Ok(())
                };
            }
        }
    }

    #[unsafe(link_section = ".data.flash")]
    #[inline(never)]
    fn wait_write_ready() -> Result<(), StorageError> {
        loop {
            let status = hal::pac::FLASH.statr().read();
            if !status.wr_bsy() {
                return if status.wrprterr() {
                    Err(StorageError::WriteFailed)
                } else {
                    Ok(())
                };
            }
        }
    }

    fn erase_256(offset: u32) -> Result<(), StorageError> {
        critical_section::with(|_| Self::erase_256_ram(offset))
    }

    #[unsafe(link_section = ".data.flash")]
    #[inline(never)]
    fn erase_256_ram(offset: u32) -> Result<(), StorageError> {
        let address = Self::FLASH_BASE as u32 + offset;
        Self::clear_errors();
        fence(Ordering::SeqCst);
        Self::unlock();
        fence(Ordering::SeqCst);

        hal::pac::FLASH.ctlr().modify(|w| w.set_page_er(true));
        hal::pac::FLASH.addr().write(|w| w.set_far(address));
        fence(Ordering::SeqCst);
        hal::pac::FLASH.ctlr().modify(|w| w.set_strt(true));
        let result = Self::wait_ready();
        hal::pac::FLASH.ctlr().modify(|w| w.set_page_er(false));
        Self::clear_errors();

        Self::lock();
        result
    }

    fn write_256(offset: u32, chunk: &[u8]) -> Result<(), StorageError> {
        critical_section::with(|_| {
            let result = Self::write_256_ram(offset, chunk);
            hal::pac::FLASH.ctlr().modify(|w| w.set_page_pg(false));
            Self::clear_errors();
            Self::lock();
            result
        })
    }

    #[unsafe(link_section = ".data.flash")]
    #[inline(never)]
    fn write_256_ram(offset: u32, chunk: &[u8]) -> Result<(), StorageError> {
        let address = Self::FLASH_BASE as u32 + offset;
        Self::clear_errors();
        fence(Ordering::SeqCst);
        Self::unlock();
        fence(Ordering::SeqCst);
        Self::wait_ready()?;
        Self::wait_write_ready()?;

        hal::pac::FLASH.ctlr().modify(|w| w.set_page_pg(true));
        let mut current = address;
        for word in chunk.chunks_exact(4) {
            unsafe {
                write_volatile(
                    current as *mut u32,
                    u32::from_le_bytes(word.try_into().unwrap()),
                );
            }
            current += 4;
            fence(Ordering::SeqCst);
            Self::wait_write_ready()?;
            fence(Ordering::SeqCst);
        }
        hal::pac::FLASH.ctlr().modify(|w| w.set_pgstart(true));
        Self::wait_ready()
    }
}

#[cfg(feature = "flash-storage")]
impl<const BASE: usize> StorageBackend for Ch32FlashRegion<BASE> {
    fn read_page(
        &mut self,
        page: usize,
        buf: &mut [u8; CH32_STORAGE_PAGE_SIZE],
    ) -> Result<(), StorageError> {
        let offset = Self::page_offset(page)?;
        Self::read(offset, buf)?;
        normalize_repeated_erased_pattern(buf, &Self::ERASED_PATTERN, 0xff);
        Ok(())
    }

    fn write_page(
        &mut self,
        page: usize,
        buf: &[u8; CH32_STORAGE_PAGE_SIZE],
    ) -> Result<(), StorageError> {
        let offset = Self::page_offset(page).map_err(|_| StorageError::WriteFailed)?;

        let mut committed_header = [0u8; 256];
        committed_header.copy_from_slice(&buf[..256]);
        mark_storage_page_committed(&mut committed_header)?;
        Self::erase(offset, CH32_STORAGE_PAGE_SIZE)?;
        Self::write(offset, &committed_header)?;
        Self::write(offset + 256, &buf[256..])
    }

    fn commit_page(&mut self, page: usize) -> Result<(), StorageError> {
        if page >= CH32_STORAGE_PAGE_COUNT {
            return Err(StorageError::WriteFailed);
        }

        Ok(())
    }

    fn clear_pages(&mut self) -> Result<(), StorageError> {
        Self::erase(
            Self::STORAGE_OFFSET as u32,
            CH32_STORAGE_PAGE_COUNT * CH32_STORAGE_PAGE_SIZE,
        )
    }
}

#[cfg(feature = "client-pin-flash")]
/// Two CRC/sequence slots, not wear leveling; caller reserves their erase units exclusively.
/// If neither slot is valid, current load semantics return PIN-unset.
pub struct Ch32PinUvAuthFlashStorage;

#[cfg(feature = "client-pin-flash")]
impl Ch32PinUvAuthFlashStorage {
    const PIN_REGION: FixedPageRegion = FixedPageRegion::new(
        Ch32FlashStorage::STORAGE_REGION.base() - CH32_PIN_SLOT_COUNT * CH32_PIN_SLOT_SIZE,
        CH32_PIN_SLOT_SIZE,
        CH32_PIN_SLOT_COUNT,
    );
    pub const fn new() -> Self {
        Self
    }

    fn slot_offset(slot: usize) -> Result<u32, PinStorageError> {
        Self::PIN_REGION
            .page_offset_for_len(slot, CH32_PIN_SLOT_SIZE)
            .and_then(|offset| u32::try_from(offset).ok())
            .ok_or(PinStorageError::ReadFailed)
    }

    fn read_slot(
        &self,
        slot: usize,
        buf: &mut [u8; CH32_PIN_SLOT_SIZE],
    ) -> Result<(), PinStorageError> {
        let offset = Self::slot_offset(slot)?;
        let source = unsafe {
            core::slice::from_raw_parts(
                (Ch32FlashStorage::FLASH_BASE + offset as usize) as *const u8,
                buf.len(),
            )
        };
        buf.copy_from_slice(source);
        normalize_repeated_erased_pattern(buf, &Ch32FlashStorage::ERASED_PATTERN, 0xff);
        Ok(())
    }

    fn load_active_slot(&self) -> Result<Option<(usize, u32, PinUvAuthState)>, PinStorageError> {
        let mut first = [0xff; CH32_PIN_SLOT_SIZE];
        let mut second = [0xff; CH32_PIN_SLOT_SIZE];
        self.read_slot(0, &mut first)?;
        self.read_slot(1, &mut second)?;
        Ok(CompactPinUvAuthSlot::newest(&first, &second))
    }
}

#[cfg(feature = "client-pin-flash")]
impl PinUvAuthStateStorage for Ch32PinUvAuthFlashStorage {
    fn load_pin_state(&mut self) -> Result<PinUvAuthState, PinStorageError> {
        Ok(self
            .load_active_slot()?
            .map(|(_, _, state)| state)
            .unwrap_or_else(PinUvAuthState::new_unset))
    }

    fn store_pin_state(&mut self, state: &PinUvAuthState) -> Result<(), PinStorageError> {
        let active = self.load_active_slot()?;
        let (target, sequence) = match active {
            Some((0, sequence, _)) => (1, sequence.wrapping_add(1)),
            Some((1, sequence, _)) => (0, sequence.wrapping_add(1)),
            Some(_) => return Err(PinStorageError::WriteFailed),
            None => (0, 1),
        };
        let offset = Self::slot_offset(target).map_err(|_| PinStorageError::WriteFailed)?;
        let mut slot = [0xff; CH32_PIN_SLOT_SIZE];
        CompactPinUvAuthSlot::encode(&mut slot, sequence, state);
        Ch32FlashStorage::erase_256(offset).map_err(|_| PinStorageError::WriteFailed)?;
        Ch32FlashStorage::write_256(offset, &slot).map_err(|_| PinStorageError::WriteFailed)
    }
}

#[cfg(feature = "flash-storage")]
pub type SelectedStorage = Ch32FlashStorage;
#[cfg(not(feature = "flash-storage"))]
pub type SelectedStorage = TinyVolatileStorage;
