use super::PIN_STORAGE_PAGE_COUNT;
use manekey::ctaphid::pin_uv_auth::{PIN_UV_AUTH_PAGE_SIZE, PinStorageError, PinUvAuthPageBackend};
#[cfg(all(
    feature = "riscv-rp2350-hal",
    target_arch = "riscv32",
    target_os = "none"
))]
use manekey::ctaphid::storage::mark_storage_page_committed;
use manekey::ctaphid::storage::{
    FLASH_SECTOR_SIZE, STORAGE_PAGE_COUNT, StorageBackend, StorageError,
};
#[cfg(all(
    any(
        feature = "chip-rp2040",
        feature = "chip-rp235xa",
        feature = "chip-rp235xa-nonsecure"
    ),
    target_arch = "arm",
    target_os = "none"
))]
use manekey::ctaphid::storage::{
    STORAGE_PAGE_COMMIT_MARKER as PAGE_COMMIT_MARKER,
    STORAGE_PAGE_COMMIT_OFFSET as PAGE_COMMIT_OFFSET, Storage,
};

#[cfg(all(
    any(
        feature = "chip-rp2040",
        feature = "chip-rp235xa",
        feature = "chip-rp235xa-nonsecure"
    ),
    target_arch = "arm",
    target_os = "none"
))]
use core::cell::RefCell;

#[cfg(all(
    any(
        feature = "chip-rp2040",
        feature = "chip-rp235xa",
        feature = "chip-rp235xa-nonsecure"
    ),
    target_arch = "arm",
    target_os = "none"
))]
use embassy_rp::{
    flash::{Blocking, Flash},
    peripherals,
};
#[cfg(all(
    any(
        feature = "chip-rp2040",
        feature = "chip-rp235xa",
        feature = "chip-rp235xa-nonsecure"
    ),
    target_arch = "arm",
    target_os = "none"
))]
use embassy_sync::blocking_mutex::{Mutex, raw::CriticalSectionRawMutex};

#[cfg(all(feature = "chip-rp2040", target_arch = "arm", target_os = "none"))]
const FLASH_SIZE: usize = 2 * 1024 * 1024;
#[cfg(all(
    any(feature = "chip-rp235xa", feature = "chip-rp235xa-nonsecure"),
    target_arch = "arm",
    target_os = "none"
))]
const FLASH_SIZE: usize = manekey::security::layout::FLASH_SIZE;
#[cfg(all(
    feature = "riscv-rp2350-hal",
    target_arch = "riscv32",
    target_os = "none"
))]
const FLASH_SIZE: usize = 4 * 1024 * 1024;

const PIN_STORAGE_OFFSET: usize =
    FLASH_SIZE - (STORAGE_PAGE_COUNT + PIN_STORAGE_PAGE_COUNT) * FLASH_SECTOR_SIZE;

#[cfg(any(
    all(
        feature = "riscv-rp2350-hal",
        target_arch = "riscv32",
        target_os = "none"
    ),
    all(
        any(feature = "chip-rp2040", feature = "chip-rp235xa"),
        target_arch = "arm",
        target_os = "none"
    )
))]
const BLE_BOND_STORAGE_OFFSET: usize = PIN_STORAGE_OFFSET - FLASH_SECTOR_SIZE;

#[cfg(all(
    target_arch = "arm",
    target_os = "none",
    any(feature = "chip-rp235xa", feature = "chip-rp235xa-nonsecure")
))]
const _: () = assert!(PIN_STORAGE_OFFSET == manekey::security::layout::SECURE_STORAGE_OFFSET);

const STORAGE_REGION: manekey::storage_region::FixedPageRegion =
    manekey::storage_region::FixedPageRegion::from_end(
        FLASH_SIZE,
        FLASH_SECTOR_SIZE,
        STORAGE_PAGE_COUNT,
    );
const STORAGE_OFFSET: usize = STORAGE_REGION.base();
const PIN_STORAGE_REGION: manekey::storage_region::FixedPageRegion =
    manekey::storage_region::FixedPageRegion::new(
        PIN_STORAGE_OFFSET,
        PIN_UV_AUTH_PAGE_SIZE,
        PIN_STORAGE_PAGE_COUNT,
    );

fn page_offset(page: usize) -> Result<usize, StorageError> {
    STORAGE_REGION
        .page_offset_for_len(page, FLASH_SECTOR_SIZE)
        .ok_or(StorageError::ReadFailed)
}

#[cfg(all(
    any(
        feature = "chip-rp2040",
        feature = "chip-rp235xa",
        feature = "chip-rp235xa-nonsecure"
    ),
    target_arch = "arm",
    target_os = "none"
))]
fn storage_region_end() -> Result<usize, StorageError> {
    STORAGE_REGION.end().ok_or(StorageError::ReadFailed)
}

fn pin_page_offset(page: usize) -> Result<usize, PinStorageError> {
    PIN_STORAGE_REGION
        .page_offset_for_len(page, PIN_UV_AUTH_PAGE_SIZE)
        .ok_or(PinStorageError::ReadFailed)
}

#[cfg(all(
    any(
        feature = "chip-rp2040",
        feature = "chip-rp235xa",
        feature = "chip-rp235xa-nonsecure"
    ),
    target_arch = "arm",
    target_os = "none"
))]

/// Dedicated Arm credential journal; reserve actual Flash geometry and HAL core/IRQ exclusion.
/// Power-loss qualification is not provided by this adapter.
pub struct FlashStorage<'d> {
    flash: Flash<'d, peripherals::FLASH, Blocking, FLASH_SIZE>,
}

#[cfg(all(
    any(
        feature = "chip-rp2040",
        feature = "chip-rp235xa",
        feature = "chip-rp235xa-nonsecure"
    ),
    target_arch = "arm",
    target_os = "none"
))]
impl<'d> FlashStorage<'d> {
    pub fn new(flash: Flash<'d, peripherals::FLASH, Blocking, FLASH_SIZE>) -> Self {
        Self { flash }
    }
}

#[cfg(all(
    any(
        feature = "chip-rp2040",
        feature = "chip-rp235xa",
        feature = "chip-rp235xa-nonsecure"
    ),
    target_arch = "arm",
    target_os = "none"
))]
impl<'d> StorageBackend for FlashStorage<'d> {
    fn read_page(
        &mut self,
        page: usize,
        buf: &mut [u8; FLASH_SECTOR_SIZE],
    ) -> Result<(), StorageError> {
        let offset = page_offset(page)?;
        self.flash
            .blocking_read(offset as u32, buf)
            .map_err(|_| StorageError::ReadFailed)
    }

    fn write_page(
        &mut self,
        page: usize,
        buf: &[u8; FLASH_SECTOR_SIZE],
    ) -> Result<(), StorageError> {
        let offset = page_offset(page).map_err(|_| StorageError::WriteFailed)?;
        let end = offset
            .checked_add(FLASH_SECTOR_SIZE)
            .ok_or(StorageError::WriteFailed)?;
        self.flash
            .blocking_erase(offset as u32, end as u32)
            .map_err(|_| StorageError::WriteFailed)?;

        self.flash
            .blocking_write(offset as u32, buf)
            .map_err(|_| StorageError::WriteFailed)?;

        Ok(())
    }

    fn commit_page(&mut self, page: usize) -> Result<(), StorageError> {
        let offset = page_offset(page).map_err(|_| StorageError::WriteFailed)? + PAGE_COMMIT_OFFSET;
        self.flash
            .blocking_write(offset as u32, &PAGE_COMMIT_MARKER)
            .map_err(|_| StorageError::WriteFailed)?;

        Ok(())
    }

    fn clear_pages(&mut self) -> Result<(), StorageError> {
        let end = storage_region_end().map_err(|_| StorageError::WriteFailed)?;
        self.flash
            .blocking_erase(STORAGE_OFFSET as u32, end as u32)
            .map_err(|_| StorageError::WriteFailed)?;

        Ok(())
    }
}

#[cfg(all(
    feature = "riscv-rp2350-hal",
    target_arch = "riscv32",
    target_os = "none"
))]
const XIP_BASE: usize = 0x1000_0000;
#[cfg(all(
    feature = "riscv-rp2350-hal",
    target_arch = "riscv32",
    target_os = "none"
))]
const FLASH_PROGRAM_PAGE_SIZE: usize = 256;
#[cfg(all(
    feature = "riscv-rp2350-hal",
    target_arch = "riscv32",
    target_os = "none"
))]
const FLASH_DISABLE_BLOCK_ERASE: u32 = 1 << 31;
#[cfg(all(
    feature = "riscv-rp2350-hal",
    target_arch = "riscv32",
    target_os = "none"
))]
const MSTATUS_MIE: usize = 1 << 3;

#[cfg(all(
    feature = "riscv-rp2350-hal",
    target_arch = "riscv32",
    target_os = "none"
))]
fn riscv_flash_read(offset: usize, buf: &mut [u8]) -> Result<(), StorageError> {
    if offset
        .checked_add(buf.len())
        .is_none_or(|end| end > FLASH_SIZE)
    {
        return Err(StorageError::ReadFailed);
    }

    let source =
        unsafe { core::slice::from_raw_parts((XIP_BASE + offset) as *const u8, buf.len()) };
    buf.copy_from_slice(source);
    Ok(())
}

#[cfg(all(
    feature = "riscv-rp2350-hal",
    target_arch = "riscv32",
    target_os = "none"
))]
#[inline(never)]
#[unsafe(link_section = ".data.ram_func")]
/// RAM-resident Flash operation; caller quiesces every other XIP master, hart and DMA/debug access.
fn riscv_flash_erase(offset: usize, len: usize) -> Result<(), StorageError> {
    if offset % FLASH_SECTOR_SIZE != 0
        || len % FLASH_SECTOR_SIZE != 0
        || offset.checked_add(len).is_none_or(|end| end > FLASH_SIZE)
    {
        return Err(StorageError::WriteFailed);
    }

    unsafe {
        let previous_mstatus: usize;
        core::arch::asm!(
            "csrrc {previous}, mstatus, {mie}",
            previous = out(reg) previous_mstatus,
            mie = in(reg) MSTATUS_MIE,
            options(nomem, nostack)
        );
        rp235x_hal::rom_data::connect_internal_flash();
        rp235x_hal::rom_data::flash_exit_xip();
        rp235x_hal::rom_data::flash_range_erase(offset as u32, len, FLASH_DISABLE_BLOCK_ERASE, 0);
        rp235x_hal::rom_data::flash_flush_cache();
        rp235x_hal::rom_data::flash_enter_cmd_xip();
        if previous_mstatus & MSTATUS_MIE != 0 {
            core::arch::asm!(
                "csrs mstatus, {mie}",
                mie = in(reg) MSTATUS_MIE,
                options(nomem, nostack)
            );
        }
    }
    Ok(())
}

#[cfg(all(
    feature = "riscv-rp2350-hal",
    target_arch = "riscv32",
    target_os = "none"
))]
#[inline(never)]
#[unsafe(link_section = ".data.ram_func")]
/// Requires RAM-backed input and the same complete XIP-master exclusion as erase.
fn riscv_flash_program(offset: usize, data: &[u8]) -> Result<(), StorageError> {
    if offset % FLASH_PROGRAM_PAGE_SIZE != 0
        || data.len() % FLASH_PROGRAM_PAGE_SIZE != 0
        || offset
            .checked_add(data.len())
            .is_none_or(|end| end > FLASH_SIZE)
    {
        return Err(StorageError::WriteFailed);
    }

    unsafe {
        let previous_mstatus: usize;
        core::arch::asm!(
            "csrrc {previous}, mstatus, {mie}",
            previous = out(reg) previous_mstatus,
            mie = in(reg) MSTATUS_MIE,
            options(nomem, nostack)
        );
        rp235x_hal::rom_data::connect_internal_flash();
        rp235x_hal::rom_data::flash_exit_xip();
        rp235x_hal::rom_data::flash_range_program(offset as u32, data.as_ptr(), data.len());
        rp235x_hal::rom_data::flash_flush_cache();
        rp235x_hal::rom_data::flash_enter_cmd_xip();
        if previous_mstatus & MSTATUS_MIE != 0 {
            core::arch::asm!(
                "csrs mstatus, {mie}",
                mie = in(reg) MSTATUS_MIE,
                options(nomem, nostack)
            );
        }
    }
    Ok(())
}

#[cfg(all(
    feature = "riscv-rp2350-hal",
    target_arch = "riscv32",
    target_os = "none"
))]

/// Exclusive RAM/ROM Flash owner; park other harts and quiesce XIP masters.
/// write_page includes the commit marker; commit_page validates only the index, not an atomic commit.
pub struct RiscvFlashStorage;

#[cfg(all(
    feature = "riscv-flash-managed-keys",
    target_arch = "riscv32",
    target_os = "none"
))]
/// Reserved plaintext assets using the same ROM/XIP exclusion and nonseparate commit contract.
/// Raw clear_pages erases root assets; it is not CTAP reset.
pub struct RiscvManagedKeyFlashStorage;

#[cfg(all(
    feature = "riscv-flash-managed-keys",
    target_arch = "riscv32",
    target_os = "none"
))]
const _: () =
    assert!(FLASH_SECTOR_SIZE == crate::platform::rp2350::flash_layout::MANAGED_KEYS.page_size());

#[cfg(all(
    feature = "riscv-flash-managed-keys",
    target_arch = "riscv32",
    target_os = "none"
))]
impl StorageBackend for RiscvManagedKeyFlashStorage {
    fn read_page(
        &mut self,
        page: usize,
        buf: &mut [u8; FLASH_SECTOR_SIZE],
    ) -> Result<(), StorageError> {
        let offset = crate::platform::rp2350::flash_layout::MANAGED_KEYS
            .page_offset(page)
            .ok_or(StorageError::ReadFailed)?;
        riscv_flash_read(offset, buf)
    }
    fn write_page(
        &mut self,
        page: usize,
        buf: &[u8; FLASH_SECTOR_SIZE],
    ) -> Result<(), StorageError> {
        let offset = crate::platform::rp2350::flash_layout::MANAGED_KEYS
            .page_offset(page)
            .ok_or(StorageError::WriteFailed)?;
        let mut committed = zeroize::Zeroizing::new(*buf);
        mark_storage_page_committed(&mut committed[..])?;

        riscv_flash_erase(offset, FLASH_SECTOR_SIZE)?;
        riscv_flash_program(offset, committed.as_ref())
    }
    fn commit_page(&mut self, page: usize) -> Result<(), StorageError> {
        crate::platform::rp2350::flash_layout::MANAGED_KEYS
            .page_offset(page)
            .ok_or(StorageError::WriteFailed)?;
        Ok(())
    }
    fn clear_pages(&mut self) -> Result<(), StorageError> {
        let region = crate::platform::rp2350::flash_layout::MANAGED_KEYS;
        riscv_flash_erase(region.base(), region.len())
    }
}

#[cfg(all(
    feature = "riscv-rp2350-hal",
    target_arch = "riscv32",
    target_os = "none"
))]
impl RiscvFlashStorage {
    pub const fn new() -> Self {
        Self
    }
}

#[cfg(all(
    feature = "riscv-rp2350-hal",
    target_arch = "riscv32",
    target_os = "none"
))]
impl StorageBackend for RiscvFlashStorage {
    fn read_page(
        &mut self,
        page: usize,
        buf: &mut [u8; FLASH_SECTOR_SIZE],
    ) -> Result<(), StorageError> {
        riscv_flash_read(page_offset(page)?, buf)
    }

    fn write_page(
        &mut self,
        page: usize,
        buf: &[u8; FLASH_SECTOR_SIZE],
    ) -> Result<(), StorageError> {
        let offset = page_offset(page).map_err(|_| StorageError::WriteFailed)?;
        let mut committed = *buf;
        mark_storage_page_committed(&mut committed)?;
        riscv_flash_erase(offset, FLASH_SECTOR_SIZE)?;
        riscv_flash_program(offset, &committed)
    }

    fn commit_page(&mut self, page: usize) -> Result<(), StorageError> {
        page_offset(page).map_err(|_| StorageError::WriteFailed)?;

        Ok(())
    }

    fn clear_pages(&mut self) -> Result<(), StorageError> {
        riscv_flash_erase(
            STORAGE_OFFSET,
            STORAGE_REGION
                .checked_len()
                .ok_or(StorageError::WriteFailed)?,
        )
    }
}

#[cfg(all(
    feature = "riscv-rp2350-hal",
    target_arch = "riscv32",
    target_os = "none"
))]

/// Exclusive PIN journal with the same ROM/XIP and nonseparate commit contract.
pub struct RiscvPinUvAuthFlashStorage;

#[cfg(all(
    feature = "riscv-rp2350-hal",
    target_arch = "riscv32",
    target_os = "none"
))]
impl RiscvPinUvAuthFlashStorage {
    pub const fn new() -> Self {
        Self
    }
}

#[cfg(all(
    feature = "riscv-rp2350-hal",
    target_arch = "riscv32",
    target_os = "none"
))]
impl PinUvAuthPageBackend for RiscvPinUvAuthFlashStorage {
    fn read_pin_page(
        &mut self,
        page: usize,
        buf: &mut [u8; PIN_UV_AUTH_PAGE_SIZE],
    ) -> Result<(), PinStorageError> {
        riscv_flash_read(
            pin_page_offset(page).map_err(|_| PinStorageError::ReadFailed)?,
            buf,
        )
        .map_err(|_| PinStorageError::ReadFailed)
    }

    fn write_pin_page(
        &mut self,
        page: usize,
        buf: &[u8; PIN_UV_AUTH_PAGE_SIZE],
    ) -> Result<(), PinStorageError> {
        let offset = pin_page_offset(page).map_err(|_| PinStorageError::WriteFailed)?;
        let mut committed = *buf;
        mark_storage_page_committed(&mut committed).map_err(|_| PinStorageError::WriteFailed)?;
        riscv_flash_erase(offset, PIN_UV_AUTH_PAGE_SIZE)
            .map_err(|_| PinStorageError::WriteFailed)?;
        riscv_flash_program(offset, &committed).map_err(|_| PinStorageError::WriteFailed)
    }

    fn commit_pin_page(&mut self, page: usize) -> Result<(), PinStorageError> {
        pin_page_offset(page).map_err(|_| PinStorageError::WriteFailed)?;

        Ok(())
    }
}

#[cfg(all(
    feature = "riscv-rp2350-hal",
    target_arch = "riscv32",
    target_os = "none"
))]

/// One plaintext bond sector; rewrite has no power-loss atomicity guarantee.
pub struct RiscvBleBondFlashStorage;

#[cfg(all(
    feature = "riscv-rp2350-hal",
    target_arch = "riscv32",
    target_os = "none"
))]
impl RiscvBleBondFlashStorage {
    pub const fn new() -> Self {
        Self
    }
}

#[cfg(all(
    feature = "riscv-rp2350-hal",
    target_arch = "riscv32",
    target_os = "none"
))]
impl manekey::transport::ble::BleBondStore for RiscvBleBondFlashStorage {
    fn load_bonds<F>(&mut self, mut visit: F)
    where
        F: FnMut(manekey::transport::ble::StoredBleBond),
    {
        let mut encoded = [0xff; manekey::transport::ble::BLE_BOND_RECORD_LEN];
        if riscv_flash_read(BLE_BOND_STORAGE_OFFSET, &mut encoded).is_ok()
            && let Some(bond) = manekey::transport::ble::StoredBleBond::decode(&encoded)
        {
            visit(bond);
        }
    }

    fn store_bond(&mut self, bond: manekey::transport::ble::StoredBleBond) -> bool {
        let encoded = bond.encode();
        let mut page = [0xff; FLASH_PROGRAM_PAGE_SIZE];
        page[..encoded.len()].copy_from_slice(&encoded);
        riscv_flash_erase(BLE_BOND_STORAGE_OFFSET, FLASH_SECTOR_SIZE).is_ok()
            && riscv_flash_program(BLE_BOND_STORAGE_OFFSET, &page).is_ok()
    }

    fn clear_bonds(&mut self) -> bool {
        riscv_flash_erase(BLE_BOND_STORAGE_OFFSET, FLASH_SECTOR_SIZE).is_ok()
    }
}

#[cfg(all(
    any(
        feature = "chip-rp2040",
        feature = "chip-rp235xa",
        feature = "chip-rp235xa-nonsecure"
    ),
    target_arch = "arm",
    target_os = "none"
))]

pub type FlashBackedStorage<'d> = Storage<FlashStorage<'d>>;

#[cfg(all(
    any(
        feature = "chip-rp2040",
        feature = "chip-rp235xa",
        feature = "chip-rp235xa-nonsecure"
    ),
    target_arch = "arm",
    target_os = "none"
))]

/// Shared HAL Flash owner; critical section does not replace required other-core/XIP exclusion.
pub type SharedRpFlash<'d> =
    Mutex<CriticalSectionRawMutex, RefCell<Flash<'d, peripherals::FLASH, Blocking, FLASH_SIZE>>>;

#[cfg(all(
    any(feature = "chip-rp2040", feature = "chip-rp235xa"),
    target_arch = "arm",
    target_os = "none"
))]

/// Single plaintext bond sector under the shared HAL owner; no atomic replacement guarantee.
pub struct SharedBleBondFlashStorage<'d> {
    flash: &'d SharedRpFlash<'d>,
}

#[cfg(all(
    any(feature = "chip-rp2040", feature = "chip-rp235xa"),
    target_arch = "arm",
    target_os = "none"
))]
impl<'d> SharedBleBondFlashStorage<'d> {
    pub const fn new(flash: &'d SharedRpFlash<'d>) -> Self {
        Self { flash }
    }
}

#[cfg(all(
    any(feature = "chip-rp2040", feature = "chip-rp235xa"),
    target_arch = "arm",
    target_os = "none"
))]
impl manekey::transport::ble::BleBondStore for SharedBleBondFlashStorage<'_> {
    fn load_bonds<F>(&mut self, mut visit: F)
    where
        F: FnMut(manekey::transport::ble::StoredBleBond),
    {
        let mut encoded = [0xff; manekey::transport::ble::BLE_BOND_RECORD_LEN];
        if self
            .flash
            .lock(|flash| {
                flash
                    .borrow_mut()
                    .blocking_read(BLE_BOND_STORAGE_OFFSET as u32, &mut encoded)
            })
            .is_ok()
            && let Some(bond) = manekey::transport::ble::StoredBleBond::decode(&encoded)
        {
            visit(bond);
        }
    }

    fn store_bond(&mut self, bond: manekey::transport::ble::StoredBleBond) -> bool {
        let encoded = bond.encode();
        let mut page = [0xff; 256];
        page[..encoded.len()].copy_from_slice(&encoded);
        self.flash
            .lock(|flash| {
                let mut flash = flash.borrow_mut();
                flash.blocking_erase(
                    BLE_BOND_STORAGE_OFFSET as u32,
                    (BLE_BOND_STORAGE_OFFSET + FLASH_SECTOR_SIZE) as u32,
                )?;
                flash.blocking_write(BLE_BOND_STORAGE_OFFSET as u32, &page)
            })
            .is_ok()
    }

    fn clear_bonds(&mut self) -> bool {
        self.flash
            .lock(|flash| {
                flash.borrow_mut().blocking_erase(
                    BLE_BOND_STORAGE_OFFSET as u32,
                    (BLE_BOND_STORAGE_OFFSET + FLASH_SECTOR_SIZE) as u32,
                )
            })
            .is_ok()
    }
}

#[cfg(all(
    any(
        feature = "chip-rp2040",
        feature = "chip-rp235xa",
        feature = "chip-rp235xa-nonsecure"
    ),
    target_arch = "arm",
    target_os = "none"
))]

/// Credential view of the shared Flash owner; reserve dedicated journal sectors.
pub struct SharedFlashStorage<'d> {
    flash: &'d SharedRpFlash<'d>,
}

#[cfg(all(
    any(
        feature = "chip-rp2040",
        feature = "chip-rp235xa",
        feature = "chip-rp235xa-nonsecure"
    ),
    target_arch = "arm",
    target_os = "none"
))]
impl<'d> SharedFlashStorage<'d> {
    pub fn new(flash: &'d SharedRpFlash<'d>) -> Self {
        Self { flash }
    }
}

#[cfg(all(
    any(
        feature = "chip-rp2040",
        feature = "chip-rp235xa",
        feature = "chip-rp235xa-nonsecure"
    ),
    target_arch = "arm",
    target_os = "none"
))]
impl<'d> StorageBackend for SharedFlashStorage<'d> {
    fn read_page(
        &mut self,
        page: usize,
        buf: &mut [u8; FLASH_SECTOR_SIZE],
    ) -> Result<(), StorageError> {
        let offset = page_offset(page)?;
        self.flash
            .lock(|flash| flash.borrow_mut().blocking_read(offset as u32, buf))
            .map_err(|_| StorageError::ReadFailed)
    }

    fn write_page(
        &mut self,
        page: usize,
        buf: &[u8; FLASH_SECTOR_SIZE],
    ) -> Result<(), StorageError> {
        let offset = page_offset(page).map_err(|_| StorageError::WriteFailed)?;
        let end = offset
            .checked_add(FLASH_SECTOR_SIZE)
            .ok_or(StorageError::WriteFailed)?;
        self.flash
            .lock(|flash| {
                let mut flash = flash.borrow_mut();
                flash.blocking_erase(offset as u32, end as u32)?;
                flash.blocking_write(offset as u32, buf)
            })
            .map_err(|_| StorageError::WriteFailed)?;

        Ok(())
    }

    fn commit_page(&mut self, page: usize) -> Result<(), StorageError> {
        let offset = page_offset(page).map_err(|_| StorageError::WriteFailed)? + PAGE_COMMIT_OFFSET;
        self.flash
            .lock(|flash| {
                flash
                    .borrow_mut()
                    .blocking_write(offset as u32, &PAGE_COMMIT_MARKER)
            })
            .map_err(|_| StorageError::WriteFailed)?;

        Ok(())
    }

    fn clear_pages(&mut self) -> Result<(), StorageError> {
        let end = storage_region_end().map_err(|_| StorageError::WriteFailed)?;
        self.flash
            .lock(|flash| {
                flash
                    .borrow_mut()
                    .blocking_erase(STORAGE_OFFSET as u32, end as u32)
            })
            .map_err(|_| StorageError::WriteFailed)?;

        Ok(())
    }
}

#[cfg(all(
    any(
        feature = "chip-rp2040",
        feature = "chip-rp235xa",
        feature = "chip-rp235xa-nonsecure"
    ),
    target_arch = "arm",
    target_os = "none"
))]

/// PIN view sharing the same serialized controller while reserving disjoint journal sectors.
pub struct SharedPinUvAuthFlashStorage<'d> {
    flash: &'d SharedRpFlash<'d>,
}

#[cfg(all(
    any(
        feature = "chip-rp2040",
        feature = "chip-rp235xa",
        feature = "chip-rp235xa-nonsecure"
    ),
    target_arch = "arm",
    target_os = "none"
))]
impl<'d> SharedPinUvAuthFlashStorage<'d> {
    pub fn new(flash: &'d SharedRpFlash<'d>) -> Self {
        Self { flash }
    }
}

#[cfg(all(
    any(
        feature = "chip-rp2040",
        feature = "chip-rp235xa",
        feature = "chip-rp235xa-nonsecure"
    ),
    target_arch = "arm",
    target_os = "none"
))]
impl<'d> PinUvAuthPageBackend for SharedPinUvAuthFlashStorage<'d> {
    fn read_pin_page(
        &mut self,
        page: usize,
        buf: &mut [u8; PIN_UV_AUTH_PAGE_SIZE],
    ) -> Result<(), PinStorageError> {
        let offset = pin_page_offset(page)?;
        self.flash
            .lock(|flash| flash.borrow_mut().blocking_read(offset as u32, buf))
            .map_err(|_| PinStorageError::ReadFailed)
    }

    fn write_pin_page(
        &mut self,
        page: usize,
        buf: &[u8; PIN_UV_AUTH_PAGE_SIZE],
    ) -> Result<(), PinStorageError> {
        let offset = pin_page_offset(page).map_err(|_| PinStorageError::WriteFailed)?;
        self.flash
            .lock(|flash| {
                let mut flash = flash.borrow_mut();
                flash.blocking_erase(offset as u32, (offset + PIN_UV_AUTH_PAGE_SIZE) as u32)?;
                flash.blocking_write(offset as u32, buf)
            })
            .map_err(|_| PinStorageError::WriteFailed)?;

        Ok(())
    }

    fn commit_pin_page(&mut self, page: usize) -> Result<(), PinStorageError> {
        let offset =
            pin_page_offset(page).map_err(|_| PinStorageError::WriteFailed)? + PAGE_COMMIT_OFFSET;
        self.flash
            .lock(|flash| {
                flash
                    .borrow_mut()
                    .blocking_write(offset as u32, &PAGE_COMMIT_MARKER)
            })
            .map_err(|_| PinStorageError::WriteFailed)?;

        Ok(())
    }
}

#[cfg(all(
    any(
        feature = "chip-rp2040",
        feature = "chip-rp235xa",
        feature = "chip-rp235xa-nonsecure"
    ),
    target_arch = "arm",
    target_os = "none"
))]

pub type SharedFlashBackedStorage<'d> = Storage<SharedFlashStorage<'d>>;
