#[cfg(feature = "nrf-flash-storage")]
use cortex_m::asm;
#[cfg(feature = "client-pin-flash-storage")]
use manekey::ctaphid::pin_uv_auth::{
    PIN_PAGE_COMMIT_MARKER, PIN_PAGE_COMMIT_OFFSET, PIN_UV_AUTH_PAGE_SIZE, PinStorageError,
    PinUvAuthPageBackend,
};
use manekey::ctaphid::storage::Storage;
#[cfg(not(feature = "nrf-flash-storage"))]
use manekey::ctaphid::storage::StubStorage;
#[cfg(feature = "nrf-flash-storage")]
use manekey::ctaphid::storage::{
    STORAGE_PAGE_COMMIT_MARKER, STORAGE_PAGE_COMMIT_OFFSET, StorageBackend, StorageError,
};
#[cfg(feature = "nrf-flash-storage")]
use manekey::storage_region::FixedPageRegion;
#[cfg(feature = "nrf-flash-storage")]
use nrf_softdevice::raw;
use nrf52840_pac::NVMC;

#[cfg(feature = "nrf-flash-storage")]
const NRF_FLASH_PAGE_SIZE: usize = 4096;
#[cfg(feature = "nrf-flash-storage")]
const NRF_FLASH_CREDENTIAL_PAGE_COUNT: usize = 2;
#[cfg(feature = "nrf-flash-storage")]
const NRF_FLASH_BLE_BOND_PAGE_COUNT: usize = 1;
#[cfg(feature = "nrf-flash-storage")]
const NRF_FLASH_CREDENTIAL_BASE: usize = 0x000E_0000;
#[cfg(feature = "nrf-flash-storage")]
const NRF_FLASH_BLE_BOND_BASE: usize =
    NRF_FLASH_CREDENTIAL_BASE + NRF_FLASH_PAGE_SIZE * NRF_FLASH_CREDENTIAL_PAGE_COUNT;
#[cfg(feature = "client-pin-flash-storage")]
const NRF_FLASH_PIN_BASE: usize = NRF_FLASH_BLE_BOND_BASE + NRF_FLASH_PAGE_SIZE;
#[cfg(feature = "client-pin-flash-storage")]
const NRF_FLASH_PIN_PAGE_COUNT: usize = 2;
#[cfg(feature = "nrf-flash-storage")]
const NRF_FLASH_CREDENTIAL_REGION: FixedPageRegion = FixedPageRegion::new(
    NRF_FLASH_CREDENTIAL_BASE,
    NRF_FLASH_PAGE_SIZE,
    NRF_FLASH_CREDENTIAL_PAGE_COUNT,
);
#[cfg(feature = "nrf-flash-storage")]
pub const NRF_FLASH_BLE_BOND_REGION: FixedPageRegion = FixedPageRegion::new(
    NRF_FLASH_BLE_BOND_BASE,
    NRF_FLASH_PAGE_SIZE,
    NRF_FLASH_BLE_BOND_PAGE_COUNT,
);
#[cfg(feature = "client-pin-flash-storage")]
const NRF_FLASH_PIN_REGION: FixedPageRegion = FixedPageRegion::new(
    NRF_FLASH_PIN_BASE,
    NRF_FLASH_PAGE_SIZE,
    NRF_FLASH_PIN_PAGE_COUNT,
);
#[cfg(feature = "client-pin-flash-storage")]
const _: () =
    assert!(NRF_FLASH_PIN_BASE + NRF_FLASH_PAGE_SIZE * NRF_FLASH_PIN_PAGE_COUNT <= 0xF4000);
#[cfg(feature = "nrf-flash-storage")]
const NRF_FLASH_EVENT_WAIT_LIMIT: u32 = 20_000_000;

#[cfg(feature = "nrf-flash-managed-keys")]
pub const NRF_FLASH_MANAGED_REGION: FixedPageRegion =
    FixedPageRegion::new(0x000E_5000, NRF_FLASH_PAGE_SIZE, 2);
#[cfg(feature = "nrf-flash-managed-keys")]
const _: () = {
    assert!(NRF_FLASH_PIN_BASE + NRF_FLASH_PAGE_SIZE * NRF_FLASH_PIN_PAGE_COUNT <= 0xE5000);
    assert!(0xE5000 + NRF_FLASH_PAGE_SIZE * 2 <= 0xF4000);
};

#[cfg(feature = "nrf-flash-managed-keys")]
pub enum NrfManagedKeyStorage {
    Direct,
    Softdevice(NrfSoftdeviceFlashStorage),
}

#[cfg(feature = "nrf-flash-managed-keys")]
impl NrfManagedKeyStorage {
    pub(crate) fn new(softdevice: bool) -> Self {
        if softdevice {
            Self::Softdevice(NrfSoftdeviceFlashStorage::new(NRF_FLASH_MANAGED_REGION))
        } else {
            Self::Direct
        }
    }
}

#[cfg(feature = "nrf-flash-managed-keys")]
impl NrfJournalPageBackend for NrfManagedKeyStorage {
    fn journal_region(&self) -> FixedPageRegion {
        NRF_FLASH_MANAGED_REGION
    }
    fn erase_journal_page(&mut self, addr: usize) -> Result<(), StorageError> {
        match self {
            Self::Softdevice(media) => media.erase_journal_page(addr),

            Self::Direct => {
                nvmc_erase_page(unsafe { &*NVMC::ptr() }, NRF_FLASH_MANAGED_REGION, addr)
            }
        }
    }
    fn program_journal_words(&mut self, addr: usize, data: &[u8]) -> Result<(), StorageError> {
        match self {
            Self::Softdevice(media) => media.program_journal_words(addr, data),

            Self::Direct => nvmc_program_words(
                unsafe { &*NVMC::ptr() },
                NRF_FLASH_MANAGED_REGION,
                addr,
                data,
            ),
        }
    }
}

#[cfg(feature = "nrf-flash-managed-keys")]
impl StorageBackend for NrfManagedKeyStorage {
    fn read_page(
        &mut self,
        page: usize,
        buf: &mut [u8; NRF_FLASH_PAGE_SIZE],
    ) -> Result<(), StorageError> {
        read_journal_page(self, page, buf)
    }
    fn write_page(
        &mut self,
        page: usize,
        buf: &[u8; NRF_FLASH_PAGE_SIZE],
    ) -> Result<(), StorageError> {
        write_journal_page(self, page, buf)
    }
    fn commit_page(&mut self, page: usize) -> Result<(), StorageError> {
        commit_journal_page(self, page)
    }
    fn clear_pages(&mut self) -> Result<(), StorageError> {
        clear_journal_pages(self)
    }
}

#[cfg(feature = "nrf-flash-storage")]
fn nrf_flash_page_addr(region: FixedPageRegion, page: usize) -> Result<usize, StorageError> {
    region
        .page_offset_for_len(page, NRF_FLASH_PAGE_SIZE)
        .ok_or(StorageError::ReadFailed)
}

#[cfg(feature = "nrf-flash-storage")]
fn read_nrf_flash_page(
    region: FixedPageRegion,
    page: usize,
    buf: &mut [u8; NRF_FLASH_PAGE_SIZE],
) -> Result<(), StorageError> {
    let addr = nrf_flash_page_addr(region, page)?;

    unsafe {
        core::ptr::copy_nonoverlapping(addr as *const u8, buf.as_mut_ptr(), buf.len());
    }
    Ok(())
}

#[cfg(feature = "nrf-flash-storage")]
trait NrfJournalPageBackend {
    fn journal_region(&self) -> FixedPageRegion;
    fn erase_journal_page(&mut self, addr: usize) -> Result<(), StorageError>;
    fn program_journal_words(&mut self, addr: usize, data: &[u8]) -> Result<(), StorageError>;
}

#[cfg(feature = "nrf-flash-storage")]
fn read_journal_page<B: NrfJournalPageBackend>(
    backend: &B,
    page: usize,
    buf: &mut [u8; NRF_FLASH_PAGE_SIZE],
) -> Result<(), StorageError> {
    read_nrf_flash_page(backend.journal_region(), page, buf)
}

#[cfg(feature = "nrf-flash-storage")]
fn write_journal_page<B: NrfJournalPageBackend>(
    backend: &mut B,
    page: usize,
    buf: &[u8; NRF_FLASH_PAGE_SIZE],
) -> Result<(), StorageError> {
    let addr = nrf_flash_page_addr(backend.journal_region(), page)
        .map_err(|_| StorageError::WriteFailed)?;
    backend.erase_journal_page(addr)?;
    backend.program_journal_words(addr, buf)
}

#[cfg(feature = "nrf-flash-storage")]
fn commit_journal_page<B: NrfJournalPageBackend>(
    backend: &mut B,
    page: usize,
) -> Result<(), StorageError> {
    let addr = nrf_flash_page_addr(backend.journal_region(), page)
        .map_err(|_| StorageError::WriteFailed)?;
    let marker_addr = addr
        .checked_add(STORAGE_PAGE_COMMIT_OFFSET)
        .ok_or(StorageError::WriteFailed)?;
    backend.program_journal_words(marker_addr, &STORAGE_PAGE_COMMIT_MARKER)
}

#[cfg(feature = "nrf-flash-storage")]
fn clear_journal_pages<B: NrfJournalPageBackend>(backend: &mut B) -> Result<(), StorageError> {
    for page in 0..backend.journal_region().page_count() {
        let addr = nrf_flash_page_addr(backend.journal_region(), page)
            .map_err(|_| StorageError::WriteFailed)?;
        backend.erase_journal_page(addr)?;
    }
    Ok(())
}

#[cfg(feature = "nrf-flash-storage")]
pub type SelectedStorage = NrfFlashStorage;

#[cfg(not(feature = "nrf-flash-storage"))]
pub type SelectedStorage = StubStorage;

#[cfg(feature = "nrf-flash-storage")]
/// Exclusive direct NVMC owner with dedicated credential pages; SoftDevice must be disabled.
/// Ready waits have no timeout; power-loss behavior is not qualified.
pub struct NrfFlashStorage {
    nvmc: NVMC,
}

#[cfg(feature = "nrf-flash-storage")]
fn nvmc_wait_ready(nvmc: &nrf52840_pac::nvmc::RegisterBlock) {
    while nvmc.ready.read().ready().is_busy() {
        asm::nop();
    }
}

#[cfg(feature = "nrf-flash-storage")]
fn nvmc_set_read_only(nvmc: &nrf52840_pac::nvmc::RegisterBlock) {
    nvmc_wait_ready(nvmc);
    nvmc.config.write(|w| w.wen().ren());
    nvmc_wait_ready(nvmc);
}

#[cfg(feature = "nrf-flash-storage")]
fn nvmc_erase_page(
    nvmc: &nrf52840_pac::nvmc::RegisterBlock,
    region: FixedPageRegion,
    addr: usize,
) -> Result<(), StorageError> {
    if addr % NRF_FLASH_PAGE_SIZE != 0 || !region.contains_range(addr, NRF_FLASH_PAGE_SIZE) {
        return Err(StorageError::WriteFailed);
    }
    nvmc_wait_ready(nvmc);
    nvmc.config.write(|w| w.wen().een());
    nvmc_wait_ready(nvmc);
    nvmc.erasepage()
        .write(|w| unsafe { w.erasepage().bits(addr as u32) });
    nvmc_set_read_only(nvmc);
    Ok(())
}

#[cfg(feature = "nrf-flash-storage")]
fn nvmc_program_words(
    nvmc: &nrf52840_pac::nvmc::RegisterBlock,
    region: FixedPageRegion,
    addr: usize,
    data: &[u8],
) -> Result<(), StorageError> {
    if addr % 4 != 0 || data.len() % 4 != 0 || !region.contains_single_page_range(addr, data.len())
    {
        return Err(StorageError::WriteFailed);
    }

    nvmc_wait_ready(nvmc);
    nvmc.config.write(|w| w.wen().wen());
    nvmc_wait_ready(nvmc);

    for (index, chunk) in data.chunks_exact(4).enumerate() {
        let word = u32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]);
        let ptr = (addr + index * 4) as *mut u32;

        unsafe {
            ptr.write_volatile(word);
        }
        nvmc_wait_ready(nvmc);
    }

    nvmc_set_read_only(nvmc);
    Ok(())
}

#[cfg(feature = "nrf-flash-storage")]
impl NrfFlashStorage {
    const fn new(nvmc: NVMC) -> Self {
        Self { nvmc }
    }

    fn erase_page(&self, addr: usize) -> Result<(), StorageError> {
        nvmc_erase_page(&self.nvmc, NRF_FLASH_CREDENTIAL_REGION, addr)
    }

    fn program_words(&self, addr: usize, data: &[u8]) -> Result<(), StorageError> {
        nvmc_program_words(&self.nvmc, NRF_FLASH_CREDENTIAL_REGION, addr, data)
    }
}

#[cfg(feature = "nrf-flash-storage")]
impl NrfJournalPageBackend for NrfFlashStorage {
    fn journal_region(&self) -> FixedPageRegion {
        NRF_FLASH_CREDENTIAL_REGION
    }

    fn erase_journal_page(&mut self, addr: usize) -> Result<(), StorageError> {
        self.erase_page(addr)
    }

    fn program_journal_words(&mut self, addr: usize, data: &[u8]) -> Result<(), StorageError> {
        self.program_words(addr, data)
    }
}

#[cfg(feature = "nrf-flash-storage")]
impl StorageBackend for NrfFlashStorage {
    fn read_page(
        &mut self,
        page: usize,
        buf: &mut [u8; NRF_FLASH_PAGE_SIZE],
    ) -> Result<(), StorageError> {
        read_journal_page(self, page, buf)
    }

    fn write_page(
        &mut self,
        page: usize,
        buf: &[u8; NRF_FLASH_PAGE_SIZE],
    ) -> Result<(), StorageError> {
        write_journal_page(self, page, buf)
    }

    fn commit_page(&mut self, page: usize) -> Result<(), StorageError> {
        commit_journal_page(self, page)
    }

    fn clear_pages(&mut self) -> Result<(), StorageError> {
        clear_journal_pages(self)
    }
}

#[cfg(feature = "nrf-flash-storage")]
pub fn selected_storage(nvmc: NVMC, log: fn(&str)) -> Storage<SelectedStorage> {
    log("storage=nrf-flash 0x000e0000..0x000e2000\r\n");
    Storage::new(NrfFlashStorage::new(nvmc))
}

#[cfg(not(feature = "nrf-flash-storage"))]
pub fn selected_storage(_nvmc: NVMC, log: fn(&str)) -> Storage<SelectedStorage> {
    log("storage=volatile\r\n");
    Storage::new(StubStorage::new())
}

#[cfg(feature = "nrf-flash-storage")]
pub type SelectedSoftdeviceStorage = NrfSoftdeviceFlashStorage;

#[cfg(not(feature = "nrf-flash-storage"))]
pub type SelectedSoftdeviceStorage = StubStorage;

#[cfg(feature = "nrf-flash-storage")]
/// Requires an active SoftDevice and exclusive Flash/event ownership with reserved journal pages.
/// An ambiguous completion requires recovery before buffers or Flash operations are reused.
pub struct NrfSoftdeviceFlashStorage {
    region: FixedPageRegion,
}

#[cfg(feature = "nrf-flash-storage")]
static SHARED_FLASH_BUSY: core::sync::atomic::AtomicBool =
    core::sync::atomic::AtomicBool::new(false);
#[cfg(feature = "nrf-flash-storage")]
static mut SHARED_FLASH_WORDS: [u32; NRF_FLASH_PAGE_SIZE / 4] = [0; NRF_FLASH_PAGE_SIZE / 4];

#[cfg(feature = "nrf-flash-storage")]
impl NrfSoftdeviceFlashStorage {
    const fn new(region: FixedPageRegion) -> Self {
        Self { region }
    }

    fn wait_flash_event() -> Result<(), StorageError> {
        for _ in 0..NRF_FLASH_EVENT_WAIT_LIMIT {
            let mut event = 0u32;
            let ret = unsafe { raw::sd_evt_get(&mut event) };
            if ret == raw::NRF_SUCCESS {
                match event {
                    raw::NRF_SOC_EVTS_NRF_EVT_FLASH_OPERATION_SUCCESS => return Ok(()),
                    raw::NRF_SOC_EVTS_NRF_EVT_FLASH_OPERATION_ERROR => {
                        return Err(StorageError::WriteFailed);
                    }
                    _ => {}
                }
            } else if ret != raw::NRF_ERROR_NOT_FOUND {
                return Err(StorageError::WriteFailed);
            }
            asm::nop();
        }
        Err(StorageError::WriteFailed)
    }

    fn erase_page(&mut self, addr: usize) -> Result<(), StorageError> {
        if SHARED_FLASH_BUSY.load(core::sync::atomic::Ordering::Acquire) {
            return Err(StorageError::WriteFailed);
        }
        if addr % NRF_FLASH_PAGE_SIZE != 0 || !self.region.contains_range(addr, NRF_FLASH_PAGE_SIZE)
        {
            return Err(StorageError::WriteFailed);
        }
        let page_number = (addr / NRF_FLASH_PAGE_SIZE) as u32;
        let ret = unsafe { raw::sd_flash_page_erase(page_number) };
        if ret != raw::NRF_SUCCESS {
            return Err(StorageError::WriteFailed);
        }
        let result = Self::wait_flash_event();
        if result.is_err() {
            SHARED_FLASH_BUSY.store(true, core::sync::atomic::Ordering::Release);
        }
        result
    }

    fn program_words(&mut self, addr: usize, data: &[u8]) -> Result<(), StorageError> {
        if addr % 4 != 0
            || data.len() % 4 != 0
            || data.len() > NRF_FLASH_PAGE_SIZE
            || !self.region.contains_single_page_range(addr, data.len())
        {
            return Err(StorageError::WriteFailed);
        }

        let scratch = {
            use core::sync::atomic::Ordering;
            if SHARED_FLASH_BUSY
                .compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
                .is_err()
            {
                return Err(StorageError::WriteFailed);
            }

            unsafe { &mut *core::ptr::addr_of_mut!(SHARED_FLASH_WORDS) }
        };
        for word in scratch.iter_mut() {
            *word = 0xffff_ffff;
        }
        for (index, chunk) in data.chunks_exact(4).enumerate() {
            scratch[index] = u32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]);
        }

        let ret = unsafe {
            raw::sd_flash_write(addr as *mut u32, scratch.as_ptr(), (data.len() / 4) as u32)
        };
        if ret != raw::NRF_SUCCESS {
            {
                scratch.fill(0);
                SHARED_FLASH_BUSY.store(false, core::sync::atomic::Ordering::Release);
            }
            return Err(StorageError::WriteFailed);
        }
        let result = Self::wait_flash_event();
        if result.is_ok() {
            scratch.fill(0);
            SHARED_FLASH_BUSY.store(false, core::sync::atomic::Ordering::Release);
        }
        result
    }
}

#[cfg(feature = "nrf-flash-storage")]
impl NrfJournalPageBackend for NrfSoftdeviceFlashStorage {
    fn journal_region(&self) -> FixedPageRegion {
        self.region
    }

    fn erase_journal_page(&mut self, addr: usize) -> Result<(), StorageError> {
        self.erase_page(addr)
    }

    fn program_journal_words(&mut self, addr: usize, data: &[u8]) -> Result<(), StorageError> {
        self.program_words(addr, data)
    }
}

#[cfg(feature = "nrf-flash-storage")]
fn softdevice_erase_region_page(
    region: FixedPageRegion,
    page: usize,
) -> Result<usize, StorageError> {
    let addr = nrf_flash_page_addr(region, page).map_err(|_| StorageError::WriteFailed)?;
    NrfSoftdeviceFlashStorage::new(region).erase_page(addr)?;
    Ok(addr)
}

#[cfg(feature = "nrf-flash-storage")]
fn softdevice_program_region_words(
    region: FixedPageRegion,
    addr: usize,
    data: &[u8],
) -> Result<(), StorageError> {
    NrfSoftdeviceFlashStorage::new(region).program_words(addr, data)
}

#[cfg(feature = "nrf-flash-storage")]
pub fn read_ble_bond_record<const N: usize>(buf: &mut [u8; N]) -> Result<(), StorageError> {
    let addr = nrf_flash_page_addr(NRF_FLASH_BLE_BOND_REGION, 0)?;
    if !NRF_FLASH_BLE_BOND_REGION.contains_range(addr, N) {
        return Err(StorageError::ReadFailed);
    }

    unsafe {
        core::ptr::copy_nonoverlapping(addr as *const u8, buf.as_mut_ptr(), N);
    }
    Ok(())
}

#[cfg(feature = "nrf-flash-storage")]
/// Replaces the dedicated plaintext bond page; caller serializes Flash and event ownership.
/// No power-loss atomicity guarantee; ambiguous completion requires recovery.
pub fn write_ble_bond_record(data: &[u8]) -> Result<(), StorageError> {
    const MAX_BOND_RECORD_BYTES: usize = 256;
    if data.len() % 4 != 0 || data.len() > MAX_BOND_RECORD_BYTES {
        return Err(StorageError::WriteFailed);
    }
    let addr = softdevice_erase_region_page(NRF_FLASH_BLE_BOND_REGION, 0)?;
    softdevice_program_region_words(NRF_FLASH_BLE_BOND_REGION, addr, data)
}

#[cfg(feature = "nrf-flash-storage")]
impl StorageBackend for NrfSoftdeviceFlashStorage {
    fn read_page(
        &mut self,
        page: usize,
        buf: &mut [u8; NRF_FLASH_PAGE_SIZE],
    ) -> Result<(), StorageError> {
        read_journal_page(self, page, buf)
    }

    fn write_page(
        &mut self,
        page: usize,
        buf: &[u8; NRF_FLASH_PAGE_SIZE],
    ) -> Result<(), StorageError> {
        write_journal_page(self, page, buf)
    }

    fn commit_page(&mut self, page: usize) -> Result<(), StorageError> {
        commit_journal_page(self, page)
    }

    fn clear_pages(&mut self) -> Result<(), StorageError> {
        clear_journal_pages(self)
    }
}

#[cfg(feature = "nrf-flash-storage")]
pub fn selected_softdevice_storage(
    _nvmc: NVMC,
    log: fn(&str),
) -> Storage<SelectedSoftdeviceStorage> {
    log("storage=nrf-softdevice-credential-flash 0x000e0000..0x000e2000\r\n");
    Storage::new(NrfSoftdeviceFlashStorage::new(NRF_FLASH_CREDENTIAL_REGION))
}

#[cfg(not(feature = "nrf-flash-storage"))]
pub fn selected_softdevice_storage(
    _nvmc: NVMC,
    log: fn(&str),
) -> Storage<SelectedSoftdeviceStorage> {
    log("storage=volatile\r\n");
    Storage::new(StubStorage::new())
}

#[cfg(feature = "client-pin-flash-storage")]
/// Serialized direct NVMC PIN adapter; exclude all other Flash owners and disable SoftDevice.
pub struct NrfPinUvAuthFlashStorage;

#[cfg(feature = "client-pin-flash-storage")]
impl NrfPinUvAuthFlashStorage {
    pub const fn new() -> Self {
        Self
    }

    fn nvmc() -> &'static nrf52840_pac::nvmc::RegisterBlock {
        unsafe { &*NVMC::ptr() }
    }

    fn erase_page(addr: usize) -> Result<(), PinStorageError> {
        nvmc_erase_page(Self::nvmc(), NRF_FLASH_PIN_REGION, addr)
            .map_err(|_| PinStorageError::WriteFailed)
    }

    fn program_words(addr: usize, data: &[u8]) -> Result<(), PinStorageError> {
        nvmc_program_words(Self::nvmc(), NRF_FLASH_PIN_REGION, addr, data)
            .map_err(|_| PinStorageError::WriteFailed)
    }
}

#[cfg(feature = "client-pin-flash-storage")]
impl PinUvAuthPageBackend for NrfPinUvAuthFlashStorage {
    fn read_pin_page(
        &mut self,
        page: usize,
        buf: &mut [u8; PIN_UV_AUTH_PAGE_SIZE],
    ) -> Result<(), PinStorageError> {
        read_nrf_flash_page(NRF_FLASH_PIN_REGION, page, buf)
            .map_err(|_| PinStorageError::ReadFailed)
    }

    fn write_pin_page(
        &mut self,
        page: usize,
        buf: &[u8; PIN_UV_AUTH_PAGE_SIZE],
    ) -> Result<(), PinStorageError> {
        let addr = nrf_flash_page_addr(NRF_FLASH_PIN_REGION, page)
            .map_err(|_| PinStorageError::WriteFailed)?;
        Self::erase_page(addr)?;
        Self::program_words(addr, buf)
    }

    fn commit_pin_page(&mut self, page: usize) -> Result<(), PinStorageError> {
        let addr = nrf_flash_page_addr(NRF_FLASH_PIN_REGION, page)
            .map_err(|_| PinStorageError::WriteFailed)?;
        Self::program_words(addr + PIN_PAGE_COMMIT_OFFSET, &PIN_PAGE_COMMIT_MARKER)
    }
}

#[cfg(feature = "client-pin-flash-storage")]
/// PIN journal using the same serialized SoftDevice Flash/event service.
pub struct NrfSoftdevicePinUvAuthFlashStorage(NrfSoftdeviceFlashStorage);

#[cfg(feature = "client-pin-flash-storage")]
impl NrfSoftdevicePinUvAuthFlashStorage {
    pub const fn new() -> Self {
        Self(NrfSoftdeviceFlashStorage::new(NRF_FLASH_PIN_REGION))
    }
}

#[cfg(feature = "client-pin-flash-storage")]
impl PinUvAuthPageBackend for NrfSoftdevicePinUvAuthFlashStorage {
    fn read_pin_page(
        &mut self,
        page: usize,
        buf: &mut [u8; PIN_UV_AUTH_PAGE_SIZE],
    ) -> Result<(), PinStorageError> {
        read_nrf_flash_page(NRF_FLASH_PIN_REGION, page, buf)
            .map_err(|_| PinStorageError::ReadFailed)
    }

    fn write_pin_page(
        &mut self,
        page: usize,
        buf: &[u8; PIN_UV_AUTH_PAGE_SIZE],
    ) -> Result<(), PinStorageError> {
        let addr = nrf_flash_page_addr(NRF_FLASH_PIN_REGION, page)
            .map_err(|_| PinStorageError::WriteFailed)?;
        self.0
            .erase_page(addr)
            .map_err(|_| PinStorageError::WriteFailed)?;
        self.0
            .program_words(addr, buf)
            .map_err(|_| PinStorageError::WriteFailed)
    }

    fn commit_pin_page(&mut self, page: usize) -> Result<(), PinStorageError> {
        let addr = nrf_flash_page_addr(NRF_FLASH_PIN_REGION, page)
            .map_err(|_| PinStorageError::WriteFailed)?;
        self.0
            .program_words(addr + PIN_PAGE_COMMIT_OFFSET, &PIN_PAGE_COMMIT_MARKER)
            .map_err(|_| PinStorageError::WriteFailed)
    }
}
