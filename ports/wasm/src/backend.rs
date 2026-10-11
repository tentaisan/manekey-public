// SPDX-License-Identifier: AGPL-3.0-only

use manekey::ctaphid::entropy::{EntropyError, EntropySource};
use manekey::ctaphid::pin_uv_auth::{
    PIN_PAGE_COMMIT_MARKER, PIN_PAGE_COMMIT_OFFSET, PIN_UV_AUTH_PAGE_SIZE, PinStorageError,
    PinUvAuthPageBackend, PinUvAuthTokenClock,
};
use manekey::ctaphid::storage::{
    FLASH_SECTOR_SIZE, STORAGE_PAGE_COUNT, StorageBackend, StorageError,
    mark_storage_page_committed,
};

#[link(wasm_import_module = "manekey_host")]
unsafe extern "C" {
    fn entropy_fill(pointer: *mut u8, length: u32) -> u32;
    fn page_read(domain: u32, page: u32, pointer: *mut u8, length: u32) -> u32;
    fn page_write(domain: u32, page: u32, pointer: *const u8, length: u32) -> u32;
    fn clock_millis() -> f64;
}

/// Host callback must fill the entire output; failure has no fallback.
pub struct HostEntropy;
impl EntropySource for HostEntropy {
    fn fill_entropy(&mut self, output: &mut [u8]) -> Result<(), EntropyError> {
        let length = u32::try_from(output.len()).map_err(|_| EntropyError::Unavailable)?;

        if unsafe { entropy_fill(output.as_mut_ptr(), length) } != 1 {
            output.fill(0);
            return Err(EntropyError::Unavailable);
        }
        Ok(())
    }
}

/// Host monotonic time; the runtime must reject invalid clocks before issuing operations.
pub struct HostClock;
impl HostClock {
    pub fn checked_now_ms() -> Option<u64> {
        let now = unsafe { clock_millis() };
        (now.is_finite() && now >= 0.0 && now < u64::MAX as f64).then_some(now as u64)
    }
}
impl PinUvAuthTokenClock for HostClock {
    fn now_ms(&self) -> u64 {
        Self::checked_now_ms().unwrap_or(u64::MAX)
    }
}

/// Domain 0 pages; host callbacks own synchronous persistence, exclusion and confidentiality.
pub struct HostCredentialStorage;

/// Domain 1 PIN pages; host storage must not alias credential pages.
pub struct HostPinStorage;

fn read(domain: u32, page: usize, output: &mut [u8]) -> bool {
    if page >= STORAGE_PAGE_COUNT {
        return false;
    }

    let result = unsafe {
        page_read(
            domain,
            page as u32,
            output.as_mut_ptr(),
            output.len() as u32,
        )
    };
    if result != 1 {
        output.fill(0);
    }
    result == 1
}

fn write(domain: u32, page: usize, input: &[u8]) -> bool {
    if page >= STORAGE_PAGE_COUNT {
        return false;
    }

    unsafe { page_write(domain, page as u32, input.as_ptr(), input.len() as u32) == 1 }
}

impl StorageBackend for HostCredentialStorage {
    fn read_page(
        &mut self,
        page: usize,
        output: &mut [u8; FLASH_SECTOR_SIZE],
    ) -> Result<(), StorageError> {
        if read(0, page, output) {
            Ok(())
        } else {
            Err(StorageError::ReadFailed)
        }
    }
    fn write_page(
        &mut self,
        page: usize,
        input: &[u8; FLASH_SECTOR_SIZE],
    ) -> Result<(), StorageError> {
        if write(0, page, input) {
            Ok(())
        } else {
            Err(StorageError::WriteFailed)
        }
    }
    fn commit_page(&mut self, page: usize) -> Result<(), StorageError> {
        let mut buffer = [0; FLASH_SECTOR_SIZE];
        self.read_page(page, &mut buffer)?;
        mark_storage_page_committed(&mut buffer)?;
        self.write_page(page, &buffer)
    }
    fn clear_pages(&mut self) -> Result<(), StorageError> {
        for page in 0..STORAGE_PAGE_COUNT {
            self.write_page(page, &[0xff; FLASH_SECTOR_SIZE])?;
        }
        Ok(())
    }
}

impl PinUvAuthPageBackend for HostPinStorage {
    fn read_pin_page(
        &mut self,
        page: usize,
        output: &mut [u8; PIN_UV_AUTH_PAGE_SIZE],
    ) -> Result<(), PinStorageError> {
        if read(1, page, output) {
            Ok(())
        } else {
            Err(PinStorageError::ReadFailed)
        }
    }
    fn write_pin_page(
        &mut self,
        page: usize,
        input: &[u8; PIN_UV_AUTH_PAGE_SIZE],
    ) -> Result<(), PinStorageError> {
        if write(1, page, input) {
            Ok(())
        } else {
            Err(PinStorageError::WriteFailed)
        }
    }
    fn commit_pin_page(&mut self, page: usize) -> Result<(), PinStorageError> {
        let mut buffer = [0; PIN_UV_AUTH_PAGE_SIZE];
        self.read_pin_page(page, &mut buffer)?;
        buffer[PIN_PAGE_COMMIT_OFFSET..PIN_PAGE_COMMIT_OFFSET + PIN_PAGE_COMMIT_MARKER.len()]
            .copy_from_slice(&PIN_PAGE_COMMIT_MARKER);
        self.write_pin_page(page, &buffer)
    }
}
