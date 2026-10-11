use crate::ctaphid::pin_uv_auth::{PIN_UV_AUTH_PAGE_SIZE, PinStorageError, PinUvAuthPageBackend};
use crate::ctaphid::storage::{FLASH_SECTOR_SIZE, StorageBackend, StorageError};

pub const CORE0_FLASH_REQUEST_MAX: usize = FLASH_SECTOR_SIZE + 2;

pub const CORE0_FLASH_RESPONSE_MAX: usize = FLASH_SECTOR_SIZE;

pub const CORE0_FLASH_READ_PAGE: u8 = 1;
pub const CORE0_FLASH_WRITE_PAGE: u8 = 2;
pub const CORE0_FLASH_COMMIT_PAGE: u8 = 3;
pub const CORE0_FLASH_CLEAR_PAGES: u8 = 4;
pub const CORE0_FLASH_READ_PIN_PAGE: u8 = 5;
pub const CORE0_FLASH_WRITE_PIN_PAGE: u8 = 6;
pub const CORE0_FLASH_COMMIT_PIN_PAGE: u8 = 7;
pub const CORE0_FLASH_READ_KEY_PAGE: u8 = 8;
pub const CORE0_FLASH_WRITE_KEY_PAGE: u8 = 9;
pub const CORE0_FLASH_COMMIT_KEY_PAGE: u8 = 10;
pub const CORE0_FLASH_CLEAR_KEY_PAGES: u8 = 11;

/// Page service, not a hardware isolation or caller-authentication boundary.
/// Backends own persistence/commit ordering, exclusion, protection and failure reconciliation.
pub struct Core0FlashService<
    B: StorageBackend,
    P: PinUvAuthPageBackend = NoPinFlashBackend,
    K: StorageBackend = NoKeyFlashBackend,
> {
    backend: B,
    pin_backend: P,
    key_backend: K,
}

pub struct NoKeyFlashBackend;

impl StorageBackend for NoKeyFlashBackend {
    fn read_page(&mut self, _: usize, _: &mut [u8; FLASH_SECTOR_SIZE]) -> Result<(), StorageError> {
        Err(StorageError::ReadFailed)
    }
    fn write_page(&mut self, _: usize, _: &[u8; FLASH_SECTOR_SIZE]) -> Result<(), StorageError> {
        Err(StorageError::WriteFailed)
    }
    fn commit_page(&mut self, _: usize) -> Result<(), StorageError> {
        Err(StorageError::WriteFailed)
    }
    fn clear_pages(&mut self) -> Result<(), StorageError> {
        Err(StorageError::WriteFailed)
    }
}

pub struct NoPinFlashBackend;

impl PinUvAuthPageBackend for NoPinFlashBackend {
    fn read_pin_page(
        &mut self,
        _page: usize,
        _buf: &mut [u8; PIN_UV_AUTH_PAGE_SIZE],
    ) -> Result<(), PinStorageError> {
        Err(PinStorageError::ReadFailed)
    }

    fn write_pin_page(
        &mut self,
        _page: usize,
        _buf: &[u8; PIN_UV_AUTH_PAGE_SIZE],
    ) -> Result<(), PinStorageError> {
        Err(PinStorageError::WriteFailed)
    }

    fn commit_pin_page(&mut self, _page: usize) -> Result<(), PinStorageError> {
        Err(PinStorageError::WriteFailed)
    }
}

impl<B: StorageBackend> Core0FlashService<B, NoPinFlashBackend> {
    pub const fn new(backend: B) -> Self {
        Self {
            backend,
            pin_backend: NoPinFlashBackend,
            key_backend: NoKeyFlashBackend,
        }
    }
}

impl<B: StorageBackend, P: PinUvAuthPageBackend> Core0FlashService<B, P> {
    pub const fn with_pin_backend(backend: B, pin_backend: P) -> Self {
        Self {
            backend,
            pin_backend,
            key_backend: NoKeyFlashBackend,
        }
    }
}

impl<B: StorageBackend, P: PinUvAuthPageBackend, K: StorageBackend> Core0FlashService<B, P, K> {
    pub const fn with_key_backend(backend: B, pin_backend: P, key_backend: K) -> Self {
        Self {
            backend,
            pin_backend,
            key_backend,
        }
    }

    /// Handles one page operation; caller authorizes credential/PIN/key access before dispatch.
    /// Failed reads may modify output; clear does not guarantee physical secure erase.
    pub fn process(&mut self, request: &[u8], response: &mut [u8]) -> Result<usize, StorageError> {
        let (&operation, rest) = request.split_first().ok_or(StorageError::WriteFailed)?;
        match operation {
            CORE0_FLASH_READ_KEY_PAGE => {
                let (&page, tail) = rest.split_first().ok_or(StorageError::ReadFailed)?;
                if !tail.is_empty() || response.len() < FLASH_SECTOR_SIZE {
                    return Err(StorageError::ReadFailed);
                }
                let buf = (&mut response[..FLASH_SECTOR_SIZE])
                    .try_into()
                    .map_err(|_| StorageError::ReadFailed)?;
                self.key_backend.read_page(page as usize, buf)?;
                Ok(FLASH_SECTOR_SIZE)
            }
            CORE0_FLASH_WRITE_KEY_PAGE => {
                let (&page, image) = rest.split_first().ok_or(StorageError::WriteFailed)?;
                let buf = image.try_into().map_err(|_| StorageError::WriteFailed)?;
                self.key_backend.write_page(page as usize, buf)?;
                Ok(0)
            }
            CORE0_FLASH_COMMIT_KEY_PAGE => {
                let (&page, tail) = rest.split_first().ok_or(StorageError::WriteFailed)?;
                if !tail.is_empty() {
                    return Err(StorageError::WriteFailed);
                }
                self.key_backend.commit_page(page as usize)?;
                Ok(0)
            }
            CORE0_FLASH_CLEAR_KEY_PAGES if rest.is_empty() => {
                self.key_backend.clear_pages()?;
                Ok(0)
            }
            CORE0_FLASH_READ_PAGE => {
                let (&page, tail) = rest.split_first().ok_or(StorageError::ReadFailed)?;
                if !tail.is_empty() || response.len() < FLASH_SECTOR_SIZE {
                    return Err(StorageError::ReadFailed);
                }
                let page_buf = (&mut response[..FLASH_SECTOR_SIZE])
                    .try_into()
                    .map_err(|_| StorageError::ReadFailed)?;
                self.backend.read_page(page as usize, page_buf)?;
                Ok(FLASH_SECTOR_SIZE)
            }
            CORE0_FLASH_WRITE_PAGE => {
                let (&page, image) = rest.split_first().ok_or(StorageError::WriteFailed)?;
                let page_buf = image.try_into().map_err(|_| StorageError::WriteFailed)?;
                self.backend.write_page(page as usize, page_buf)?;
                Ok(0)
            }
            CORE0_FLASH_COMMIT_PAGE => {
                let (&page, tail) = rest.split_first().ok_or(StorageError::WriteFailed)?;
                if !tail.is_empty() {
                    return Err(StorageError::WriteFailed);
                }
                self.backend.commit_page(page as usize)?;
                Ok(0)
            }
            CORE0_FLASH_CLEAR_PAGES if rest.is_empty() => {
                self.backend.clear_pages()?;
                Ok(0)
            }
            CORE0_FLASH_READ_PIN_PAGE => {
                let (&page, tail) = rest.split_first().ok_or(StorageError::ReadFailed)?;
                if !tail.is_empty() || response.len() < PIN_UV_AUTH_PAGE_SIZE {
                    return Err(StorageError::ReadFailed);
                }
                let page_buf = (&mut response[..PIN_UV_AUTH_PAGE_SIZE])
                    .try_into()
                    .map_err(|_| StorageError::ReadFailed)?;
                self.pin_backend
                    .read_pin_page(page as usize, page_buf)
                    .map_err(|_| StorageError::ReadFailed)?;
                Ok(PIN_UV_AUTH_PAGE_SIZE)
            }
            CORE0_FLASH_WRITE_PIN_PAGE => {
                let (&page, image) = rest.split_first().ok_or(StorageError::WriteFailed)?;
                let page_buf = image.try_into().map_err(|_| StorageError::WriteFailed)?;
                self.pin_backend
                    .write_pin_page(page as usize, page_buf)
                    .map_err(|_| StorageError::WriteFailed)?;
                Ok(0)
            }
            CORE0_FLASH_COMMIT_PIN_PAGE => {
                let (&page, tail) = rest.split_first().ok_or(StorageError::WriteFailed)?;
                if !tail.is_empty() {
                    return Err(StorageError::WriteFailed);
                }
                self.pin_backend
                    .commit_pin_page(page as usize)
                    .map_err(|_| StorageError::WriteFailed)?;
                Ok(0)
            }
            _ => Err(StorageError::WriteFailed),
        }
    }
}
