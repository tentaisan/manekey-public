use super::PIN_STORAGE_PAGE_COUNT;
#[cfg(all(
    any(
        feature = "chip-rp2040",
        feature = "chip-rp235xa",
        feature = "chip-rp235xa-nonsecure"
    ),
    target_arch = "arm",
    target_os = "none"
))]
use manekey::boundary::storage_mailbox::Core0FlashService;
use manekey::boundary::storage_mailbox::{
    CORE0_FLASH_CLEAR_PAGES, CORE0_FLASH_COMMIT_PAGE, CORE0_FLASH_COMMIT_PIN_PAGE,
    CORE0_FLASH_READ_PAGE, CORE0_FLASH_READ_PIN_PAGE, CORE0_FLASH_REQUEST_MAX,
    CORE0_FLASH_RESPONSE_MAX, CORE0_FLASH_WRITE_PAGE, CORE0_FLASH_WRITE_PIN_PAGE,
};
use manekey::ctaphid::pin_uv_auth::{PIN_UV_AUTH_PAGE_SIZE, PinStorageError, PinUvAuthPageBackend};
use manekey::ctaphid::storage::{
    FLASH_SECTOR_SIZE, STORAGE_PAGE_COUNT, StorageBackend, StorageError,
};

#[cfg(any(
    all(
        any(
            feature = "chip-rp2040",
            feature = "chip-rp235xa",
            feature = "chip-rp235xa-nonsecure"
        ),
        target_arch = "arm",
        target_os = "none"
    ),
    all(
        feature = "riscv-rp2350-hal",
        target_arch = "riscv32",
        target_os = "none"
    )
))]
use manekey::boundary::mailbox::{MailboxEndpoint, MailboxState};

#[cfg(all(
    any(
        feature = "chip-rp2040",
        feature = "chip-rp235xa",
        feature = "chip-rp235xa-nonsecure"
    ),
    target_arch = "arm",
    target_os = "none"
))]
fn notify_peer() {
    cortex_m::asm::sev();
}

#[cfg(all(
    feature = "riscv-rp2350-hal",
    target_arch = "riscv32",
    target_os = "none"
))]
fn notify_peer() {
    rp235x_hal::arch::sev();
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
fn wait_for_peer() {
    cortex_m::asm::wfe();
}

#[cfg(all(
    feature = "riscv-rp2350-hal",
    target_arch = "riscv32",
    target_os = "none"
))]
fn wait_for_peer() {
    rp235x_hal::arch::wfe();
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
/// Single core0 media-service owner; pump only one request synchronously and reserve endpoint buffers.
pub trait Core0FlashServiceExt {
    fn pump_once(
        &mut self,
        endpoint: &MailboxEndpoint<CORE0_FLASH_REQUEST_MAX, CORE0_FLASH_RESPONSE_MAX>,
    ) -> bool;
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
impl<B: StorageBackend, P: PinUvAuthPageBackend, K: StorageBackend> Core0FlashServiceExt
    for Core0FlashService<B, P, K>
{
    fn pump_once(
        &mut self,
        endpoint: &MailboxEndpoint<CORE0_FLASH_REQUEST_MAX, CORE0_FLASH_RESPONSE_MAX>,
    ) -> bool {
        if endpoint.state() != Ok(MailboxState::RequestReady) {
            return false;
        }
        let mut request = [0; CORE0_FLASH_REQUEST_MAX];
        let mut response = [0; CORE0_FLASH_RESPONSE_MAX];
        let result = endpoint
            .take_request(&mut request)
            .and_then(|len| {
                self.process(&request[..len], &mut response)
                    .map_err(|_| manekey::boundary::mailbox::MailboxError::InvalidState)
            })
            .and_then(|len| endpoint.publish_response(&response[..len]));
        if result.is_err() {
            let _ = endpoint.publish_response(&[0xff]);
        }
        notify_peer();
        true
    }
}
#[cfg(any(
    all(
        any(
            feature = "chip-rp2040",
            feature = "chip-rp235xa",
            feature = "chip-rp235xa-nonsecure"
        ),
        target_arch = "arm",
        target_os = "none"
    ),
    all(
        feature = "riscv-rp2350-hal",
        target_arch = "riscv32",
        target_os = "none"
    )
))]

/// Single synchronous endpoint client; core0 service must run while requester waits without a timeout.
pub struct Core0FlashPinUvAuthStorageClient<'a> {
    endpoint: &'a MailboxEndpoint<CORE0_FLASH_REQUEST_MAX, CORE0_FLASH_RESPONSE_MAX>,
}

#[cfg(any(
    all(
        any(
            feature = "chip-rp2040",
            feature = "chip-rp235xa",
            feature = "chip-rp235xa-nonsecure"
        ),
        target_arch = "arm",
        target_os = "none"
    ),
    all(
        feature = "riscv-rp2350-hal",
        target_arch = "riscv32",
        target_os = "none"
    )
))]
impl<'a> Core0FlashPinUvAuthStorageClient<'a> {
    pub const fn new(
        endpoint: &'a MailboxEndpoint<CORE0_FLASH_REQUEST_MAX, CORE0_FLASH_RESPONSE_MAX>,
    ) -> Self {
        Self { endpoint }
    }

    fn call(&self, request: &[u8], response: &mut [u8]) -> Result<usize, PinStorageError> {
        self.endpoint
            .submit(request)
            .map_err(|_| PinStorageError::WriteFailed)?;
        notify_peer();
        loop {
            if self
                .endpoint
                .state()
                .map_err(|_| PinStorageError::ReadFailed)?
                == MailboxState::ResponseReady
            {
                return self
                    .endpoint
                    .take_response(response)
                    .map_err(|_| PinStorageError::ReadFailed);
            }
            wait_for_peer();
        }
    }
}

#[cfg(any(
    all(
        any(
            feature = "chip-rp2040",
            feature = "chip-rp235xa",
            feature = "chip-rp235xa-nonsecure"
        ),
        target_arch = "arm",
        target_os = "none"
    ),
    all(
        feature = "riscv-rp2350-hal",
        target_arch = "riscv32",
        target_os = "none"
    )
))]
impl PinUvAuthPageBackend for Core0FlashPinUvAuthStorageClient<'_> {
    fn read_pin_page(
        &mut self,
        page: usize,
        buf: &mut [u8; PIN_UV_AUTH_PAGE_SIZE],
    ) -> Result<(), PinStorageError> {
        if page >= PIN_STORAGE_PAGE_COUNT
            || self.call(&[CORE0_FLASH_READ_PIN_PAGE, page as u8], buf)? != PIN_UV_AUTH_PAGE_SIZE
        {
            Err(PinStorageError::ReadFailed)
        } else {
            Ok(())
        }
    }

    fn write_pin_page(
        &mut self,
        page: usize,
        buf: &[u8; PIN_UV_AUTH_PAGE_SIZE],
    ) -> Result<(), PinStorageError> {
        let mut request = [0; CORE0_FLASH_REQUEST_MAX];
        request[0] = CORE0_FLASH_WRITE_PIN_PAGE;
        request[1] = page as u8;
        request[2..2 + PIN_UV_AUTH_PAGE_SIZE].copy_from_slice(buf);
        if page >= PIN_STORAGE_PAGE_COUNT
            || self.call(&request[..2 + PIN_UV_AUTH_PAGE_SIZE], &mut [])? != 0
        {
            Err(PinStorageError::WriteFailed)
        } else {
            Ok(())
        }
    }

    fn commit_pin_page(&mut self, page: usize) -> Result<(), PinStorageError> {
        if page >= PIN_STORAGE_PAGE_COUNT
            || self.call(&[CORE0_FLASH_COMMIT_PIN_PAGE, page as u8], &mut [])? != 0
        {
            Err(PinStorageError::WriteFailed)
        } else {
            Ok(())
        }
    }
}

#[cfg(any(
    all(
        any(
            feature = "chip-rp2040",
            feature = "chip-rp235xa",
            feature = "chip-rp235xa-nonsecure"
        ),
        target_arch = "arm",
        target_os = "none"
    ),
    all(
        feature = "riscv-rp2350-hal",
        target_arch = "riscv32",
        target_os = "none"
    )
))]

/// Serialized delegated journal client; requester must park during Flash mutation.
/// No timeout or concurrent endpoint client; raw key-media clear also erases root assets.
pub struct Core0FlashStorageClient<'a, const OP_OFFSET: u8 = 0> {
    endpoint: &'a MailboxEndpoint<CORE0_FLASH_REQUEST_MAX, CORE0_FLASH_RESPONSE_MAX>,
}

#[cfg(any(
    all(
        any(
            feature = "chip-rp2040",
            feature = "chip-rp235xa",
            feature = "chip-rp235xa-nonsecure"
        ),
        target_arch = "arm",
        target_os = "none"
    ),
    all(
        feature = "riscv-rp2350-hal",
        target_arch = "riscv32",
        target_os = "none"
    )
))]
impl<'a, const OP_OFFSET: u8> Core0FlashStorageClient<'a, OP_OFFSET> {
    pub const fn new(
        endpoint: &'a MailboxEndpoint<CORE0_FLASH_REQUEST_MAX, CORE0_FLASH_RESPONSE_MAX>,
    ) -> Self {
        assert!(OP_OFFSET == 0 || OP_OFFSET == 7);
        Self { endpoint }
    }

    fn call(&self, request: &[u8], response: &mut [u8]) -> Result<usize, StorageError> {
        self.endpoint
            .submit(request)
            .map_err(|_| StorageError::WriteFailed)?;
        notify_peer();
        loop {
            if self
                .endpoint
                .state()
                .map_err(|_| StorageError::ReadFailed)?
                == MailboxState::ResponseReady
            {
                return self
                    .endpoint
                    .take_response(response)
                    .map_err(|_| StorageError::ReadFailed);
            }
            wait_for_peer();
        }
    }
}

#[cfg(any(
    all(
        any(
            feature = "chip-rp2040",
            feature = "chip-rp235xa",
            feature = "chip-rp235xa-nonsecure"
        ),
        target_arch = "arm",
        target_os = "none"
    ),
    all(
        feature = "riscv-rp2350-hal",
        target_arch = "riscv32",
        target_os = "none"
    )
))]
impl<const OP_OFFSET: u8> StorageBackend for Core0FlashStorageClient<'_, OP_OFFSET> {
    fn read_page(
        &mut self,
        page: usize,
        buf: &mut [u8; FLASH_SECTOR_SIZE],
    ) -> Result<(), StorageError> {
        if page >= STORAGE_PAGE_COUNT
            || self.call(&[CORE0_FLASH_READ_PAGE + OP_OFFSET, page as u8], buf)?
                != FLASH_SECTOR_SIZE
        {
            Err(StorageError::ReadFailed)
        } else {
            Ok(())
        }
    }
    fn write_page(
        &mut self,
        page: usize,
        buf: &[u8; FLASH_SECTOR_SIZE],
    ) -> Result<(), StorageError> {
        let mut request = [0; CORE0_FLASH_REQUEST_MAX];
        request[0] = CORE0_FLASH_WRITE_PAGE + OP_OFFSET;
        request[1] = page as u8;
        request[2..].copy_from_slice(buf);
        if page >= STORAGE_PAGE_COUNT || self.call(&request, &mut [])? != 0 {
            Err(StorageError::WriteFailed)
        } else {
            Ok(())
        }
    }
    fn commit_page(&mut self, page: usize) -> Result<(), StorageError> {
        if page >= STORAGE_PAGE_COUNT
            || self.call(&[CORE0_FLASH_COMMIT_PAGE + OP_OFFSET, page as u8], &mut [])? != 0
        {
            Err(StorageError::WriteFailed)
        } else {
            Ok(())
        }
    }
    fn clear_pages(&mut self) -> Result<(), StorageError> {
        if self.call(&[CORE0_FLASH_CLEAR_PAGES + OP_OFFSET], &mut [])? != 0 {
            Err(StorageError::WriteFailed)
        } else {
            Ok(())
        }
    }
}
