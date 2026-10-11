// SPDX-License-Identifier: AGPL-3.0-only

use std::fs::{self, DirBuilder, File, OpenOptions};
use std::io::{self, Read, Write};
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Instant;

use manekey::presence::{ManualPresenceState, PresenceStatus, UserPresence};

struct PresenceShared {
    state: ManualPresenceState,
    origin: Instant,
}

impl PresenceShared {
    fn now(&self) -> u64 {
        self.origin.elapsed().as_millis().min(u64::MAX as u128) as u64
    }
}

/// Explicit host confirmation; no hardware isolation or physical-action guarantee.
pub struct HostPresence(Arc<Mutex<PresenceShared>>);

#[derive(Clone)]
/// Confirms only a current request; queued input must not be reused for later requests.
pub struct HostPresenceControl(Arc<Mutex<PresenceShared>>);

impl HostPresence {
    pub fn new(timeout_millis: u64) -> (Self, HostPresenceControl) {
        let shared = Arc::new(Mutex::new(PresenceShared {
            state: ManualPresenceState::new(timeout_millis),
            origin: Instant::now(),
        }));
        (Self(shared.clone()), HostPresenceControl(shared))
    }
}

impl HostPresenceControl {
    pub fn pending_request(&self) -> Option<u64> {
        let mut shared = self.0.lock().ok()?;
        let now = shared.now();
        shared.state.pending_request(now)
    }

    pub fn confirm(&self, request: u64) -> bool {
        let Ok(mut shared) = self.0.lock() else {
            return false;
        };
        let now = shared.now();
        shared.state.confirm(request, now)
    }
}

impl UserPresence for HostPresence {
    fn is_present(&mut self) -> bool {
        self.poll() == PresenceStatus::Confirmed
    }

    fn begin_wait(&mut self) {
        if let Ok(mut shared) = self.0.lock() {
            let now = shared.now();
            let _ = shared.state.begin_wait(now);
        }
    }

    fn poll(&mut self) -> PresenceStatus {
        let Ok(mut shared) = self.0.lock() else {
            return PresenceStatus::TimedOut;
        };
        let now = shared.now();
        shared.state.poll(now)
    }

    fn cancel(&mut self) {
        if let Ok(mut shared) = self.0.lock() {
            shared.state.cancel();
        }
    }
}

use manekey::ctaphid::entropy::{EntropyError, EntropySource};
use manekey::ctaphid::pin_uv_auth::{
    PIN_PAGE_COMMIT_MARKER, PIN_PAGE_COMMIT_OFFSET, PIN_UV_AUTH_PAGE_SIZE, PinStorageError,
    PinUvAuthPageBackend, PinUvAuthTokenClock,
};
use manekey::ctaphid::storage::{
    FLASH_SECTOR_SIZE, STORAGE_PAGE_COUNT, StorageBackend, StorageError,
    mark_storage_page_committed,
};

/// Linux OS entropy; failures clear the output and do not use a deterministic fallback.
pub struct OsEntropy(File);

pub struct HostTokenClock(Instant);
impl HostTokenClock {
    pub fn new() -> Self {
        Self(Instant::now())
    }
}
impl PinUvAuthTokenClock for HostTokenClock {
    fn now_ms(&self) -> u64 {
        self.0.elapsed().as_millis().min(u64::MAX as u128) as u64
    }
}

impl OsEntropy {
    pub fn open() -> io::Result<Self> {
        File::open("/dev/urandom").map(Self)
    }
}

impl EntropySource for OsEntropy {
    fn fill_entropy(&mut self, output: &mut [u8]) -> Result<(), EntropyError> {
        self.0.read_exact(output).map_err(|_| {
            output.fill(0);
            EntropyError::Unavailable
        })
    }
}

/// Private-directory plaintext pages; trust the host user, OS and directory ancestry.
/// No same-user isolation, rollback prevention, secure erase or multi-page reset atomicity.
pub struct FileStorage {
    directory: PathBuf,
    _lock: File,
}

/// Dedicated PIN journal directory; host storage does not prevent rollback.
pub struct FilePinStorage(FileStorage);

impl FilePinStorage {
    pub fn open(parent: impl AsRef<Path>) -> io::Result<Self> {
        FileStorage::open(parent.as_ref().join("pin")).map(Self)
    }
}

impl PinUvAuthPageBackend for FilePinStorage {
    fn read_pin_page(
        &mut self,
        page: usize,
        buffer: &mut [u8; PIN_UV_AUTH_PAGE_SIZE],
    ) -> Result<(), PinStorageError> {
        self.0
            .read_page(page, buffer)
            .map_err(|_| PinStorageError::ReadFailed)
    }

    fn write_pin_page(
        &mut self,
        page: usize,
        buffer: &[u8; PIN_UV_AUTH_PAGE_SIZE],
    ) -> Result<(), PinStorageError> {
        self.0
            .write_page(page, buffer)
            .map_err(|_| PinStorageError::WriteFailed)
    }

    fn commit_pin_page(&mut self, page: usize) -> Result<(), PinStorageError> {
        let mut buffer = [0; PIN_UV_AUTH_PAGE_SIZE];
        self.read_pin_page(page, &mut buffer)?;
        buffer[PIN_PAGE_COMMIT_OFFSET..PIN_PAGE_COMMIT_OFFSET + PIN_PAGE_COMMIT_MARKER.len()]
            .copy_from_slice(&PIN_PAGE_COMMIT_MARKER);
        self.write_pin_page(page, &buffer)
    }
}

impl FileStorage {
    pub fn open(directory: impl AsRef<Path>) -> io::Result<Self> {
        let directory = directory.as_ref();
        match DirBuilder::new().mode(0o700).create(directory) {
            Ok(()) => {}
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
            Err(error) => return Err(error),
        }
        let metadata = fs::symlink_metadata(directory)?;
        if !metadata.is_dir() || metadata.permissions().mode() & 0o077 != 0 {
            return Err(io::Error::other("storage directory must be private"));
        }
        let lock_path = directory.join("lock");
        reject_nonregular(&lock_path)?;
        let lock = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .mode(0o600)
            .open(lock_path)?;
        if lock.metadata()?.permissions().mode() & 0o077 != 0 {
            return Err(io::Error::other("storage lock must be private"));
        }
        lock.try_lock().map_err(io::Error::other)?;
        Ok(Self {
            directory: directory.to_path_buf(),
            _lock: lock,
        })
    }

    fn page_path(&self, page: usize) -> io::Result<PathBuf> {
        if page >= STORAGE_PAGE_COUNT {
            return Err(io::Error::other("invalid storage page"));
        }
        Ok(self.directory.join(format!("page-{page}")))
    }

    fn replace_page(&self, page: usize, bytes: &[u8; FLASH_SECTOR_SIZE]) -> io::Result<()> {
        let path = self.page_path(page)?;
        reject_nonregular(&path)?;
        let temporary = self.directory.join(format!("next-{page}"));
        reject_nonregular(&temporary)?;
        match fs::remove_file(&temporary) {
            Ok(()) => {}
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(error),
        }
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&temporary)?;
        file.write_all(bytes)?;
        file.sync_all()?;
        fs::rename(&temporary, path)?;
        File::open(&self.directory)?.sync_all()
    }
}

fn reject_nonregular(path: &Path) -> io::Result<()> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.is_file() && metadata.permissions().mode() & 0o077 == 0 => Ok(()),
        Ok(_) => Err(io::Error::other(
            "storage entry must be a private regular file",
        )),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error),
    }
}

impl StorageBackend for FileStorage {
    fn read_page(
        &mut self,
        page: usize,
        buffer: &mut [u8; FLASH_SECTOR_SIZE],
    ) -> Result<(), StorageError> {
        let path = self.page_path(page).map_err(|_| StorageError::ReadFailed)?;
        reject_nonregular(&path).map_err(|_| StorageError::ReadFailed)?;
        match File::open(path) {
            Ok(mut file) => {
                if file.metadata().map_err(|_| StorageError::ReadFailed)?.len()
                    != FLASH_SECTOR_SIZE as u64
                {
                    return Err(StorageError::ReadFailed);
                }
                file.read_exact(buffer)
                    .map_err(|_| StorageError::ReadFailed)
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                buffer.fill(0xff);
                Ok(())
            }
            Err(_) => Err(StorageError::ReadFailed),
        }
    }

    fn write_page(
        &mut self,
        page: usize,
        buffer: &[u8; FLASH_SECTOR_SIZE],
    ) -> Result<(), StorageError> {
        self.replace_page(page, buffer)
            .map_err(|_| StorageError::WriteFailed)
    }

    fn commit_page(&mut self, page: usize) -> Result<(), StorageError> {
        let mut buffer = [0; FLASH_SECTOR_SIZE];
        self.read_page(page, &mut buffer)
            .map_err(|_| StorageError::WriteFailed)?;
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
