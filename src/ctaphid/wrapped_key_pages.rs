use super::{
    flash_key_storage::FLASH_KEY_STORAGE_USED_LEN as USED,
    key_wrap::{self, OpaqueAes256Blocks},
    storage::{FLASH_SECTOR_SIZE, STORAGE_PAGE_COMMIT_OFFSET, StorageBackend, StorageError},
};
use zeroize::{Zeroize, Zeroizing};

const HEADER: usize = 24;
const CIPHER_END: usize = HEADER + USED + 8;
const MAGIC: &[u8; 8] = b"MKWRAP01";
const _: () = assert!(CIPHER_END <= FLASH_SECTOR_SIZE && USED % 8 == 0);

/// RFC3394-protected key-journal pages; no anti-rollback or physical-erase guarantee.
/// Media owns commit/persistence semantics and the key backend owns root protection.
pub struct WrappedKeyPages<B, K> {
    media: B,
    key: K,
}

impl<B, K> WrappedKeyPages<B, K> {
    pub fn new(media: B, key: K) -> Self {
        Self { media, key }
    }
    pub fn into_parts(self) -> (B, K) {
        (self.media, self.key)
    }
}
impl<B: StorageBackend, K: OpaqueAes256Blocks> StorageBackend for WrappedKeyPages<B, K> {
    fn read_page(
        &mut self,
        index: usize,
        out: &mut [u8; FLASH_SECTOR_SIZE],
    ) -> Result<(), StorageError> {
        out.zeroize();
        let mut physical = Zeroizing::new([0xff; FLASH_SECTOR_SIZE]);
        self.media.read_page(index, &mut physical)?;
        if physical.iter().all(|b| *b == 0xff) {
            out.fill(0xff);
            return Ok(());
        }
        if &physical[..8] != MAGIC
            || physical[8..16] != (USED as u64).to_le_bytes()
            || physical[20..24] != [0xff; 4]
            || physical[CIPHER_END..].iter().any(|b| *b != 0xff)
        {
            return Err(StorageError::ReadFailed);
        }
        key_wrap::unwrap(
            &mut self.key,
            &physical[HEADER..CIPHER_END],
            &mut out[..USED],
        )
        .map_err(|_| StorageError::ReadFailed)?;

        if out[16..20] != [0xff; 4] {
            out.zeroize();
            return Err(StorageError::ReadFailed);
        }
        out[16..20].copy_from_slice(&physical[16..20]);
        out[USED..].fill(0xff);
        Ok(())
    }
    fn write_page(
        &mut self,
        index: usize,
        page: &[u8; FLASH_SECTOR_SIZE],
    ) -> Result<(), StorageError> {
        if page[16..20] != [0xff; 4] || page[USED..].iter().any(|b| *b != 0xff) {
            return Err(StorageError::WriteFailed);
        }
        let mut physical = Zeroizing::new([0xff; FLASH_SECTOR_SIZE]);
        physical[..8].copy_from_slice(MAGIC);
        physical[8..16].copy_from_slice(&(USED as u64).to_le_bytes());
        key_wrap::wrap(
            &mut self.key,
            &page[..USED],
            &mut physical[HEADER..CIPHER_END],
        )
        .map_err(|_| StorageError::WriteFailed)?;
        self.media.write_page(index, &physical)
    }
    fn commit_page(&mut self, index: usize) -> Result<(), StorageError> {
        const _: () = assert!(STORAGE_PAGE_COMMIT_OFFSET == 16);
        self.media.commit_page(index)
    }
    fn clear_pages(&mut self) -> Result<(), StorageError> {
        self.media.clear_pages()
    }
}
