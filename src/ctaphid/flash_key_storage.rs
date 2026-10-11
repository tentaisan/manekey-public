


use zeroize::{Zeroize, Zeroizing};

use super::{
    crypto,
    entropy::EntropySource,
    hash::{Sha256Backend, SoftwareSha256},
    managed_key_store::{KeyPersistenceProtection, ManagedKeyError, RamKeyStorage},
    storage::{FLASH_SECTOR_SIZE, MAX_RECORDS, STORAGE_PAGE_COMMIT_MARKER, StorageBackend},
};

const MAGIC: &[u8; 8] = b"MKFLASH1";
const HEADER: usize = 64;
const ROOT_END: usize = HEADER + 32;
const RECORD: usize = 64;

pub const FLASH_KEY_STORAGE_USED_LEN: usize = ROOT_END + MAX_RECORDS * RECORD;
const _: () = assert!(ROOT_END + MAX_RECORDS * RECORD <= FLASH_SECTOR_SIZE);

pub struct FlashKeyStorage<B> {
    // Dedicated plaintext two-page storage; never overlap credentials/PIN physical pages.
    // Backend owns exclusive access and ordered persistent I/O under the chosen boundary.
    // Unkeyed checksum is not authentication/rollback defense; logical release may
    // leave root/private bytes in an older page and is not secure erase.
    backend: B,
    page: Zeroizing<[u8; FLASH_SECTOR_SIZE]>,
    active: Option<usize>,
    sequence: u64,
    poisoned: bool,
    owner: [u8; 8],
}

fn checksum(page: &[u8; FLASH_SECTOR_SIZE]) -> [u8; 32] {
    // Commit marker and checksum are excluded; all format/sequence/payload bytes are covered.
    SoftwareSha256
        .digest_parts(&[&page[..16], &page[20..24], &page[56..]])
        .expect("software SHA256 supports multipart")
}

fn valid(page: &[u8; FLASH_SECTOR_SIZE]) -> Option<u64> {
    if &page[..8] != MAGIC
        || page[16..20] != STORAGE_PAGE_COMMIT_MARKER
        || page[24..56] != checksum(page)
        || page[20..24] != [0xff; 4]
    {
        return None;
    }
    for index in 0..MAX_RECORDS {
        let start = ROOT_END + index * RECORD;
        let record = &page[start..start + RECORD];
        if record.iter().all(|b| *b == 0xff) {
            continue;
        }
        if record[0] != 1
            || record[49..] != [0xff; 15]
            || !crypto::p256_private_scalar_is_valid(record[17..49].try_into().ok()?)
        {
            return None;
        }
    }
    if page[ROOT_END + MAX_RECORDS * RECORD..]
        .iter()
        .any(|b| *b != 0xff)
    {
        return None;
    }
    Some(u64::from_le_bytes(page[8..16].try_into().ok()?))
}

impl<B: StorageBackend> FlashKeyStorage<B> {

    pub fn open(mut backend: B, owner: [u8; 8]) -> Result<Self, ManagedKeyError> {
        if owner == [0xff; 8] {
            return Err(ManagedKeyError::InvalidConfiguration);
        }
        let mut page = Zeroizing::new([0xff; FLASH_SECTOR_SIZE]);
        let mut active = None;
        let mut sequence = 0;
        let mut any_nonblank = false;
        for index in 0..2 {
            backend
                .read_page(index, &mut page)
                .map_err(|_| ManagedKeyError::Hardware)?;
            any_nonblank |= page.iter().any(|b| *b != 0xff);
            if let Some(candidate) = valid(&page) {
                if page[56..HEADER] != owner {
                    return Err(ManagedKeyError::ForeignAsset);
                }
                if active.is_some() && candidate == sequence {
                    return Err(ManagedKeyError::CorruptStorage);
                }
                if active.is_none() || candidate > sequence {
                    active = Some(index);
                    sequence = candidate;
                }
            }
        }
        if let Some(index) = active {
            backend
                .read_page(index, &mut page)
                .map_err(|_| ManagedKeyError::Hardware)?;
            if valid(&page) != Some(sequence) {
                return Err(ManagedKeyError::CorruptStorage);
            }
        } else {
            if any_nonblank {
                return Err(ManagedKeyError::CorruptStorage);
            }
            page.fill(0xff);
        }
        Ok(Self {
            backend,
            page,
            active,
            sequence,
            poisoned: false,
            owner,
        })
    }


    pub fn initialize_root<E: EntropySource>(
        &mut self,
        entropy: &mut E,
        empty_journal: bool,
    ) -> Result<(), ManagedKeyError> {
        // Caller must independently establish an empty credential journal before
        // first provisioning; the boolean is not a journal scan or authorization.
        if self.poisoned {
            return Err(ManagedKeyError::Hardware);
        }
        if self.active.is_some() {
            return Err(ManagedKeyError::ForeignAsset);
        }
        if !empty_journal {
            return Err(ManagedKeyError::InvalidHandle);
        }
        let root: Zeroizing<[u8; 32]> =
            Zeroizing::new(crypto::generate_random_bytes(entropy).ok_or(ManagedKeyError::Entropy)?);
        self.page[HEADER..ROOT_END].copy_from_slice(&*root);
        self.commit()
    }

    pub fn load_root(&self) -> Result<Zeroizing<[u8; 32]>, ManagedKeyError> {
        self.ready()?;
        Ok(Zeroizing::new(
            self.page[HEADER..ROOT_END].try_into().unwrap(),
        ))
    }

    pub fn into_backend(self) -> B {
        self.backend
    }

    fn ready(&self) -> Result<(), ManagedKeyError> {
        if self.poisoned {
            return Err(ManagedKeyError::Hardware);
        }
        if self.active.is_none() {
            return Err(ManagedKeyError::MissingAsset);
        }
        Ok(())
    }

    fn offset(&self, index: usize) -> Result<usize, ManagedKeyError> {
        self.ready()?;
        if index >= MAX_RECORDS {
            return Err(ManagedKeyError::InvalidHandle);
        }
        Ok(ROOT_END + index * RECORD)
    }

    fn commit(&mut self) -> Result<(), ManagedKeyError> {
        self.poisoned = true;
        let Some(sequence) = self.sequence.checked_add(1) else {
            self.page.zeroize();
            return Err(ManagedKeyError::Full);
        };
        let target = self.active.map_or(0, |index| 1 - index);
        self.page[..8].copy_from_slice(MAGIC);
        self.page[56..HEADER].copy_from_slice(&self.owner);
        self.page[8..16].copy_from_slice(&sequence.to_le_bytes());
        self.page[16..20].fill(0xff);
        let digest = checksum(&self.page);
        self.page[24..56].copy_from_slice(&digest);
        // After an ambiguous write/commit failure this object must be reopened,
        // not used with a potentially uncommitted RAM snapshot.
        self.poisoned = true;
        let result = (|| {
            self.backend
                .write_page(target, &self.page)
                .map_err(|_| ManagedKeyError::Hardware)?;
            self.backend
                .commit_page(target)
                .map_err(|_| ManagedKeyError::Hardware)?;
            self.page.zeroize();
            self.backend
                .read_page(target, &mut self.page)
                .map_err(|_| ManagedKeyError::Hardware)?;
            if valid(&self.page) != Some(sequence) {
                return Err(ManagedKeyError::CorruptStorage);
            }
            Ok(())
        })();
        if result.is_err() {
            self.page.zeroize();
        }
        result?;
        self.active = Some(target);
        self.sequence = sequence;
        self.poisoned = false;
        Ok(())
    }
}

impl<B: StorageBackend> RamKeyStorage for FlashKeyStorage<B> {
    fn capacity(&self) -> usize {
        MAX_RECORDS
    }
    fn protection(&self) -> KeyPersistenceProtection {
        KeyPersistenceProtection::Plaintext
    }

    fn nonce(&mut self, index: usize) -> Result<Option<[u8; 16]>, ManagedKeyError> {
        let start = self.offset(index)?;
        if self.page[start] == 0xff {
            return Ok(None);
        }
        Ok(Some(self.page[start + 1..start + 17].try_into().unwrap()))
    }

    fn load_private(&mut self, index: usize) -> Result<Zeroizing<[u8; 32]>, ManagedKeyError> {
        if self.nonce(index)?.is_none() {
            return Err(ManagedKeyError::MissingAsset);
        }
        let start = self.offset(index)?;
        Ok(Zeroizing::new(
            self.page[start + 17..start + 49].try_into().unwrap(),
        ))
    }

    fn provision(
        &mut self,
        index: usize,
        private: &[u8; 32],
        nonce: &[u8; 16],
    ) -> Result<(), ManagedKeyError> {
        if self.nonce(index)?.is_some() {
            return Err(ManagedKeyError::ForeignAsset);
        }
        if !crypto::p256_private_scalar_is_valid(private) {
            return Err(ManagedKeyError::InvalidHandle);
        }
        let start = self.offset(index)?;
        self.page[start] = 1;
        self.page[start + 1..start + 17].copy_from_slice(nonce);
        self.page[start + 17..start + 49].copy_from_slice(private);
        self.commit()
    }

    fn release(&mut self, index: usize) -> Result<(), ManagedKeyError> {
        if self.nonce(index)?.is_none() {
            return Ok(());
        }
        let start = self.offset(index)?;
        self.page[start..start + RECORD].fill(0xff);
        self.commit()
    }
}



