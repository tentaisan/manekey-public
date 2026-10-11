use manekey::ctaphid::{
    crypto::SoftwareEs256,
    entropy::EntropySource,
    flash_key_storage::FlashKeyStorage,
    hash::Sha256Backend,
    managed_key_store::{ManagedKeyError, ManagedPrivateKeyStore},
    storage::{FLASH_SECTOR_SIZE, MAX_RECORDS, Storage, StorageBackend, StorageError},
};

use crate::{
    flash_region::{EspFlashRegion, clear_region, commit_page, read_page, write_page},
    storage::SharedEspFlash,
};

/// Dedicated plaintext key pages; shared flash owner supplies exclusion and boundary protection.
pub struct EspFlashKeyStorage {
    flash: &'static SharedEspFlash<'static>,
    region: EspFlashRegion,
}

impl EspFlashKeyStorage {
    pub fn new(
        flash: &'static SharedEspFlash<'static>,
        region: EspFlashRegion,
    ) -> Result<Self, ManagedKeyError> {
        if region.base as usize % FLASH_SECTOR_SIZE != 0
            || region.len as usize != FLASH_SECTOR_SIZE * 2
            || region.page_range(1, FLASH_SECTOR_SIZE, 2).is_err()
        {
            return Err(ManagedKeyError::Hardware);
        }
        Ok(Self { flash, region })
    }
}

impl StorageBackend for EspFlashKeyStorage {
    fn read_page(
        &mut self,
        page: usize,
        buf: &mut [u8; FLASH_SECTOR_SIZE],
    ) -> Result<(), StorageError> {
        self.flash.lock(|cell| {
            read_page::<FLASH_SECTOR_SIZE, 2>(&mut cell.borrow_mut(), self.region, page, buf)
        })
    }
    fn write_page(
        &mut self,
        page: usize,
        buf: &[u8; FLASH_SECTOR_SIZE],
    ) -> Result<(), StorageError> {
        self.flash.lock(|cell| {
            write_page::<FLASH_SECTOR_SIZE, 2>(&mut cell.borrow_mut(), self.region, page, buf)
        })
    }
    fn commit_page(&mut self, page: usize) -> Result<(), StorageError> {
        self.flash.lock(|cell| {
            commit_page::<FLASH_SECTOR_SIZE, 2>(&mut cell.borrow_mut(), self.region, page)
        })
    }
    fn clear_pages(&mut self) -> Result<(), StorageError> {
        self.flash
            .lock(|cell| clear_region(&mut cell.borrow_mut(), self.region, self.region.len))
    }
}

pub type EspManagedKeyStore<H> =
    ManagedPrivateKeyStore<FlashKeyStorage<EspFlashKeyStorage>, SoftwareEs256, H>;

pub struct ManagedKeyConfig {
    pub region: EspFlashRegion,
    pub owner: [u8; 8],
    pub handle_domain: &'static [u8],
    pub prf_domain: &'static [u8],
    pub allow_setup: bool,
}

/// Requires matching exclusive key partition; missing/overlapping metadata panics rather than falling back.
pub fn require_partition(
    flash: &'static SharedEspFlash<'static>,
    base: u32,
    len: u32,
) -> EspFlashRegion {
    flash.lock(|cell| {
        let mut media = cell.borrow_mut();
        let region = crate::flash_region::find_partition_region(&mut media, "key-assets", len)
            .expect("dedicated managed key partition required");
        assert_eq!(region.base, base);
        assert_eq!(region.len, len);
        let end = base.checked_add(len).expect("managed partition bounds");
        let mut data = [0; esp_bootloader_esp_idf::partitions::PARTITION_TABLE_MAX_LEN];
        let table =
            esp_bootloader_esp_idf::partitions::read_partition_table(&mut *media, &mut data)
                .expect("valid partition table");
        assert!(
            table.iter().all(|part| {
                if part.label_as_str() == "key-assets" {
                    return part.offset() == base && part.len() == len;
                }
                part.offset()
                    .checked_add(part.len())
                    .is_some_and(|part_end| part_end <= base || part.offset() >= end)
            }),
            "managed partition overlaps another partition"
        );
        region
    })
}

/// Reconciles keys/records; setup permission allows a new root only with empty records.
/// Flash journaling does not add encryption, rollback protection or secure erase.
pub fn open_classical<R: StorageBackend, E: EntropySource, H: Sha256Backend>(
    flash: &'static SharedEspFlash<'static>,
    config: ManagedKeyConfig,
    records: &mut Storage<R>,
    entropy: &mut E,
    hash: H,
) -> Result<EspManagedKeyStore<H>, ManagedKeyError> {
    let mut empty = true;
    for index in 0..MAX_RECORDS {
        empty &= records
            .load_record_checked(index)
            .map_err(|_| ManagedKeyError::CorruptStorage)?
            .is_none();
    }
    let mut assets =
        FlashKeyStorage::open(EspFlashKeyStorage::new(flash, config.region)?, config.owner)?;
    if matches!(assets.load_root(), Err(ManagedKeyError::MissingAsset)) {
        if !config.allow_setup {
            return Err(ManagedKeyError::MissingAsset);
        }
        esp_println::println!("ESP managed: explicit root setup on empty journal");
        assets.initialize_root(entropy, empty)?;
    }
    let root = assets.load_root()?;
    let mut keys = EspManagedKeyStore::new_with_hash(
        assets,
        root,
        SoftwareEs256,
        config.handle_domain,
        config.prf_domain,
        hash,
    )?;
    keys.reconcile(records)?;
    esp_println::println!("ESP managed: checked journal and records reconciled");
    Ok(keys)
}
