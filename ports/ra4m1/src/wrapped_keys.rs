
use crate::{
    data_flash::BLOCK,
    sce_wrapped::WrappedAes256,
    storage::{Journal, SharedFlash},
};
#[cfg(feature = "flash-managed-key-setup")]
use manekey::ctaphid::storage::StorageBackend;
use manekey::ctaphid::{
    entropy::EntropySource,
    flash_key_storage::FlashKeyStorage,
    managed_key_store::{KeyPersistenceProtection, ManagedKeyError, RamKeyStorage},
    wrapped_key_pages::WrappedKeyPages,
};
use zeroize::Zeroizing;
const BASE: usize = 7 * BLOCK;
const OWNER: &[u8; 8] = b"RA-KMU01";
type Pages = WrappedKeyPages<Journal, WrappedAes256>;
pub struct Assets(pub FlashKeyStorage<Pages>);

pub fn open<E: EntropySource>(
    flash: &'static SharedFlash,
    entropy: &mut E,
    empty_records: bool,
) -> Result<Assets, ()> {
    let mut page = Zeroizing::new([0xff; BLOCK]);
    flash
        .try_borrow()
        .map_err(|_| ())?
        .read(BASE, &mut *page)
        .map_err(|_| ())?;
    let key = if page.iter().all(|b| *b == 0xff) {
        #[cfg(not(feature = "flash-managed-key-setup"))]
        {
            let _ = (entropy, empty_records);
            return Err(());
        }
        #[cfg(feature = "flash-managed-key-setup")]
        {
            if !empty_records {
                return Err(());
            }
            let mut journal = Journal::keys(flash);
            for index in 0..2 {
                journal.read_page(index, &mut page).map_err(|_| ())?;
                if page.iter().any(|b| *b != 0xff) {
                    return Err(());
                }
            }
            let mut raw = Zeroizing::new([0; 32]);
            entropy.fill_entropy(&mut *raw).map_err(|_| ())?;
            let key = WrappedAes256::wrap(&raw).map_err(|_| ())?;
            page.fill(0xff);
            page[..8].copy_from_slice(OWNER);
            page[8..72].copy_from_slice(&key.blob()[..]);
            let mut media = flash.try_borrow_mut().map_err(|_| ())?;
            media.program(BASE + 8, &page[8..72]).map_err(|_| ())?;
            media.program(BASE, OWNER).map_err(|_| ())?;
            let mut verify = Zeroizing::new([0; BLOCK]);
            media.read(BASE, &mut *verify).map_err(|_| ())?;
            if verify[..] != page[..] {
                return Err(());
            }
            key
        }
    } else {
        if &page[..8] != OWNER || page[72..].iter().any(|b| *b != 0xff) {
            return Err(());
        }
        WrappedAes256::from_blob(page[8..72].try_into().map_err(|_| ())?)
    };
    // Validate the hardware index before opening even an empty journal.
    let mut key = key;
    let mut check = Zeroizing::new([0x42; 16]);
    key.apply(&mut check, false).map_err(|_| ())?;
    key.apply(&mut check, true).map_err(|_| ())?;
    if check[..] != [0x42; 16] {
        return Err(());
    }
    FlashKeyStorage::open(Pages::new(Journal::keys(flash), key), *b"RA-FIDO1")
        .map(Assets)
        .map_err(|_| ())
}

impl Assets {
    pub fn load_root(&self) -> Result<Zeroizing<[u8; 32]>, ManagedKeyError> {
        self.0.load_root()
    }
    #[cfg(feature = "flash-managed-key-setup")]
    pub fn initialize_root<E: EntropySource>(
        &mut self,
        entropy: &mut E,
        empty: bool,
    ) -> Result<(), ManagedKeyError> {
        self.0.initialize_root(entropy, empty)
    }
}
impl RamKeyStorage for Assets {
    fn capacity(&self) -> usize {
        self.0.capacity()
    }
    fn protection(&self) -> KeyPersistenceProtection {
        KeyPersistenceProtection::HardwareWrapped
    }
    fn nonce(&mut self, index: usize) -> Result<Option<[u8; 16]>, ManagedKeyError> {
        self.0.nonce(index)
    }
    fn load_private(&mut self, index: usize) -> Result<Zeroizing<[u8; 32]>, ManagedKeyError> {
        self.0.load_private(index)
    }
    fn provision(
        &mut self,
        index: usize,
        private: &[u8; 32],
        nonce: &[u8; 16],
    ) -> Result<(), ManagedKeyError> {
        self.0.provision(index, private, nonce)
    }
    fn release(&mut self, index: usize) -> Result<(), ManagedKeyError> {
        self.0.release(index)
    }
}
