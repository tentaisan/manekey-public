
use crate::storage::{Journal, SharedFlash};
use manekey::ctaphid::{entropy::EntropySource, storage::Storage};
#[cfg(not(feature = "flash-managed-keys"))]
pub type Keys = manekey::ctaphid::key_store::DerivedPrivateKeyStore;
#[cfg(feature = "flash-managed-keys")]
#[cfg(not(feature = "hardware-wrapped-keys"))]
type Assets = manekey::ctaphid::flash_key_storage::FlashKeyStorage<Journal>;
#[cfg(feature = "hardware-wrapped-keys")]
type Assets = crate::wrapped_keys::Assets;
#[cfg(feature = "flash-managed-keys")]
pub type Keys = manekey::ctaphid::managed_key_store::ManagedPrivateKeyStore<
    Assets,
    manekey::ctaphid::crypto::SoftwareEs256,
>;

pub fn open<E: EntropySource>(
    flash: &'static SharedFlash,
    entropy: &mut E,
    records: &mut Storage<Journal>,
) -> Result<Keys, ()> {
    #[cfg(not(feature = "flash-managed-keys"))]
    {
        let _ = records;
        let mut candidate = zeroize::Zeroizing::new([0; 32]);
        entropy.fill_entropy(&mut *candidate).map_err(|_| ())?;
        Ok(Keys::new(crate::storage::device_secret(flash, &candidate)?))
    }
    #[cfg(feature = "flash-managed-keys")]
    {
        use manekey::ctaphid::{
            crypto::SoftwareEs256,
            managed_key_store::{ManagedKeyError, ManagedPrivateKeyStore},
            storage::MAX_RECORDS,
        };
        let mut empty = true;
        for index in 0..MAX_RECORDS {
            empty &= records
                .load_record_checked(index)
                .map_err(|_| ())?
                .is_none();
        }
        #[cfg(not(feature = "hardware-wrapped-keys"))]
        let assets = Assets::open(Journal::keys(flash), *b"RA-FIDO1").map_err(|_| ())?;
        #[cfg(feature = "hardware-wrapped-keys")]
        let assets = crate::wrapped_keys::open(flash, entropy, empty)?;
        #[cfg(feature = "flash-managed-key-setup")]
        let mut assets = assets;
        if matches!(assets.load_root(), Err(ManagedKeyError::MissingAsset)) {
            #[cfg(feature = "flash-managed-key-setup")]
            assets.initialize_root(entropy, empty).map_err(|_| ())?;
            #[cfg(not(feature = "flash-managed-key-setup"))]
            return Err(());
        }
        let _ = (entropy, empty);
        let root = assets.load_root().map_err(|_| ())?;
        let mut keys = ManagedPrivateKeyStore::new(
            assets,
            root,
            SoftwareEs256,
            b"manekey-ra-data-flash-handle-v1",
            b"manekey-ra-data-flash-prf-v1",
        )
        .map_err(|_| ())?;
        keys.reconcile(records).map_err(|_| ())?;
        Ok(keys)
    }
}
