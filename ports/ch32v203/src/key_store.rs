#[cfg(feature = "fido-p256")]
use manekey::ctaphid::crypto;
#[cfg(feature = "fido-p256")]
use manekey::ctaphid::{
    credential::CREDENTIAL_ID_LEN,
    entropy::EntropySource,
    key_store::{KEY_MATERIAL_LEN, PrivateKeyStore},
};

#[cfg(feature = "fido-p256")]
/// Software P-256 adapter; stored key material protection belongs to the selected storage/boundary.
pub struct P256KeyStore;

#[cfg(feature = "fido-p256")]
impl P256KeyStore {
    pub const fn new() -> Self {
        Self
    }
}

#[cfg(feature = "fido-p256")]
impl PrivateKeyStore for P256KeyStore {
    fn create_key_material<E: EntropySource>(
        &mut self,
        _credential_id: &[u8; CREDENTIAL_ID_LEN],
        entropy: &mut E,
    ) -> Option<[u8; KEY_MATERIAL_LEN]> {
        manekey::ctaphid::key_store::FlashPrivateKeyStore
            .create_key_material(_credential_id, entropy)
    }

    fn public_key_xy(
        &mut self,
        key_material: &[u8; KEY_MATERIAL_LEN],
    ) -> Option<([u8; 32], [u8; 32])> {
        crypto::public_key_xy(&crypto::signing_key_from_bytes(key_material)?)
    }

    fn sign<'a>(
        &mut self,
        key_material: &[u8; KEY_MATERIAL_LEN],
        auth_data: &[u8],
        client_data_hash: &[u8; 32],
        signature_buf: &'a mut [u8],
    ) -> Option<&'a [u8]> {
        crypto::sign_assertion(
            &crypto::signing_key_from_bytes(key_material)?,
            auth_data,
            client_data_hash,
            signature_buf,
        )
    }
}

#[cfg(all(feature = "fido-p256", not(feature = "flash-managed-keys")))]
pub type SelectedKeyStore = P256KeyStore;
#[cfg(feature = "flash-managed-keys")]
pub type SelectedKeyStore = manekey::ctaphid::managed_key_store::ManagedPrivateKeyStore<
    manekey::ctaphid::flash_key_storage::FlashKeyStorage<crate::storage::Ch32ManagedFlashStorage>,
    manekey::ctaphid::crypto::SoftwareEs256,
>;

#[cfg(feature = "flash-managed-keys")]
/// Open with exclusive private Flash ownership; root protection is software/boundary-owned, not a hardware key vault.
pub fn open_managed<E: EntropySource>(
    records: &mut manekey::ctaphid::storage::Storage<crate::storage::SelectedStorage>,
    entropy: &mut E,
) -> Result<SelectedKeyStore, manekey::ctaphid::managed_key_store::ManagedKeyError> {
    use manekey::ctaphid::{
        crypto::SoftwareEs256, flash_key_storage::FlashKeyStorage,
        managed_key_store::ManagedKeyError, storage::MAX_RECORDS,
    };
    let mut empty = true;
    for index in 0..MAX_RECORDS {
        empty &= records
            .load_record_checked(index)
            .map_err(|_| ManagedKeyError::CorruptStorage)?
            .is_none();
    }
    let mut assets =
        FlashKeyStorage::open(crate::storage::Ch32ManagedFlashStorage::new(), *b"CH-FIDO1")?;
    if matches!(assets.load_root(), Err(ManagedKeyError::MissingAsset)) {
        if !cfg!(feature = "flash-managed-key-setup") {
            return Err(ManagedKeyError::MissingAsset);
        }
        assets.initialize_root(entropy, empty)?;
    }
    let root = assets.load_root()?;
    let mut keys = SelectedKeyStore::new(
        assets,
        root,
        SoftwareEs256,
        b"manekey-ch32-flash-handle-v1",
        b"manekey-ch32-flash-prf-v1",
    )?;
    keys.reconcile(records)?;
    Ok(keys)
}

#[cfg(all(not(any()), not(feature = "fido-p256")))]
compile_error!("select fido-p256 for a product or an explicit private key-store fixture");
