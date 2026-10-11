use manekey::ctaphid::{
    crypto::SoftwareEs256,
    entropy::EntropySource,
    flash_key_storage::FlashKeyStorage,
    hash::{Sha256Backend, SoftwareSha256},
    managed_key_store::{ManagedKeyError, ManagedPrivateKeyStore},
    storage::{MAX_RECORDS, Storage, StorageBackend},
};

pub type ClassicalKeys<B, H = SoftwareSha256> =
    ManagedPrivateKeyStore<FlashKeyStorage<B>, SoftwareEs256, H>;

/// Caller owns serialized media/hash access; delegated media service must already be running.
/// Root setup is explicit and requires empty credential media; plaintext Flash is not a hardware key vault.
pub fn open_classical<B: StorageBackend, R: StorageBackend, E: EntropySource, H: Sha256Backend>(
    backend: B,
    records: &mut Storage<R>,
    entropy: &mut E,
    hash: H,
    setup: bool,
) -> Result<ClassicalKeys<B, H>, ManagedKeyError> {
    let mut empty = true;
    for index in 0..MAX_RECORDS {
        empty &= records
            .load_record_checked(index)
            .map_err(|_| ManagedKeyError::CorruptStorage)?
            .is_none();
    }
    let mut assets = FlashKeyStorage::open(backend, *b"RP-FIDO1")?;
    if matches!(assets.load_root(), Err(ManagedKeyError::MissingAsset)) {
        if !setup {
            return Err(ManagedKeyError::MissingAsset);
        }
        assets.initialize_root(entropy, empty)?;
    }
    let _ = (empty, entropy);
    let root = assets.load_root()?;
    let mut base = ClassicalKeys::new_with_hash(
        assets,
        root,
        SoftwareEs256,
        b"manekey-rp2350-flash-handle-v1",
        b"manekey-rp2350-flash-prf-v1",
        hash,
    )?;
    base.reconcile(records)?;
    Ok(base)
}
