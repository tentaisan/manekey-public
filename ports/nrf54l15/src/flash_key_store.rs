use crate::{
    crypto::CracenP256,
    storage::{Nrf54RramKeyStorage, Nrf54SharedRram},
};
use manekey::ctaphid::{
    entropy::EntropySource,
    flash_key_storage::FlashKeyStorage,
    managed_key_store::{ManagedKeyError, ManagedPrivateKeyStore},
};

pub type FlashKeys = ManagedPrivateKeyStore<FlashKeyStorage<Nrf54RramKeyStorage>, CracenP256>;

/// Open reserved plaintext RRAM assets under exclusive Secure RRAM/crypto ownership.
/// Setup requires authorized empty media; Flash-backed storage is not CPU-invisible key protection.
pub fn open<E: EntropySource>(
    rram: &'static Nrf54SharedRram,
    entropy: &mut E,
    empty_journal: bool,
) -> Result<FlashKeys, ManagedKeyError> {
    #[allow(unused_mut)]
    let mut assets = FlashKeyStorage::open(Nrf54RramKeyStorage::new(rram), *b"N54-FIDO")?;
    #[cfg(feature = "flash-managed-key-setup")]
    if matches!(assets.load_root(), Err(ManagedKeyError::MissingAsset)) {
        assets.initialize_root(entropy, empty_journal)?;
    }
    let _ = (entropy, empty_journal);
    let root = assets.load_root()?;
    ManagedPrivateKeyStore::new(
        assets,
        root,
        CracenP256,
        b"manekey-fido-nrf54-rram-handle-v1",
        b"manekey-fido-nrf54-rram-prf-v1",
    )
}
