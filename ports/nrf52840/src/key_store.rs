#[cfg(all(
    feature = "nrf-cryptocell-sha256",
    not(feature = "client-pin-volatile")
))]
use crate::crypto::Cc310Sha256;
#[cfg(feature = "client-pin-volatile")]
use crate::crypto::SharedCc310Sha256;
#[cfg(feature = "experimental-ml-dsa-fips204")]
use manekey::ctaphid::key_store::AdditionalSignaturePrivateKeyStore;
#[cfg(all(
    feature = "nrf-cryptocell-sha256",
    not(feature = "nrf-flash-managed-keys")
))]
use manekey::ctaphid::key_store::DerivedPrivateKeyStore;
#[cfg(not(feature = "nrf-cryptocell-sha256"))]
use manekey::ctaphid::key_store::FlashPrivateKeyStore;
#[cfg(not(feature = "nrf-flash-managed-keys"))]
use nrf52840_pac::FICR;

#[cfg(all(
    feature = "nrf-cryptocell-sha256",
    not(feature = "client-pin-volatile")
))]
pub type SelectedClassicalPrivateKeyStore = DerivedPrivateKeyStore<Cc310Sha256>;

#[cfg(all(
    feature = "client-pin-volatile",
    not(feature = "nrf-flash-managed-keys")
))]
pub type SelectedClassicalPrivateKeyStore = DerivedPrivateKeyStore<SharedCc310Sha256>;

#[cfg(feature = "nrf-flash-managed-keys")]
pub type SelectedClassicalPrivateKeyStore =
    manekey::ctaphid::managed_key_store::ManagedPrivateKeyStore<
        manekey::ctaphid::flash_key_storage::FlashKeyStorage<crate::storage::NrfManagedKeyStorage>,
        manekey::ctaphid::crypto::SoftwareEs256,
        SharedCc310Sha256,
    >;

#[cfg(feature = "nrf-flash-managed-keys")]
/// Open with exclusive private Flash/CryptoCell ownership and matching SoftDevice storage mode.
/// Flash-backed root protection is software/boundary-owned, not a hardware key vault.
pub(crate) fn open_managed<
    R: manekey::ctaphid::storage::StorageBackend,
    E: manekey::ctaphid::entropy::EntropySource,
>(
    softdevice: bool,
    records: &mut manekey::ctaphid::storage::Storage<R>,
    entropy: &mut E,
    hash: SharedCc310Sha256,
    log: fn(&str),
) -> Result<SelectedClassicalPrivateKeyStore, manekey::ctaphid::managed_key_store::ManagedKeyError>
{
    use manekey::ctaphid::{
        flash_key_storage::FlashKeyStorage, managed_key_store::ManagedKeyError,
        storage::MAX_RECORDS,
    };
    let mut empty = true;
    log("managed: checking credential journal\r\n");
    for index in 0..MAX_RECORDS {
        empty &= records
            .load_record_checked(index)
            .map_err(|_| ManagedKeyError::CorruptStorage)?
            .is_none();
    }
    log("managed: credential journal validation done\r\n");
    let mut assets = FlashKeyStorage::open(
        crate::storage::NrfManagedKeyStorage::new(softdevice),
        *b"NRF-FID1",
    )?;
    log("managed: key journal opened\r\n");
    if matches!(assets.load_root(), Err(ManagedKeyError::MissingAsset)) {
        if !cfg!(feature = "nrf-flash-managed-key-setup") {
            return Err(ManagedKeyError::MissingAsset);
        }
        log("managed: initializing root on empty journal\r\n");
        assets.initialize_root(entropy, empty)?;
    }
    let root = assets.load_root()?;
    let mut keys = SelectedClassicalPrivateKeyStore::new_with_hash(
        assets,
        root,
        manekey::ctaphid::crypto::SoftwareEs256,
        b"manekey-nrf52840-flash-handle-v1",
        b"manekey-nrf52840-flash-prf-v1",
        hash,
    )?;
    log("managed: reconciling checked records\r\n");
    keys.reconcile(records)?;
    Ok(keys)
}

#[cfg(not(feature = "nrf-cryptocell-sha256"))]
pub type SelectedClassicalPrivateKeyStore = FlashPrivateKeyStore;

#[cfg(not(feature = "experimental-ml-dsa-fips204"))]
pub type SelectedPrivateKeyStore = SelectedClassicalPrivateKeyStore;

#[cfg(feature = "experimental-ml-dsa-fips204")]
pub type SelectedPrivateKeyStore = AdditionalSignaturePrivateKeyStore<
    SelectedClassicalPrivateKeyStore,
    crate::signature_backend::SelectedMlDsa,
>;

#[cfg(not(feature = "experimental-ml-dsa-fips204"))]
pub fn wrap_private_key_store(store: SelectedClassicalPrivateKeyStore) -> SelectedPrivateKeyStore {
    store
}

#[cfg(feature = "experimental-ml-dsa-fips204")]
pub fn wrap_private_key_store(store: SelectedClassicalPrivateKeyStore) -> SelectedPrivateKeyStore {
    AdditionalSignaturePrivateKeyStore::new(store, crate::signature_backend::selected())
}

#[cfg(all(
    feature = "nrf-cryptocell-sha256",
    not(feature = "client-pin-volatile")
))]
/// Legacy FICR identity derivation is not a secret hardware root; caller excludes concurrent CryptoCell access.
pub fn selected_private_key_store(ficr: FICR, log: fn(&str)) -> SelectedPrivateKeyStore {
    log("key-store=nrf-cryptocell-derived\r\n");
    let device_id = nrf_device_id(&ficr);

    let sha256 = unsafe { Cc310Sha256::new_unchecked() };
    wrap_private_key_store(
        DerivedPrivateKeyStore::from_device_id_with_hash(&device_id, sha256)
            .expect("derive nRF52840 device key with CryptoCell SHA-256"),
    )
}

#[cfg(not(feature = "nrf-cryptocell-sha256"))]
pub fn selected_private_key_store(_ficr: FICR, log: fn(&str)) -> SelectedPrivateKeyStore {
    log("key-store=flash-private-key\r\n");
    wrap_private_key_store(FlashPrivateKeyStore)
}

#[cfg(all(
    feature = "nrf-cryptocell-sha256",
    not(feature = "nrf-flash-managed-keys")
))]
pub(crate) fn nrf_device_id(ficr: &FICR) -> [u8; 8] {
    let lo = ficr.deviceid[0].read().deviceid().bits();
    let hi = ficr.deviceid[1].read().deviceid().bits();
    let mut id = [0u8; 8];
    id[..4].copy_from_slice(&lo.to_le_bytes());
    id[4..].copy_from_slice(&hi.to_le_bytes());
    id
}
