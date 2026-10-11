use crate::{
    crypto,
    storage::{Journal, SharedFlash},
};
use manekey::ctaphid::{entropy::EntropySource, storage::Storage};
#[cfg(not(feature = "flash-managed-keys"))]
type Base = crypto::DerivedKeys;
#[cfg(feature = "flash-managed-keys")]
type Assets = manekey::ctaphid::flash_key_storage::FlashKeyStorage<Journal>;
#[cfg(feature = "flash-managed-keys")]
type Base = manekey::ctaphid::managed_key_store::ManagedPrivateKeyStore<
    Assets,
    manekey::ctaphid::crypto::SoftwareEs256,
    crypto::Hash,
>;

#[cfg(all(
    feature = "experimental-ml-dsa-fips204",
    feature = "experimental-ml-dsa-mldsa-native"
))]
compile_error!("Select exactly one ML-DSA backend");
#[cfg(feature = "experimental-ml-dsa-fips204")]
type Signature = manekey::ctaphid::pqc_signature_fips204::Fips204MlDsa44;
#[cfg(feature = "experimental-ml-dsa-mldsa-native")]
type Signature = manekey::ctaphid::pqc_signature_mldsa_native::MldsaNativeMlDsa44;
#[cfg(any(
    feature = "experimental-ml-dsa-fips204",
    feature = "experimental-ml-dsa-mldsa-native"
))]
pub type Keys = manekey::ctaphid::key_store::AdditionalSignaturePrivateKeyStore<Base, Signature>;
#[cfg(not(any(
    feature = "experimental-ml-dsa-fips204",
    feature = "experimental-ml-dsa-mldsa-native"
)))]
pub type Keys = Base;

/// Open with exclusive private Flash ownership; root protection is boundary/software-owned, not a hardware key vault.
pub fn open<E: EntropySource>(
    flash: &'static SharedFlash,
    entropy: &mut E,
    records: &mut Storage<Journal>,
) -> Result<Keys, ()> {
    #[cfg(not(feature = "flash-managed-keys"))]
    let base = {
        let _ = records;
        let mut candidate = [0; 32];
        entropy.fill_entropy(&mut candidate).map_err(|_| ())?;
        crypto::derived_keys(crate::storage::device_secret(flash, candidate))
    };
    #[cfg(feature = "flash-managed-keys")]
    let base = {
        use manekey::ctaphid::{managed_key_store::ManagedKeyError, storage::MAX_RECORDS};
        let mut empty = true;
        for index in 0..MAX_RECORDS {
            empty &= records
                .load_record_checked(index)
                .map_err(|_| ())?
                .is_none();
        }
        let assets = Assets::open(Journal::keys(flash), *b"U5-FIDO1").map_err(|_| ())?;
        #[cfg(feature = "flash-managed-key-setup")]
        let mut assets = assets;
        if matches!(assets.load_root(), Err(ManagedKeyError::MissingAsset)) {
            #[cfg(feature = "flash-managed-key-setup")]
            assets.initialize_root(entropy, empty).map_err(|_| ())?;
            #[cfg(not(feature = "flash-managed-key-setup"))]
            return Err(());
        }
        let _ = (empty, entropy);
        let root = assets.load_root().map_err(|_| ())?;
        let mut base = Base::new_with_hash(
            assets,
            root,
            manekey::ctaphid::crypto::SoftwareEs256,
            b"manekey-u575-flash-handle-v1",
            b"manekey-u575-flash-prf-v1",
            crypto::hash_backend(),
        )
        .map_err(|_| ())?;
        base.reconcile(records).map_err(|_| ())?;
        base
    };
    #[cfg(feature = "experimental-ml-dsa-fips204")]
    {
        Ok(Keys::new(
            base,
            manekey::ctaphid::pqc_signature_fips204::Fips204MlDsa44,
        ))
    }
    #[cfg(feature = "experimental-ml-dsa-mldsa-native")]
    {
        Ok(Keys::new(
            base,
            manekey::ctaphid::pqc_signature_mldsa_native::MldsaNativeMlDsa44,
        ))
    }
    #[cfg(not(any(
        feature = "experimental-ml-dsa-fips204",
        feature = "experimental-ml-dsa-mldsa-native"
    )))]
    {
        Ok(base)
    }
}
