#[cfg(not(feature = "flash-managed-keys"))]
use manekey::ctaphid::key_store::DerivedPrivateKeyStore;
#[cfg(not(feature = "flash-managed-keys"))]
type Base = DerivedPrivateKeyStore;
#[cfg(feature = "flash-managed-keys")]
type Assets = manekey::ctaphid::flash_key_storage::FlashKeyStorage<crate::storage::Journal>;
#[cfg(feature = "flash-managed-keys")]
type Base = manekey::ctaphid::managed_key_store::ManagedPrivateKeyStore<
    Assets,
    manekey::ctaphid::crypto::SoftwareEs256,
>;

#[cfg(any(
    all(feature = "ml-dsa-fips204", feature = "ml-dsa-native"),
    all(feature = "ml-dsa-scratch", feature = "ml-dsa-native"),
    all(feature = "ml-dsa-scratch", feature = "ml-dsa-fips204")
))]
compile_error!("select exactly one ML-DSA backend");
#[cfg(feature = "ml-dsa-fips204")]
type Signature = manekey::ctaphid::pqc_signature_fips204::Fips204MlDsa44;
#[cfg(feature = "ml-dsa-native")]
type Signature = manekey::ctaphid::pqc_signature_mldsa_native::MldsaNativeMlDsa44;
#[cfg(feature = "ml-dsa-scratch")]
type Signature = manekey::ctaphid::pqc_signature_fips204_scratch::Fips204ScratchMlDsa44<'static>;
#[cfg(any(
    feature = "ml-dsa-fips204",
    feature = "ml-dsa-native",
    feature = "ml-dsa-scratch"
))]
pub type KeyStore =
    manekey::ctaphid::key_store::AdditionalSignaturePrivateKeyStore<Base, Signature>;
#[cfg(not(any(
    feature = "ml-dsa-fips204",
    feature = "ml-dsa-native",
    feature = "ml-dsa-scratch"
)))]
pub type KeyStore = Base;

/// Open once per dispatcher/boot; preserve private scratch and exclusive Flash ownership.
/// Flash root protection is software/boundary-owned, not a hardware key vault.
pub fn open<E: manekey::ctaphid::entropy::EntropySource>(
    flash: &'static crate::storage::SharedFlash,
    entropy: &mut E,
    records: &mut manekey::ctaphid::storage::Storage<crate::storage::Journal>,
) -> Result<KeyStore, ()> {
    #[cfg(not(feature = "flash-managed-keys"))]
    let base = {
        let _ = records;
        let mut candidate = [0; 32];
        entropy.fill_entropy(&mut candidate).map_err(|_| ())?;
        DerivedPrivateKeyStore::new(crate::storage::device_secret(flash, candidate))
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
        let assets =
            Assets::open(crate::storage::Journal::keys(flash), *b"F4-FIDO1").map_err(|_| ())?;
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
        let mut base = Base::new(
            assets,
            root,
            manekey::ctaphid::crypto::SoftwareEs256,
            b"manekey-f411-flash-handle-v1",
            b"manekey-f411-flash-prf-v1",
        )
        .map_err(|_| ())?;
        base.reconcile(records).map_err(|_| ())?;
        base
    };
    #[cfg(feature = "ml-dsa-fips204")]
    let signature = manekey::ctaphid::pqc_signature_fips204::Fips204MlDsa44;
    #[cfg(feature = "ml-dsa-native")]
    let signature = manekey::ctaphid::pqc_signature_mldsa_native::MldsaNativeMlDsa44;
    #[cfg(feature = "ml-dsa-scratch")]
    let signature = {
        use manekey_fips204_scratch::ml_dsa_44::SignScratch;
        static SCRATCH: static_cell::StaticCell<SignScratch> = static_cell::StaticCell::new();

        Signature::new(SignScratch::init_zeroed(SCRATCH.uninit()))
    };
    #[cfg(any(
        feature = "ml-dsa-fips204",
        feature = "ml-dsa-native",
        feature = "ml-dsa-scratch"
    ))]
    {
        Ok(KeyStore::new(base, signature))
    }
    #[cfg(not(any(
        feature = "ml-dsa-fips204",
        feature = "ml-dsa-native",
        feature = "ml-dsa-scratch"
    )))]
    {
        Ok(base)
    }
}
