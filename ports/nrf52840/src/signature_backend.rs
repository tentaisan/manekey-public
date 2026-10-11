#[cfg(all(
    feature = "experimental-ml-dsa-fips204-scratch",
    feature = "experimental-ml-dsa-mldsa-native"
))]
compile_error!("select one nRF ML-DSA comparison backend");
#[cfg(feature = "experimental-ml-dsa-mldsa-native")]
pub type MlDsa = manekey::ctaphid::pqc_signature_mldsa_native::MldsaNativeMlDsa44;
#[cfg(feature = "experimental-ml-dsa-fips204-scratch")]
pub type MlDsa = manekey::ctaphid::pqc_signature_fips204_scratch::Fips204ScratchMlDsa44<'static>;
#[cfg(not(any(
    feature = "experimental-ml-dsa-fips204-scratch",
    feature = "experimental-ml-dsa-mldsa-native"
)))]
pub type MlDsa = manekey::ctaphid::pqc_signature_fips204::Fips204MlDsa44;
#[cfg(feature = "experimental-ml-dsa-fips204-scratch")]
static SCRATCH: static_cell::StaticCell<manekey_fips204_scratch::ml_dsa_44::SignScratch> =
    static_cell::StaticCell::new();
/// Initialize once per boot; keep scratch private and exclude reentry, IRQ and DMA access.
/// Backend selection does not prove stack capacity.
pub fn ml_dsa() -> MlDsa {
    #[cfg(feature = "experimental-ml-dsa-mldsa-native")]
    return manekey::ctaphid::pqc_signature_mldsa_native::MldsaNativeMlDsa44;
    #[cfg(feature = "experimental-ml-dsa-fips204-scratch")]
    return MlDsa::new(
        manekey_fips204_scratch::ml_dsa_44::SignScratch::init_zeroed(SCRATCH.uninit()),
    );
    #[cfg(not(any(
        feature = "experimental-ml-dsa-fips204-scratch",
        feature = "experimental-ml-dsa-mldsa-native"
    )))]
    manekey::ctaphid::pqc_signature_fips204::Fips204MlDsa44
}

pub type SelectedMlDsa = MlDsa;
pub fn selected() -> SelectedMlDsa {
    ml_dsa()
}
