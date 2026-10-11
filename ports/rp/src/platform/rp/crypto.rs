#[cfg(all(
    feature = "experimental-ml-dsa-fips204-scratch",
    feature = "experimental-ml-dsa-mldsa-native"
))]
compile_error!("select only one RP ML-DSA comparison backend");
#[cfg(feature = "experimental-ml-dsa-mldsa-native")]
pub type MlDsa = manekey::ctaphid::pqc_signature_mldsa_native::MldsaNativeMlDsa44;
#[cfg(all(
    feature = "experimental-ml-dsa-fips204-scratch",
    not(feature = "experimental-ml-dsa-mldsa-native")
))]
pub type MlDsa = manekey::ctaphid::pqc_signature_fips204_scratch::Fips204ScratchMlDsa44<'static>;
#[cfg(not(any(
    feature = "experimental-ml-dsa-fips204-scratch",
    feature = "experimental-ml-dsa-mldsa-native"
)))]
#[cfg(feature = "experimental-ml-dsa-fips204")]
pub type MlDsa = manekey::ctaphid::pqc_signature_fips204::Fips204MlDsa44;

#[cfg(feature = "experimental-ml-dsa-fips204-scratch")]
static SCRATCH: static_cell::StaticCell<manekey_fips204_scratch::ml_dsa_44::SignScratch> =
    static_cell::StaticCell::new();

#[cfg(feature = "experimental-ml-dsa-fips204")]
/// Experimental backend selection; initialize static scratch once and keep it private from reentry/IRQ/DMA.
/// Selection does not prove available stack or RAM capacity.
pub fn ml_dsa() -> MlDsa {
    #[cfg(feature = "experimental-ml-dsa-mldsa-native")]
    return manekey::ctaphid::pqc_signature_mldsa_native::MldsaNativeMlDsa44;
    #[cfg(all(
        feature = "experimental-ml-dsa-fips204-scratch",
        not(feature = "experimental-ml-dsa-mldsa-native")
    ))]
    return MlDsa::new(
        manekey_fips204_scratch::ml_dsa_44::SignScratch::init_zeroed(SCRATCH.uninit()),
    );
    #[cfg(not(any(
        feature = "experimental-ml-dsa-fips204-scratch",
        feature = "experimental-ml-dsa-mldsa-native"
    )))]
    manekey::ctaphid::pqc_signature_fips204::Fips204MlDsa44
}
