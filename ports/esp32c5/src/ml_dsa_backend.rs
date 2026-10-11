#[cfg(any(
    all(
        any(
            feature = "experimental-ml-dsa-fips204",
            feature = "pmp-internal-uart-ml-dsa-fips204"
        ),
        any(
            feature = "pmp-internal-uart-ml-dsa-fips204-scratch",
            feature = "pmp-internal-uart-ml-dsa-mldsa-native"
        )
    ),
    all(
        feature = "pmp-internal-uart-ml-dsa-fips204-scratch",
        feature = "pmp-internal-uart-ml-dsa-mldsa-native"
    )
))]
compile_error!("select exactly one C5 ML-DSA backend");

#[cfg(all(
    feature = "ble-ml-dsa-native",
    any(
        feature = "experimental-ml-dsa-fips204",
        feature = "pmp-internal-uart-ml-dsa-fips204",
        feature = "pmp-internal-uart-ml-dsa-fips204-scratch"
    )
))]
compile_error!("select exactly one C5 ML-DSA backend");

#[cfg(not(any(
    feature = "experimental-ml-dsa-fips204",
    feature = "ble-ml-dsa-native",
    feature = "pmp-internal-uart-ml-dsa-fips204",
    feature = "pmp-internal-uart-ml-dsa-fips204-scratch",
    feature = "pmp-internal-uart-ml-dsa-mldsa-native"
)))]
compile_error!("C5 ML-DSA product requires an explicit backend");

#[cfg(any(
    feature = "experimental-ml-dsa-fips204",
    feature = "pmp-internal-uart-ml-dsa-fips204"
))]
pub type SelectedMlDsaBackend = manekey::ctaphid::pqc_signature_fips204::Fips204MlDsa44;

#[cfg(any(
    feature = "pmp-internal-uart-ml-dsa-mldsa-native",
    feature = "ble-ml-dsa-native"
))]
pub type SelectedMlDsaBackend = manekey::ctaphid::pqc_signature_mldsa_native::MldsaNativeMlDsa44;

#[cfg(feature = "pmp-internal-uart-ml-dsa-fips204-scratch")]
pub type SelectedMlDsaBackend =
    manekey::ctaphid::pqc_signature_fips204_scratch::Fips204ScratchMlDsa44<'static>;

#[cfg(feature = "pmp-internal-uart-ml-dsa-fips204-scratch")]
static SIGN_SCRATCH: static_cell::StaticCell<manekey_fips204_scratch::ml_dsa_44::SignScratch> =
    static_cell::StaticCell::new();

/// Initialize once per boot; keep scratch private and exclude task/IRQ/DMA access.
/// Backend selection does not prove stack capacity.
pub fn init_backend() -> SelectedMlDsaBackend {
    #[cfg(any(
        feature = "experimental-ml-dsa-fips204",
        feature = "pmp-internal-uart-ml-dsa-fips204"
    ))]
    {
        manekey::ctaphid::pqc_signature_fips204::Fips204MlDsa44
    }
    #[cfg(any(
        feature = "pmp-internal-uart-ml-dsa-mldsa-native",
        feature = "ble-ml-dsa-native"
    ))]
    {
        manekey::ctaphid::pqc_signature_mldsa_native::MldsaNativeMlDsa44
    }
    #[cfg(feature = "pmp-internal-uart-ml-dsa-fips204-scratch")]
    {
        let scratch =
            manekey_fips204_scratch::ml_dsa_44::SignScratch::init_zeroed(SIGN_SCRATCH.uninit());
        SelectedMlDsaBackend::new(scratch)
    }
}
