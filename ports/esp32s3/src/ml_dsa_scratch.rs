use manekey::ctaphid::pqc_signature_fips204_scratch::Fips204ScratchMlDsa44;
use manekey_fips204_scratch::ml_dsa_44::SignScratch;
use static_cell::StaticCell;

static SCRATCH: StaticCell<SignScratch> = StaticCell::new();

/// Initialize once per boot; keep scratch private and exclude concurrent access.
/// Linking does not prove either core's stack capacity.
pub fn init_backend() -> Fips204ScratchMlDsa44<'static> {
    Fips204ScratchMlDsa44::new(SignScratch::init_zeroed(SCRATCH.uninit()))
}
