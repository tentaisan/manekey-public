use manekey::ctaphid::pqc_signature_fips204_scratch::Fips204ScratchMlDsa44;

use manekey::ctaphid::pqc_signature_fips204_scratch::NoopScratchClearObserver;

use manekey_fips204_scratch::ml_dsa_44::SignScratch;
use static_cell::StaticCell;

static SIGN_SCRATCH: StaticCell<SignScratch> = StaticCell::new();

pub type ScratchBackend = Fips204ScratchMlDsa44<'static, NoopScratchClearObserver>;

/// Initialize private static scratch once; exclude concurrent/reentrant and IRQ/DMA access.
/// This experimental backend selection does not prove stack capacity.
pub fn init_backend() -> ScratchBackend {
    let scratch = SignScratch::init_zeroed(SIGN_SCRATCH.uninit());

    { Fips204ScratchMlDsa44::new(scratch) }
}
