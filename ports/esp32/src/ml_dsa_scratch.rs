use core::{
    mem::MaybeUninit,
    sync::atomic::{AtomicBool, Ordering},
};
use manekey::ctaphid::pqc_signature_fips204_scratch::Fips204ScratchMlDsa44;
use manekey_fips204_scratch::ml_dsa_44::SignScratch;

static TAKEN: AtomicBool = AtomicBool::new(false);
#[esp_hal::ram(reclaimed)]
static mut SCRATCH: MaybeUninit<SignScratch> = MaybeUninit::uninit();

/// Initialize once per boot; caller reserves reclaimed memory privately and excludes task/IRQ access.
pub fn init_backend() -> Fips204ScratchMlDsa44<'static> {
    assert!(
        !TAKEN.swap(true, Ordering::AcqRel),
        "scratch backend already initialized"
    );

    let scratch = unsafe { &mut *(&raw mut SCRATCH) };
    Fips204ScratchMlDsa44::new(SignScratch::init_zeroed(scratch))
}
