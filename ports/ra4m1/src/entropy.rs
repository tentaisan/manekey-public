use core::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use manekey::ctaphid::entropy::{EntropyError, EntropySource};
use zeroize::Zeroize;

static DEADLINE: AtomicU32 = AtomicU32::new(0);
static BUSY: AtomicBool = AtomicBool::new(false);
static READY: AtomicBool = AtomicBool::new(false);

#[cfg(feature = "sce5-aes")]
pub fn sce_ready() -> bool {
    READY.load(Ordering::Acquire)
}



pub fn with_sce<T>(call: impl FnOnce() -> T) -> Option<T> {
    if cortex_m::register::primask::read().is_inactive()
        || BUSY
            .compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
            .is_err()
    {
        return None;
    }
    DEADLINE.store(8_000, Ordering::Relaxed);
    let result = call();
    DEADLINE.store(0, Ordering::Relaxed);
    BUSY.store(false, Ordering::Release);
    Some(result)
}
#[cfg(feature = "mpu-internal")]
pub static MILLISECONDS: AtomicU32 = AtomicU32::new(0);

unsafe extern "C" {
    fn manekey_sce5_init() -> u32;
    fn manekey_sce5_read(output: *mut u32) -> u32;
}



pub fn start_watchdog() {
    unsafe {
        let mut core = cortex_m::Peripherals::steal();
        core.SCB
            .set_priority(cortex_m::peripheral::scb::SystemHandler::SysTick, 0);
        core.SCB
            .set_priority(cortex_m::peripheral::scb::SystemHandler::SVCall, 128);
        core.SYST
            .set_clock_source(cortex_m::peripheral::syst::SystClkSource::Core);
        core.SYST.set_reload(48_000 - 1);
        core.SYST.clear_current();
        core.SYST.enable_interrupt();
        core.SYST.enable_counter();
    }
}


#[cortex_m_rt::exception]
fn SysTick() {
    systick_update();
}






















fn systick_update() {
    #[cfg(feature = "mpu-internal")]
    MILLISECONDS.fetch_add(1, Ordering::Relaxed);
    let remaining = DEADLINE.load(Ordering::Relaxed);
    if remaining != 0 {
        DEADLINE.store(remaining - 1, Ordering::Relaxed);
        if remaining == 1 {
            cortex_m::peripheral::SCB::sys_reset();
        }
    }
}

pub struct SceEntropy {
    previous: [u32; 4],
    seen: bool,
    failed: bool,
}

impl SceEntropy {
    pub fn new() -> Result<Self, EntropyError> {
        ra_hal::pac::MSTP.mstpcrc().modify(|r| r.set_mstpc31(false));
        let status =
            with_sce(|| unsafe { manekey_sce5_init() }).ok_or(EntropyError::Unavailable)?;
        if status != 0 {
            return Err(EntropyError::Unavailable);
        }
        READY.store(true, Ordering::Release);
        Ok(Self {
            previous: [0; 4],
            seen: false,
            failed: false,
        })
    }
}

impl EntropySource for SceEntropy {
    fn fill_entropy(&mut self, output: &mut [u8]) -> Result<(), EntropyError> {
        if self.failed {
            output.zeroize();
            return Err(EntropyError::Unavailable);
        }
        for chunk in output.chunks_mut(16) {
            let mut words = [0u32; 4];
            let status =
                with_sce(|| unsafe { manekey_sce5_read(words.as_mut_ptr()) }).unwrap_or(u32::MAX);
            let healthy =
                words != [0; 4] && words != [u32::MAX; 4] && (!self.seen || words != self.previous);
            if status != 0 || !healthy {
                self.failed = true;
                words.zeroize();
                output.zeroize();
                return Err(if status == 0 {
                    EntropyError::HealthCheckFailed
                } else {
                    EntropyError::Unavailable
                });
            }
            self.previous = words;
            self.seen = true;
            let mut bytes = [0; 16];
            for (dst, word) in bytes.chunks_exact_mut(4).zip(words) {
                dst.copy_from_slice(&word.to_le_bytes());
            }
            chunk.copy_from_slice(&bytes[..chunk.len()]);
            bytes.zeroize();
            words.zeroize();
        }
        Ok(())
    }
}
