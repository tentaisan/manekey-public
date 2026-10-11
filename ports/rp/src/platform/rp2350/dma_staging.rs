use core::cell::UnsafeCell;
use core::sync::atomic::{AtomicU8, Ordering};

const FREE: u8 = 0;
const LEASED: u8 = 1;
const POISONED: u8 = 2;

/// Static exclusive buffers; forgotten leases remain reserved and abandoned leases poison reuse.
pub struct DmaStaging<const WORDS: usize> {
    state: AtomicU8,
    buffers: UnsafeCell<([u32; WORDS], [u32; WORDS])>,
}

unsafe impl<const WORDS: usize> Sync for DmaStaging<WORDS> {}

impl<const WORDS: usize> DmaStaging<WORDS> {
    pub const fn new() -> Self {
        Self {
            state: AtomicU8::new(FREE),
            buffers: UnsafeCell::new(([0; WORDS], [0; WORDS])),
        }
    }

    #[inline(always)]
    pub fn acquire(&'static self) -> Option<DmaStagingLease<WORDS>> {
        self.state
            .compare_exchange(FREE, LEASED, Ordering::Acquire, Ordering::Relaxed)
            .ok()?;
        Some(DmaStagingLease { staging: self })
    }
}

pub struct DmaStagingLease<const WORDS: usize> {
    staging: &'static DmaStaging<WORDS>,
}

impl<const WORDS: usize> DmaStagingLease<WORDS> {
    #[inline(always)]
    /// # Safety
    /// Exclude every DMA access while returned references are live.
    pub unsafe fn buffers(&mut self) -> (&mut [u32; WORDS], &mut [u32; WORDS]) {
        let buffers = unsafe { &mut *self.staging.buffers.get() };
        (&mut buffers.0, &mut buffers.1)
    }

    #[inline(always)]
    /// # Safety
    /// Confirm all DMA accesses stopped and order their memory writes before permitting reuse.
    pub unsafe fn release_after_stop(self) {
        self.staging.state.store(FREE, Ordering::Release);
        core::mem::forget(self);
    }
}

impl<const WORDS: usize> Drop for DmaStagingLease<WORDS> {
    #[inline(always)]
    fn drop(&mut self) {
        self.staging.state.store(POISONED, Ordering::Release);
    }
}
