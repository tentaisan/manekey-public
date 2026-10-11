use core::cell::UnsafeCell;
use core::future::Future;
use core::mem::MaybeUninit;
use core::pin::Pin;
use core::sync::atomic::{AtomicBool, AtomicU8, AtomicU32, Ordering};
use core::task::{Context, Poll, RawWaker, RawWakerVTable, Waker};

/// Single-future U-mode executor; serialize polling and stop polling after completion.
/// Keep executor and waker code/data accessible in the executing privilege mode.
pub struct PmpUserExecutor {
    ready: AtomicBool,
}

/// Initialize once; returned future remains pinned in static storage for its entire lifetime.
pub struct PmpUserTaskStorage<F> {
    initialized: AtomicBool,
    future: UnsafeCell<MaybeUninit<F>>,
}

const HANDOFF_EMPTY: u8 = 0;
const HANDOFF_WRITING: u8 = 1;
const HANDOFF_READY: u8 = 2;
const HANDOFF_TAKEN: u8 = 3;

/// One-shot ownership handoff; publish only payload-owned values valid in the receiving domain.
/// Atomic ownership transfer does not itself configure memory protection.
pub struct PmpUserHandoff<T> {
    state: AtomicU8,
    value: UnsafeCell<MaybeUninit<T>>,
}

unsafe impl<T: Send> Sync for PmpUserHandoff<T> {}

impl<T> PmpUserHandoff<T> {
    pub const fn new() -> Self {
        Self {
            state: AtomicU8::new(HANDOFF_EMPTY),
            value: UnsafeCell::new(MaybeUninit::uninit()),
        }
    }

    pub fn publish(&'static self, value: T) -> bool {
        if self
            .state
            .compare_exchange(
                HANDOFF_EMPTY,
                HANDOFF_WRITING,
                Ordering::Acquire,
                Ordering::Relaxed,
            )
            .is_err()
        {
            return false;
        }
        unsafe { (*self.value.get()).write(value) };
        self.state.store(HANDOFF_READY, Ordering::Release);
        true
    }

    #[unsafe(link_section = ".text.pmp_user_executor")]
    pub fn take(&'static self) -> Option<&'static mut T> {
        if self
            .state
            .compare_exchange(
                HANDOFF_READY,
                HANDOFF_TAKEN,
                Ordering::AcqRel,
                Ordering::Acquire,
            )
            .is_err()
        {
            return None;
        }
        Some(unsafe { (&mut *self.value.get()).assume_init_mut() })
    }
}

unsafe impl<F: Send> Sync for PmpUserTaskStorage<F> {}

impl<F> PmpUserTaskStorage<F> {
    pub const fn new() -> Self {
        Self {
            initialized: AtomicBool::new(false),
            future: UnsafeCell::new(MaybeUninit::uninit()),
        }
    }

    #[unsafe(link_section = ".text.pmp_user_executor")]
    pub fn init(&'static self, future: F) -> Option<Pin<&'static mut F>> {
        if self
            .initialized
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            return None;
        }

        let storage = unsafe { &mut *self.future.get() };
        Some(unsafe { Pin::new_unchecked(storage.write(future)) })
    }
}

/// Single event observer; generation changes coalesce and do not identify every individual event.
pub struct PmpUserEventPump {
    observed_generation: AtomicU32,
}

impl PmpUserEventPump {
    pub const fn new() -> Self {
        Self {
            observed_generation: AtomicU32::new(0),
        }
    }

    #[unsafe(link_section = ".text.pmp_user_executor")]
    pub fn reset(&self, generation: u32) {
        self.observed_generation
            .store(generation, Ordering::Release);
    }

    #[unsafe(link_section = ".text.pmp_user_executor")]
    pub fn dispatch_if_changed(&self, generation: u32, executor: &'static PmpUserExecutor) -> bool {
        let observed = self.observed_generation.load(Ordering::Acquire);
        if generation == observed {
            return false;
        }

        self.observed_generation
            .store(generation, Ordering::Release);

        executor.notify();
        true
    }
}

impl PmpUserExecutor {
    pub const fn new() -> Self {
        Self {
            ready: AtomicBool::new(false),
        }
    }

    #[unsafe(link_section = ".text.pmp_user_executor")]
    pub fn reset(&'static self) {
        self.ready.store(true, Ordering::Release);
    }

    #[unsafe(link_section = ".text.pmp_user_executor")]
    pub fn poll<F: Future>(&'static self, mut future: Pin<&mut F>) -> Option<Poll<F::Output>> {
        if !self.ready.swap(false, Ordering::AcqRel) {
            return None;
        }

        let waker = self.waker();
        let mut context = Context::from_waker(&waker);
        Some(future.as_mut().poll(&mut context))
    }

    #[unsafe(link_section = ".text.pmp_user_executor")]
    pub fn waker(&'static self) -> Waker {
        let raw = RawWaker::new(self as *const Self as *const (), &PMP_USER_WAKER_VTABLE);
        unsafe { Waker::from_raw(raw) }
    }

    #[unsafe(link_section = ".text.pmp_user_executor")]
    pub fn notify(&'static self) {
        self.wake();
    }

    #[unsafe(link_section = ".text.pmp_user_executor")]
    fn wake(&self) {
        self.ready.store(true, Ordering::Release);
    }
}

#[used]
#[unsafe(link_section = ".rodata.pmp_user_executor")]
static PMP_USER_WAKER_VTABLE: RawWakerVTable = RawWakerVTable::new(
    clone_pmp_user_waker,
    wake_pmp_user_waker,
    wake_pmp_user_waker_by_ref,
    drop_pmp_user_waker,
);

#[unsafe(link_section = ".text.pmp_user_executor")]
unsafe fn clone_pmp_user_waker(data: *const ()) -> RawWaker {
    RawWaker::new(data, &PMP_USER_WAKER_VTABLE)
}

#[unsafe(link_section = ".text.pmp_user_executor")]
unsafe fn wake_pmp_user_waker(data: *const ()) {
    executor_from_raw(data).wake();
}

#[unsafe(link_section = ".text.pmp_user_executor")]
unsafe fn wake_pmp_user_waker_by_ref(data: *const ()) {
    executor_from_raw(data).wake();
}

#[unsafe(link_section = ".text.pmp_user_executor")]
unsafe fn drop_pmp_user_waker(_: *const ()) {}

#[unsafe(link_section = ".text.pmp_user_executor")]
fn executor_from_raw(data: *const ()) -> &'static PmpUserExecutor {
    unsafe { &*data.cast() }
}
