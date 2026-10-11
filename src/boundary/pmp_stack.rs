pub const MACHINE_TRAP_STACK_GUARD_PATTERN: u32 = 0x504d_5754;

#[derive(Clone, Copy)]
/// View over a dedicated descending trap stack; guards do not enforce memory isolation.
pub struct MachineTrapStack {
    start: *mut u32,
    bytes: usize,
    guard_words: usize,
}

impl MachineTrapStack {
    /// # Safety
    /// Provide aligned writable words, a non-overflowing byte range divisible by four,
    /// sufficient guard space, and exclusive ownership for this view's lifetime.
    pub const unsafe fn new(start: *mut u32, bytes: usize, guard_words: usize) -> Self {
        Self {
            start,
            bytes,
            guard_words,
        }
    }

    pub const fn capacity(&self) -> usize {
        self.bytes
            .saturating_sub(self.guard_words * core::mem::size_of::<u32>())
    }

    /// # Safety
    /// The trap path must not use the stack concurrently.
    pub unsafe fn initialize_guard(&self) {
        for index in 0..self.guard_words {
            unsafe {
                core::ptr::write_volatile(self.start.add(index), MACHINE_TRAP_STACK_GUARD_PATTERN)
            };
        }
    }

    pub fn guard_ok(&self) -> bool {
        (0..self.guard_words).all(|index| unsafe {
            core::ptr::read_volatile(self.start.add(index)) == MACHINE_TRAP_STACK_GUARD_PATTERN
        })
    }
}
