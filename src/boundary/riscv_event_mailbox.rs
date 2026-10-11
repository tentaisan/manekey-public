use core::{
    cell::UnsafeCell,
    sync::atomic::{AtomicU32, Ordering},
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u32)]
pub enum RiscvUserEvent {
    NoResponse = 0,
    Response = 1,
    UserPresencePending = 2,
    Busy = 3,
    InvalidRequest = 4,
    Cancelled = 5,
    LinkClosed = 6,
    FrameError = 7,
}

impl RiscvUserEvent {
    pub const fn from_raw(value: u32) -> Option<Self> {
        match value {
            0 => Some(Self::NoResponse),
            1 => Some(Self::Response),
            2 => Some(Self::UserPresencePending),
            3 => Some(Self::Busy),
            4 => Some(Self::InvalidRequest),
            5 => Some(Self::Cancelled),
            6 => Some(Self::LinkClosed),
            7 => Some(Self::FrameError),
            _ => None,
        }
    }
}

#[repr(C)]
/// One synchronous M-to-U event; caller enforces temporal ownership, not atomics alone.
/// M begins input, U exclusively writes/publishes, then M reads only after U returns.
/// No concurrent producers, readers, IRQ/DMA access or retained mutable references.
pub struct RiscvUserEventMailbox<const RESPONSE_MAX: usize> {
    input: AtomicU32,
    event: AtomicU32,
    response_len: AtomicU32,
    response: UnsafeCell<[u8; RESPONSE_MAX]>,
}

unsafe impl<const RESPONSE_MAX: usize> Sync for RiscvUserEventMailbox<RESPONSE_MAX> {}

impl<const RESPONSE_MAX: usize> RiscvUserEventMailbox<RESPONSE_MAX> {
    pub const fn new() -> Self {
        Self {
            input: AtomicU32::new(0),
            event: AtomicU32::new(RiscvUserEvent::NoResponse as u32),
            response_len: AtomicU32::new(0),
            response: UnsafeCell::new([0; RESPONSE_MAX]),
        }
    }

    pub fn begin_input(&self, byte: u8) {
        self.response_len.store(0, Ordering::Relaxed);
        self.event
            .store(RiscvUserEvent::NoResponse as u32, Ordering::Relaxed);
        self.input.store(byte as u32, Ordering::Release);
    }

    pub fn input_byte(&self) -> u8 {
        self.input.load(Ordering::Acquire) as u8
    }

    /// # Safety
    /// Only U may hold this reference, exclusively, until publication; M must wait for event return.
    pub unsafe fn response_mut(&self) -> &mut [u8; RESPONSE_MAX] {
        unsafe { &mut *self.response.get() }
    }

    pub fn publish(&self, event: RiscvUserEvent, response_len: usize) {
        let (event, response_len) = if response_len <= RESPONSE_MAX {
            (event, response_len)
        } else {
            (RiscvUserEvent::FrameError, 0)
        };
        self.response_len
            .store(response_len as u32, Ordering::Release);
        self.event.store(event as u32, Ordering::Release);
    }

    pub fn take_response_len(&self) -> usize {
        let len = self.response_len.swap(0, Ordering::Acquire) as usize;
        len.min(RESPONSE_MAX)
    }

    /// # Safety
    /// U must have returned and stopped writing; no mutable response reference may remain live.
    pub unsafe fn response(&self) -> &[u8; RESPONSE_MAX] {
        unsafe { &*self.response.get() }
    }

    pub fn event(&self) -> Option<RiscvUserEvent> {
        RiscvUserEvent::from_raw(self.event.load(Ordering::Acquire))
    }
}

impl<const RESPONSE_MAX: usize> Default for RiscvUserEventMailbox<RESPONSE_MAX> {
    fn default() -> Self {
        Self::new()
    }
}
