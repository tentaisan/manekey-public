use core::sync::atomic::{AtomicU8, Ordering};

use crate::presence::{
    PresenceEvent, PresenceInputInfo, PresenceObserver, PresenceStatus, PresenceUiHint,
    TimedPresenceConfig, TimedPresenceState, UserPresence, UserPresenceInput,
};

pub trait ButtonInput {
    fn is_pressed(&mut self) -> bool;
}

/// Supplies monotonic ticks in the unit used by TimedPresenceConfig.
pub trait UiClock {
    fn now(&mut self) -> u64;
}

/// Button provider using a caller-configured clock and debounce interval.
pub struct TimedButtonPresence<B, C> {
    button: B,
    clock: C,
    state: TimedPresenceState,
    input_info: PresenceInputInfo,
}

impl<B, C> TimedButtonPresence<B, C> {
    pub const fn new(button: B, clock: C, config: TimedPresenceConfig) -> Self {
        Self {
            button,
            clock,
            state: config.state(),
            input_info: config.input_info,
        }
    }

    pub fn into_parts(self) -> (B, C) {
        (self.button, self.clock)
    }
}

impl<B: ButtonInput, C: UiClock> UserPresence for TimedButtonPresence<B, C> {
    fn is_present(&mut self) -> bool {
        self.button.is_pressed()
    }

    fn begin_wait(&mut self) {
        self.state.begin_wait(self.clock.now());
    }

    fn poll(&mut self) -> PresenceStatus {
        self.state.poll(self.clock.now(), self.button.is_pressed())
    }

    fn cancel(&mut self) {
        self.state.cancel();
    }

    fn wait_for_presence(&mut self) -> bool {
        self.state.is_confirmed() || self.button.is_pressed()
    }
}

impl<B: ButtonInput, C: UiClock> UserPresenceInput for TimedButtonPresence<B, C> {
    fn input_info(&self) -> PresenceInputInfo {
        self.input_info
    }
}

pub trait UiStatusOutput {
    fn set_ui_hint(&mut self, hint: PresenceUiHint);
}

pub struct TouchPromptLed {
    on: fn(),
    off: fn(),
}

impl TouchPromptLed {
    pub const fn new(on: fn(), off: fn()) -> Self {
        Self { on, off }
    }
}

impl UiStatusOutput for TouchPromptLed {
    fn set_ui_hint(&mut self, hint: PresenceUiHint) {
        if hint == PresenceUiHint::TouchRequired {
            (self.on)();
        } else {
            (self.off)();
        }
    }
}

pub struct AtomicUiStatus {
    value: AtomicU8,
}

impl AtomicUiStatus {
    pub const fn new() -> Self {
        Self {
            value: AtomicU8::new(PresenceUiHint::Idle as u8),
        }
    }

    pub fn set(&self, hint: PresenceUiHint) {
        self.value.store(hint as u8, Ordering::Release);
    }

    pub fn get(&self) -> PresenceUiHint {
        match self.value.load(Ordering::Acquire) {
            value if value == PresenceUiHint::TouchRequired as u8 => PresenceUiHint::TouchRequired,
            value if value == PresenceUiHint::TouchConfirmed as u8 => {
                PresenceUiHint::TouchConfirmed
            }
            value if value == PresenceUiHint::Attention as u8 => PresenceUiHint::Attention,
            _ => PresenceUiHint::Idle,
        }
    }
}

impl Default for AtomicUiStatus {
    fn default() -> Self {
        Self::new()
    }
}

impl UiStatusOutput for &AtomicUiStatus {
    fn set_ui_hint(&mut self, hint: PresenceUiHint) {
        self.set(hint);
    }
}

pub struct UiPresenceObserver<N, O> {
    next: N,
    output: O,
}

impl<N, O> UiPresenceObserver<N, O> {
    pub const fn new(next: N, output: O) -> Self {
        Self { next, output }
    }

    pub fn into_parts(self) -> (N, O) {
        (self.next, self.output)
    }
}

impl<N: PresenceObserver, O: UiStatusOutput> PresenceObserver for UiPresenceObserver<N, O> {
    fn on_presence_event(&mut self, event: PresenceEvent) {
        self.output.set_ui_hint(event.ui_hint());
        self.next.on_presence_event(event);
    }
}
