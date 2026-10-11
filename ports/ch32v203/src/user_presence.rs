#[cfg(not(feature = "up-gpio-pa0"))]
use manekey::presence::AlwaysPresent;
#[cfg(feature = "up-gpio-pa0")]
use manekey::presence::{
    PresenceInputInfo, PresenceStatus, TimedPresenceConfig, TimedPresenceState, UserPresence,
    UserPresenceInput,
};

#[cfg(feature = "up-gpio-pa0")]
const PA0_UP_STABLE_MS: u64 = 30;
#[cfg(feature = "up-gpio-pa0")]
const PA0_UP_TIMEOUT_MS: u64 = 20_000;
#[cfg(feature = "up-gpio-pa0")]
const PA0_PRESENCE_CONFIG: TimedPresenceConfig =
    TimedPresenceConfig::low_active_button("pa0", PA0_UP_STABLE_MS, PA0_UP_TIMEOUT_MS);

#[cfg(feature = "up-gpio-pa0")]
/// Active-low PA0 with millisecond debounce/timeout; caller configures and exclusively owns the GPIO input.
/// Legacy direct presence checks remain level-based.
pub struct Pa0UserPresence {
    state: TimedPresenceState,
}

#[cfg(feature = "up-gpio-pa0")]
impl Pa0UserPresence {
    pub const fn new() -> Self {
        Self {
            state: PA0_PRESENCE_CONFIG.state(),
        }
    }

    fn pin_active() -> bool {
        !ch32_hal::pac::GPIOA.indr().read().idr(0)
    }
}

#[cfg(feature = "up-gpio-pa0")]
impl UserPresence for Pa0UserPresence {
    fn is_present(&mut self) -> bool {
        Self::pin_active()
    }

    fn begin_wait(&mut self) {
        self.state
            .begin_wait(embassy_time::Instant::now().as_millis());
    }

    fn poll(&mut self) -> PresenceStatus {
        self.state
            .poll(embassy_time::Instant::now().as_millis(), Self::pin_active())
    }

    fn cancel(&mut self) {
        self.state.cancel();
    }

    fn wait_for_presence(&mut self) -> bool {
        self.state.is_confirmed() || Self::pin_active()
    }
}

#[cfg(feature = "up-gpio-pa0")]
impl UserPresenceInput for Pa0UserPresence {
    fn input_info(&self) -> PresenceInputInfo {
        PA0_PRESENCE_CONFIG.input_info
    }
}

#[cfg(feature = "up-gpio-pa0")]
pub type SelectedUserPresence = Pa0UserPresence;
#[cfg(not(feature = "up-gpio-pa0"))]
pub type SelectedUserPresence = AlwaysPresent;

#[cfg(feature = "up-gpio-pa0")]
pub const fn selected_user_presence() -> SelectedUserPresence {
    Pa0UserPresence::new()
}

#[cfg(not(feature = "up-gpio-pa0"))]
pub const fn selected_user_presence() -> SelectedUserPresence {
    AlwaysPresent
}
