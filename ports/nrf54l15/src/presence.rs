use embassy_nrf::{
    Peri,
    gpio::{Input, Pull},
};
use embassy_time::Instant;
use manekey::{
    presence::{
        DEFAULT_GPIO_PRESENCE_STABLE_MILLIS, TimedPresenceConfig, UserPresence, UserPresenceInput,
    },
    user_interface::{ButtonInput, TimedButtonPresence, UiClock},
};

pub const USER_KEY_CONFIG: TimedPresenceConfig = TimedPresenceConfig::low_active_button(
    "USER KEY (P0.00)",
    DEFAULT_GPIO_PRESENCE_STABLE_MILLIS,
    30_000,
);

struct UserKeyButton<'d> {
    input: Input<'d>,
}

impl ButtonInput for UserKeyButton<'_> {
    fn is_pressed(&mut self) -> bool {
        let pressed = self.input.is_low();

        pressed
    }
}

struct EmbassyClock;

impl UiClock for EmbassyClock {
    fn now(&mut self) -> u64 {
        Instant::now().as_millis()
    }
}

/// Exclusive USER KEY owner using the active Embassy clock and common timed button state.
pub struct UserKeyPresence<'d> {
    inner: TimedButtonPresence<UserKeyButton<'d>, EmbassyClock>,
}

impl<'d> UserKeyPresence<'d> {
    pub fn new(pin: Peri<'d, embassy_nrf::peripherals::P0_00>) -> Self {
        Self {
            inner: TimedButtonPresence::new(
                UserKeyButton {
                    input: Input::new(pin, Pull::Up),
                },
                EmbassyClock,
                USER_KEY_CONFIG,
            ),
        }
    }
}

impl UserPresence for UserKeyPresence<'_> {
    fn is_present(&mut self) -> bool {
        self.inner.is_present()
    }

    fn begin_wait(&mut self) {
        self.inner.begin_wait();
    }

    fn poll(&mut self) -> manekey::presence::PresenceStatus {
        self.inner.poll()
    }

    fn cancel(&mut self) {
        self.inner.cancel();
    }

    fn wait_for_presence(&mut self) -> bool {
        self.inner.wait_for_presence()
    }
}

impl UserPresenceInput for UserKeyPresence<'_> {
    fn input_info(&self) -> manekey::presence::PresenceInputInfo {
        self.inner.input_info()
    }
}
