use esp_hal::gpio::{Level, Output};
use manekey::{presence::PresenceUiHint, user_interface::UiStatusOutput};

/// GPIO indicator for TouchRequired only; does not confirm presence.
pub struct EspGpioUiOutput {
    output: Output<'static>,
    active_high: bool,
}

impl EspGpioUiOutput {
    pub fn new(output: Output<'static>, active_high: bool) -> Self {
        Self {
            output,
            active_high,
        }
    }
}

impl UiStatusOutput for EspGpioUiOutput {
    fn set_ui_hint(&mut self, hint: PresenceUiHint) {
        let active = hint == PresenceUiHint::TouchRequired;
        let high = active == self.active_high;
        self.output
            .set_level(if high { Level::High } else { Level::Low });
    }
}
