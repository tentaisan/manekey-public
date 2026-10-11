use crate::ui::EspGpioUiOutput;
use esp_hal::{
    gpio::{Input, InputConfig, Level, Output, Pull},
    peripherals::{GPIO0, GPIO2},
};
use manekey::presence::{DEFAULT_GPIO_PRESENCE_STABLE_MILLIS, TimedPresenceConfig};

use crate::presence::EspGpioUserPresence;

pub fn presence_button(gpio0: GPIO0<'static>) -> EspGpioUserPresence<'static> {
    presence_button_with_timeout(gpio0, 20_000)
}

/// Active-low GPIO0 level input after boot; timeout is milliseconds and reset-time strapping remains board-owned.
pub fn presence_button_with_timeout(
    gpio0: GPIO0<'static>,
    timeout_ms: u64,
) -> EspGpioUserPresence<'static> {
    let input = Input::new(gpio0, InputConfig::default().with_pull(Pull::Up));
    EspGpioUserPresence::from_input(
        input,
        TimedPresenceConfig::low_active_button(
            "boot",
            DEFAULT_GPIO_PRESENCE_STABLE_MILLIS,
            timeout_ms,
        ),
        true,
        "GPIO0 BOOT",
    )
}

pub fn presence_led(gpio2: GPIO2<'static>) -> EspGpioUiOutput {
    EspGpioUiOutput::new(Output::new(gpio2, Level::Low, Default::default()), true)
}
