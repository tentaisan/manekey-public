use esp_hal::gpio::{Input, InputConfig, Pull};
use esp_hal::time::Instant;
use esp_println::{print, println};
use manekey::{
    presence::{
        DEFAULT_GPIO_PRESENCE_STABLE_MILLIS, DEFAULT_GPIO_PRESENCE_TIMEOUT_SECS,
        PresenceActiveLevel, PresenceEvent, PresenceInputInfo, PresenceInputKind, PresenceObserver,
        PresenceStatus, TimedPresenceConfig, UserPresence, UserPresenceInput,
        write_presence_input_info,
    },
    user_interface::{ButtonInput, TimedButtonPresence, UiClock},
};

const ESP_GPIO2_PRESENCE_CONFIG: TimedPresenceConfig = TimedPresenceConfig::low_active_button(
    "gpio2",
    DEFAULT_GPIO_PRESENCE_STABLE_MILLIS,
    DEFAULT_GPIO_PRESENCE_TIMEOUT_SECS * 1_000,
);

const ESP_GPIO0_PRESENCE_CONFIG: TimedPresenceConfig =
    TimedPresenceConfig::low_active_button("boot", DEFAULT_GPIO_PRESENCE_STABLE_MILLIS, 20_000);
const ESP_GPIO9_PRESENCE_CONFIG: TimedPresenceConfig =
    TimedPresenceConfig::low_active_button("boot", DEFAULT_GPIO_PRESENCE_STABLE_MILLIS, 20_000);

/// GPIO level presence with millisecond debounce; held input may confirm without a new press edge.
pub struct EspGpioUserPresence<'d> {
    presence: TimedButtonPresence<EspGpioButton<'d>, EspHalClock>,
    config: TimedPresenceConfig,
    reported_confirmed: bool,
}

struct EspGpioButton<'d> {
    input: Input<'d>,
    active_low: bool,
}

impl ButtonInput for EspGpioButton<'_> {
    fn is_pressed(&mut self) -> bool {
        if self.active_low {
            self.input.is_low()
        } else {
            self.input.is_high()
        }
    }
}

struct EspHalClock;

impl UiClock for EspHalClock {
    fn now(&mut self) -> u64 {
        now_ms()
    }
}

fn now_ms() -> u64 {
    Instant::now().duration_since_epoch().as_millis()
}

impl<'d> EspGpioUserPresence<'d> {
    pub fn from_gpio0(gpio0: esp_hal::peripherals::GPIO0<'d>) -> Self {
        let button = Input::new(gpio0, InputConfig::default().with_pull(Pull::Up));
        Self::from_input(button, ESP_GPIO0_PRESENCE_CONFIG, true, "GPIO0 BOOT")
    }

    pub fn from_gpio2(gpio2: esp_hal::peripherals::GPIO2<'d>) -> Self {
        let button = Input::new(gpio2, InputConfig::default().with_pull(Pull::Up));
        Self::from_input(button, ESP_GPIO2_PRESENCE_CONFIG, true, "GPIO2")
    }

    /// Active-low GPIO9 BOOT input after normal boot; board must preserve reset-time strapping behavior.
    pub fn from_gpio9(gpio9: esp_hal::peripherals::GPIO9<'d>) -> Self {
        let button = Input::new(gpio9, InputConfig::default().with_pull(Pull::Up));
        Self::from_input(button, ESP_GPIO9_PRESENCE_CONFIG, true, "GPIO9 BOOT")
    }

    pub fn from_input(
        button: Input<'d>,
        config: TimedPresenceConfig,
        active_low: bool,
        description: &'static str,
    ) -> Self {
        let active = if active_low { "low" } else { "high" };
        println!(
            "{} initial level: {}",
            description,
            if button.is_low() { "low" } else { "high" }
        );
        let input_info = PresenceInputInfo {
            kind: PresenceInputKind::PhysicalButton,
            active_level: if active_low {
                PresenceActiveLevel::ActiveLow
            } else {
                PresenceActiveLevel::ActiveHigh
            },
            label: config.input_info.label,
            has_debounce: true,
            has_timeout: true,
        };
        let config = TimedPresenceConfig {
            input_info,
            ..config
        };
        println!("{} active level: {}", description, active);
        write_presence_input_info(config.input_info, esp_log_fragment);
        Self {
            presence: TimedButtonPresence::new(
                EspGpioButton {
                    input: button,
                    active_low,
                },
                EspHalClock,
                config,
            ),
            config,
            reported_confirmed: false,
        }
    }
}

fn esp_log_fragment(fragment: &str) {
    print!("{fragment}");
}

impl UserPresence for EspGpioUserPresence<'_> {
    fn is_present(&mut self) -> bool {
        self.presence.is_present()
    }

    fn begin_wait(&mut self) {
        self.reported_confirmed = false;
        self.presence.begin_wait();
    }

    fn poll(&mut self) -> PresenceStatus {
        let status = self.presence.poll();
        if status == PresenceStatus::Confirmed && !self.reported_confirmed {
            if !cfg!(all(feature = "internal-uart", feature = "log-uart")) {
                println!("{} user presence confirmed", self.config.input_info.label);
            }
            self.reported_confirmed = true;
        }
        status
    }

    fn cancel(&mut self) {
        self.presence.cancel();
    }

    fn wait_for_presence(&mut self) -> bool {
        self.presence.wait_for_presence()
    }
}

impl UserPresenceInput for EspGpioUserPresence<'_> {
    fn input_info(&self) -> PresenceInputInfo {
        self.config.input_info
    }
}

#[derive(Clone, Copy, Debug, Default)]
pub struct EspTextPresenceObserver;

impl PresenceObserver for EspTextPresenceObserver {
    fn on_presence_event(&mut self, event: PresenceEvent) {
        if !cfg!(all(feature = "internal-uart", feature = "log-uart")) {
            println!(
                "up {} reason={} hint={} action={}",
                event.label(),
                event.reason().label(),
                event.ui_hint().label(),
                event.user_action().label()
            );
        }
    }
}
