use embassy_stm32::gpio::{Input, Output};
use manekey::{
    presence::{
        PresenceActiveLevel, PresenceInputInfo, PresenceInputKind, PresenceUiHint,
        TimedPresenceConfig,
    },
    user_interface::{AtomicUiStatus, ButtonInput, TimedButtonPresence, UiClock},
};
pub static STATUS: AtomicUiStatus = AtomicUiStatus::new();
pub struct UserButton(pub Input<'static>);
impl ButtonInput for UserButton {
    fn is_pressed(&mut self) -> bool {
        self.0.is_low()
    }
}
pub struct Clock;
impl UiClock for Clock {
    fn now(&mut self) -> u64 {
        embassy_time::Instant::now().as_millis()
    }
}
pub type PhysicalPresence = TimedButtonPresence<UserButton, Clock>;
/// Active-low button input; debounce and timeout use milliseconds.
pub fn physical_presence(input: Input<'static>) -> PhysicalPresence {
    TimedButtonPresence::new(
        UserButton(input),
        Clock,
        TimedPresenceConfig {
            stable_ticks_required: 30,
            timeout_ticks: 20_000,
            input_info: PresenceInputInfo {
                kind: PresenceInputKind::PhysicalButton,
                active_level: PresenceActiveLevel::ActiveLow,
                label: "NUCLEO F411 USER PC13",
                has_debounce: true,
                has_timeout: true,
            },
        },
    )
}
#[embassy_executor::task]
/// Status indication only, not UP confirmation.
pub async fn led_task(mut led: Output<'static>) {
    loop {
        if STATUS.get() == PresenceUiHint::TouchRequired {
            led.set_high();
        } else {
            led.set_low();
        }
        embassy_time::Timer::after_millis(5).await;
    }
}
