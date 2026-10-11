
use manekey::{
    presence::{
        PresenceActiveLevel, PresenceInputInfo, PresenceInputKind, PresenceUiHint,
        TimedPresenceConfig,
    },
    user_interface::{AtomicUiStatus, ButtonInput, TimedButtonPresence, UiClock},
};
use ra_hal::gpio::{Basic, Input, Output, WithPullUp};

pub static STATUS: AtomicUiStatus = AtomicUiStatus::new();

pub struct BootButton(pub Input<'static, WithPullUp>);
impl ButtonInput for BootButton {
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

pub type PhysicalPresence = TimedButtonPresence<BootButton, Clock>;

pub fn physical_presence(input: Input<'static, WithPullUp>) -> PhysicalPresence {
    TimedButtonPresence::new(
        BootButton(input),
        Clock,
        TimedPresenceConfig {
            stable_ticks_required: 30,
            timeout_ticks: 20_000,
            input_info: PresenceInputInfo {
                kind: PresenceInputKind::PhysicalButton,
                active_level: PresenceActiveLevel::ActiveLow,
                label: crate::boot::board::UP_LABEL,
                has_debounce: true,
                has_timeout: true,
            },
        },
    )
}

pub fn update_led(led: &mut Output<'static, Basic>) {
    let on = STATUS.get() == PresenceUiHint::TouchRequired;
    if on == crate::boot::board::LED_ACTIVE_LOW {
        led.set_low();
    } else {
        led.set_high();
    }
}

#[embassy_executor::task]
pub async fn led_task(mut led: Output<'static, Basic>) {
    loop {
        update_led(&mut led);
        embassy_time::Timer::after_millis(5).await;
    }
}
