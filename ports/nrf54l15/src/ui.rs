use embassy_executor::task;
use embassy_nrf::{
    Peri,
    gpio::{Level, Output, OutputDrive},
    peripherals::P2_00,
};
use embassy_time::Timer;
use manekey::{presence::PresenceUiHint, user_interface::AtomicUiStatus};

pub static USER_LED_STATUS: AtomicUiStatus = AtomicUiStatus::new();

pub const USER_LED_ACTIVE_HIGH: bool = false;

#[task]
/// Single GPIO owner reflecting shared UI hints; LED state is not authorization evidence.
pub async fn user_led_task(pin: Peri<'static, P2_00>) -> ! {
    let mut led = Output::new(pin, Level::Low, OutputDrive::Standard);
    loop {
        let hint = USER_LED_STATUS.get();

        let on = hint == PresenceUiHint::TouchRequired;
        let level = match (on, USER_LED_ACTIVE_HIGH) {
            (true, true) | (false, false) => Level::High,
            (true, false) | (false, true) => Level::Low,
        };
        led.set_level(level);
        Timer::after_millis(10).await;
    }
}
