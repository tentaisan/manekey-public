use embassy_time::{Duration, Timer};
use esp_hal::{
    gpio::Level,
    peripherals::{GPIO27, RMT},
    rmt::{Rmt, TxChannelConfig, TxChannelCreator},
    time::Rate,
};
use manekey::{presence::PresenceUiHint, user_interface::AtomicUiStatus};

pub static UI_STATUS: AtomicUiStatus = AtomicUiStatus::new();

use crate::status_pixel::pixel_codes;

/// Status indication, not UP confirmation; RMT initialization or transmission failure panics.
pub async fn run_status_pixel(rmt: RMT<'static>, pin: GPIO27<'static>) -> ! {
    let rmt = Rmt::new(rmt, Rate::from_mhz(80))
        .expect("RMT clock")
        .into_async();
    let mut channel = rmt
        .channel0
        .configure_tx(
            &TxChannelConfig::default()
                .with_clk_divider(4)
                .with_idle_output(true)
                .with_idle_output_level(Level::Low),
        )
        .expect("RMT TX")
        .with_pin(pin);
    let mut previous = None;

    let mut startup_refreshes = 10u8;
    loop {
        let color = if UI_STATUS.get() == PresenceUiHint::TouchRequired {
            0x202020
        } else {
            0
        };
        if previous != Some(color) || startup_refreshes != 0 {
            channel
                .transmit(&pixel_codes(color))
                .await
                .expect("status pixel transmit");
            previous = Some(color);
            startup_refreshes = startup_refreshes.saturating_sub(1);
        }
        Timer::after(Duration::from_millis(20)).await;
    }
}
