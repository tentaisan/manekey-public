use embassy_time::{Duration, Timer};
use esp_hal::{
    gpio::Level,
    peripherals::{GPIO48, RMT},
    rmt::{PulseCode, Rmt, TxChannelConfig, TxChannelCreator},
    time::Rate,
};
use esp_println::println;
use manekey::{presence::PresenceUiHint, user_interface::AtomicUiStatus};

pub static UI_STATUS: AtomicUiStatus = AtomicUiStatus::new();

fn pixel_codes(grb: u32) -> [PulseCode; 26] {
    let mut codes = [PulseCode::end_marker(); 26];
    for (index, code) in codes[..24].iter_mut().enumerate() {
        let one = grb & (1 << (23 - index)) != 0;
        *code = if one {
            PulseCode::new(Level::High, 17, Level::Low, 9)
        } else {
            PulseCode::new(Level::High, 8, Level::Low, 16)
        };
    }
    codes[24] = PulseCode::new(Level::Low, 6000, Level::Low, 1);
    codes
}

fn status_color(hint: PresenceUiHint) -> u32 {
    match hint {
        PresenceUiHint::TouchRequired => 0x202020,
        _ => 0,
    }
}

/// Status indicator only, not UP confirmation; RMT initialization/transmit failure panics.
pub async fn run_status_pixel(rmt: RMT<'static>, gpio48: GPIO48<'static>) -> ! {
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
        .with_pin(gpio48);
    let mut previous = None;
    loop {
        let color = status_color(UI_STATUS.get());
        if previous != Some(color) {
            channel
                .transmit(&pixel_codes(color))
                .await
                .expect("status pixel transmit");
            println!("board-ui RGB sent color={color:#08x}");
            previous = Some(color);
        }
        Timer::after(Duration::from_millis(20)).await;
    }
}
