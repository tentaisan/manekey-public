use esp_hal::{gpio::Level, rmt::PulseCode};

pub(crate) fn pixel_codes(grb: u32) -> [PulseCode; 26] {
    let mut codes = [PulseCode::end_marker(); 26];
    for (index, code) in codes[..24].iter_mut().enumerate() {
        *code = if grb & (1 << (23 - index)) != 0 {
            PulseCode::new(Level::High, 17, Level::Low, 9)
        } else {
            PulseCode::new(Level::High, 8, Level::Low, 16)
        };
    }
    codes[24] = PulseCode::new(Level::Low, 6000, Level::Low, 1);
    codes
}

#[cfg(feature = "pmp-internal-uart-fido")]
mod blocking {
    use esp_hal::{
        Blocking,
        delay::Delay,
        gpio::Level,
        peripherals::{GPIO27, RMT},
        rmt::{Channel, Rmt, Tx, TxChannelConfig, TxChannelCreator},
        time::{Duration, Instant, Rate},
    };
    use manekey::{presence::PresenceUiHint, user_interface::UiStatusOutput};

    /// Status indication only; RMT ownership, initialization and transfer failures panic.
    pub struct BlockingStatusPixel {
        channel: Option<Channel<'static, Blocking, Tx>>,
    }

    impl BlockingStatusPixel {
        pub fn new(rmt: RMT<'static>, pin: GPIO27<'static>) -> Self {
            let rmt = Rmt::new(rmt, Rate::from_mhz(80)).expect("RMT clock");
            let channel = rmt
                .channel0
                .configure_tx(
                    &TxChannelConfig::default()
                        .with_clk_divider(4)
                        .with_idle_output(true)
                        .with_idle_output_level(Level::Low),
                )
                .expect("RMT TX")
                .with_pin(pin);
            let mut output = Self {
                channel: Some(channel),
            };

            for _ in 0..10 {
                output.send(0);
                Delay::new().delay_millis(20);
            }
            output
        }

        fn send(&mut self, color: u32) {
            let codes = super::pixel_codes(color);
            let channel = self.channel.take().expect("status pixel channel owned");
            let mut transaction = match channel.transmit(&codes) {
                Ok(transaction) => transaction,
                Err((error, _)) => panic!("status pixel start: {error:?}"),
            };
            let deadline = Instant::now() + Duration::from_millis(20);
            while !transaction.poll() {
                assert!(Instant::now() < deadline, "status pixel timeout");
            }
            self.channel = Some(match transaction.wait() {
                Ok(channel) => channel,
                Err((error, _)) => panic!("status pixel transfer: {error:?}"),
            });
        }
    }

    impl UiStatusOutput for BlockingStatusPixel {
        fn set_ui_hint(&mut self, hint: PresenceUiHint) {
            self.send(if hint == PresenceUiHint::TouchRequired {
                0x202020
            } else {
                0
            });
        }
    }
}

#[cfg(feature = "pmp-internal-uart-fido")]
pub use blocking::BlockingStatusPixel;
