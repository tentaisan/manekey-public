


use crate::sci2::Sci2;
use manekey::{
    ctaphid::trusted::{TRUSTED_RESPONSE_MAX, TrustedBackend},
    frontend::internal::{InterconnectCtap2Frontend, InterconnectCtap2Outcome},
    transport::usb::embassy::SharedUsbArbiter,
};

pub async fn run<T: TrustedBackend + 'static>(
    mut uart: Sci2,
    arbiter: &'static SharedUsbArbiter<T>,
) -> ! {
    let mut frontend = InterconnectCtap2Frontend::<{ TRUSTED_RESPONSE_MAX + 32 }>::new(0);
    let mut response = [0; TRUSTED_RESPONSE_MAX + 32];
    loop {
        arbiter.lock(|cell| {
            let _ = frontend.poll_cancel(&mut cell.borrow_mut());
        });
        // 115200 8N1 is one byte per 87 us. Do not use a millisecond RX poll.
        while let Some(byte) = uart.read() {












            let outcome = arbiter
                .lock(|cell| frontend.push_byte(&mut cell.borrow_mut(), byte, &mut response));
            match outcome {
                Ok(Some(InterconnectCtap2Outcome::Response { len })) => {
                    uart.write(&response[..len])
                }
                Err(_) => arbiter.lock(|cell| frontend.disconnect(&mut cell.borrow_mut())),
                _ => {}
            }
        }
        embassy_time::Timer::after_micros(20).await;
    }
}
