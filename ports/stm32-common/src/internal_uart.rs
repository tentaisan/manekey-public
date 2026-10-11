use embassy_futures::select::{Either, select};
use embassy_stm32::usart::BufferedUart;
use manekey::{
    ctaphid::trusted::{TRUSTED_RESPONSE_MAX, TrustedBackend},
    frontend::internal::{InterconnectCtap2Frontend, InterconnectCtap2Outcome},
    transport::usb::embassy::SharedUsbArbiter,
};

/// Runs buffered UART I/O in the arbiter's single executor context.
/// The framing CRC does not authenticate peers.
pub async fn run<T: TrustedBackend + 'static>(
    mut uart: BufferedUart<'static>,
    arbiter: &'static SharedUsbArbiter<T>,
) -> ! {
    let mut frontend = InterconnectCtap2Frontend::<{ TRUSTED_RESPONSE_MAX + 32 }>::new(0);
    let mut response = [0; TRUSTED_RESPONSE_MAX + 32];
    let mut input = [0; 64];
    loop {
        arbiter.lock(|cell| {
            let _ = frontend.poll_cancel(&mut cell.borrow_mut());
        });
        let length = match select(uart.read(&mut input), embassy_time::Timer::after_millis(5)).await
        {
            Either::First(Ok(length)) => length,
            Either::First(Err(_)) => {
                arbiter.lock(|cell| frontend.disconnect(&mut cell.borrow_mut()));
                embassy_time::Timer::after_millis(10).await;
                continue;
            }
            Either::Second(_) => continue,
        };

        for byte in &input[..length] {
            let outcome = arbiter
                .lock(|cell| frontend.push_byte(&mut cell.borrow_mut(), *byte, &mut response));
            if let Ok(Some(InterconnectCtap2Outcome::Response { len })) = outcome {
                let mut sent = 0;
                while sent < len {
                    match uart.write(&response[sent..len]).await {
                        Ok(0) | Err(_) => break,
                        Ok(length) => {
                            sent += length;
                        }
                    }
                }
            }
        }
    }
}
