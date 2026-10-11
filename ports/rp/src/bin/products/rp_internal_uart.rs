use embassy_futures::select::{Either, select};
use embassy_time::{Duration, Ticker};
use embedded_io_async::{Read, Write};
use manekey::ctaphid::trusted::{TRUSTED_REQUEST_MAX, TRUSTED_RESPONSE_MAX};
use manekey::frontend::internal::{InterconnectCtap2Frontend, InterconnectCtap2Outcome};

use super::{InternalUart, SharedArbiter};

#[embassy_executor::task]
/// Initialize one UART frontend owner once; share only the serialized arbiter, not UART or frame buffers.
pub(super) async fn multi_internal_task(
    mut uart: InternalUart,
    arbiter: &'static SharedArbiter,
) -> ! {
    let mut frontend = InterconnectCtap2Frontend::<TRUSTED_REQUEST_MAX>::new(0);
    let mut input = [0; 64];
    let mut response = [0; TRUSTED_RESPONSE_MAX + 11];
    let mut ticker = Ticker::every(Duration::from_millis(10));
    loop {
        match select(uart.read(&mut input), ticker.next()).await {
            Either::First(Ok(length)) => {
                for byte in &input[..length] {
                    let outcome = arbiter
                        .lock(|a| frontend.push_byte(&mut a.borrow_mut(), *byte, &mut response));
                    if let Ok(Some(InterconnectCtap2Outcome::Response { len })) = outcome {
                        if uart.write_all(&response[..len]).await.is_err() {
                            arbiter.lock(|a| frontend.disconnect(&mut a.borrow_mut()));
                        }
                    }
                }
            }
            Either::First(Err(_)) => frontend.discard_partial_frame(),
            Either::Second(()) => {}
        }
        arbiter.lock(|a| frontend.poll_cancel(&mut a.borrow_mut()));
    }
}
