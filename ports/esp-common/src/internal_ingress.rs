use manekey::{
    ctaphid::trusted::TrustedBackend,
    frontend::{
        ingress::IngressArbiter,
        internal::{InterconnectCtap2Error, InterconnectCtap2Frontend, InterconnectCtap2Outcome},
    },
};

use crate::ingress::SharedArbiter;

/// Cooperative copied framing; port owns byte I/O, IRQ/DMA and authentication beyond CRC.
pub struct SharedInternalIngressFrontend<T: TrustedBackend + 'static, const MAX_FRAME: usize> {
    frontend: InterconnectCtap2Frontend<MAX_FRAME>,
    arbiter: &'static SharedArbiter<T>,
}

impl<T: TrustedBackend + 'static, const MAX_FRAME: usize>
    SharedInternalIngressFrontend<T, MAX_FRAME>
{
    pub const fn new(instance: u8, arbiter: &'static SharedArbiter<T>) -> Self {
        Self {
            frontend: InterconnectCtap2Frontend::new(instance),
            arbiter,
        }
    }

    pub const fn channel(&self) -> u8 {
        self.frontend.channel()
    }

    pub fn poll_cancel(&mut self) -> bool {
        self.arbiter
            .lock(|cell| self.frontend.poll_cancel(&mut cell.borrow_mut()))
    }

    pub fn discard_partial_frame(&mut self) {
        self.frontend.discard_partial_frame();
    }

    pub fn push_byte(
        &mut self,
        byte: u8,
        output: &mut [u8],
    ) -> Result<Option<InterconnectCtap2Outcome>, InterconnectCtap2Error> {
        self.arbiter.lock(|cell| {
            let mut arbiter: core::cell::RefMut<'_, IngressArbiter<T>> = cell.borrow_mut();
            self.frontend.push_byte(&mut arbiter, byte, output)
        })
    }
}

/// Serialized UART adapter; partial/failed writes are not reported as peer delivery or retried atomically.
pub async fn run_internal_uart<T: TrustedBackend + 'static, const MAX_FRAME: usize>(
    mut uart: esp_hal::uart::Uart<'static, esp_hal::Async>,
    frontend: &mut SharedInternalIngressFrontend<T, MAX_FRAME>,
    response: &mut [u8],
) -> ! {
    use embassy_futures::select::{Either, select};
    use embassy_time::Timer;

    let mut received = [0; 32];
    loop {
        frontend.poll_cancel();
        let count = match select(uart.read_async(&mut received), Timer::after_millis(2)).await {
            Either::First(Ok(count)) => count,
            Either::First(Err(_)) => {
                frontend.discard_partial_frame();
                continue;
            }
            Either::Second(_) => continue,
        };
        for &byte in &received[..count] {
            if let Ok(Some(InterconnectCtap2Outcome::Response { len })) =
                frontend.push_byte(byte, response)
            {
                let mut sent = 0;
                while sent < len {
                    match uart.write_async(&response[sent..len]).await {
                        Ok(0) | Err(_) => break,
                        Ok(count) => sent += count,
                    }
                }
                if sent == len {
                    let _ = uart.flush_async().await;
                }
            }
        }
    }
}
