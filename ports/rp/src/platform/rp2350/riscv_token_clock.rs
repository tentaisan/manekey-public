use rp235x_hal as hal;

use manekey::ctaphid::pin_uv_auth::PinUvAuthTokenClock;

#[derive(Clone, Copy)]
/// Millisecond token clock backed by TIMER0; its microsecond counter must be initialized and running.
pub struct Rp2350RiscvTokenClock;

impl PinUvAuthTokenClock for Rp2350RiscvTokenClock {
    fn now_ms(&self) -> u64 {
        let timer = unsafe { &*hal::pac::TIMER0::ptr() };
        let mut high = timer.timerawh().read().bits();
        loop {
            let low = timer.timerawl().read().bits();
            let next_high = timer.timerawh().read().bits();
            if high == next_high {
                let now_us = (u64::from(high) << 32) | u64::from(low);
                return now_us / 1_000;
            }
            high = next_high;
        }
    }
}
