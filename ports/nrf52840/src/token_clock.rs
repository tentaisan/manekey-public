use manekey::ctaphid::pin_uv_auth::PinUvAuthTokenClock;
use nrf52840_pac::RTC1;

const RTC1_PRESCALER: u32 = 4095;
const RTC1_TICK_MS: u64 = 125;

#[derive(Clone, Copy)]
/// Exclusively owned RTC1 at 125 ms ticks; requires the active LF clock.
/// Counter wrap moves time backward and can expire a token early.
pub struct NrfRtc1TokenClock;

impl NrfRtc1TokenClock {
    pub fn start(rtc1: RTC1) -> Self {
        rtc1.tasks_stop.write(|w| unsafe { w.bits(1) });
        rtc1.prescaler.write(|w| unsafe { w.bits(RTC1_PRESCALER) });
        rtc1.tasks_clear.write(|w| unsafe { w.bits(1) });
        rtc1.tasks_start.write(|w| unsafe { w.bits(1) });
        Self
    }
}

impl PinUvAuthTokenClock for NrfRtc1TokenClock {
    fn now_ms(&self) -> u64 {
        let rtc1 = unsafe { &*RTC1::ptr() };
        u64::from(rtc1.counter.read().bits()) * RTC1_TICK_MS
    }
}
