use embassy_stm32::{Peri, adc, peripherals, timer};
use manekey::ctaphid::entropy::{EntropyError, EntropySource, SampleConditioner, SampleHealth};

/// Unqualified ADC/LSI source; conditioning and gross-failure checks are not entropy validation.
/// Caller exclusively owns ADC1/TIM5 and keeps LSI and the configured clocks active.
pub struct ExperimentalEntropy {
    adc: adc::Adc<'static, peripherals::ADC1, embassy_stm32::mode::Blocking>,
    temperature: adc::Temperature,
    vref: adc::VrefInt,
    timer: timer::low_level::Timer<'static, peripherals::TIM5>,
}

impl ExperimentalEntropy {
    pub fn new(
        adc: Peri<'static, peripherals::ADC1>,
        tim: Peri<'static, peripherals::TIM5>,
    ) -> Self {
        let mut adc = adc::Adc::new_blocking(adc, adc::Config::default());
        let temperature = adc.enable_temperature();
        let vref = adc.enable_vrefint();
        cortex_m::asm::delay(96_000);
        let timer = timer::low_level::Timer::new(tim);
        let channel = timer::Channel::Ch4;
        timer.set_max_compare_value(u32::MAX);

        timer.regs_gp32().or().modify(|v| *v = (*v & !0xc0) | 0x40);
        timer.set_input_capture_selection(channel, timer::low_level::InputCaptureSelection::Normal);
        timer.set_input_capture_mode(channel, timer::low_level::InputCaptureMode::Rising);
        timer.enable_channel(channel, true);
        timer.start();
        Self {
            adc,
            temperature,
            vref,
            timer,
        }
    }

    fn capture(&self) -> Result<u32, EntropyError> {
        let channel = timer::Channel::Ch4;
        self.timer.regs_gp32().sr().write(|r| {
            r.0 = u32::MAX;
            r.set_ccif(3, false);
            r.set_ccof(3, false);
        });
        let start = self.timer.get_counter();
        loop {
            if self.timer.get_input_interrupt(channel) {
                if self.timer.regs_gp32().sr().read().ccof(3) {
                    return Err(EntropyError::HealthCheckFailed);
                }
                return Ok(self.timer.get_capture_value(channel));
            }

            if self.timer.get_counter().wrapping_sub(start) > 960_000 {
                return Err(EntropyError::Unavailable);
            }
        }
    }
}

impl EntropySource for ExperimentalEntropy {
    fn fill_entropy(&mut self, output: &mut [u8]) -> Result<(), EntropyError> {
        for chunk in output.chunks_mut(32) {
            let mut hash = SampleConditioner::new();
            let sample_time = self.adc.sample_time_for_us(20);
            let mut health = SampleHealth::new();
            let mut delta_min = u32::MAX;
            let mut delta_max = 0;
            let mut previous = self.capture()?;
            for _ in 0..1024 {
                let temp = self.adc.blocking_read(&mut self.temperature, sample_time);
                let vref = self.adc.blocking_read(&mut self.vref, sample_time);
                let capture = self.capture()?;
                let delta = capture.wrapping_sub(previous);
                previous = capture;
                health.observe(u32::from(temp));
                delta_min = delta_min.min(delta);
                delta_max = delta_max.max(delta);
                if health.longest_run >= 64 {
                    return Err(EntropyError::HealthCheckFailed);
                }
                hash.update(&temp.to_le_bytes());
                hash.update(&vref.to_le_bytes());
                hash.update(&delta.to_le_bytes());
            }

            health.check(1024, 64, 256..=768)?;
            if delta_min == delta_max {
                return Err(EntropyError::HealthCheckFailed);
            }
            chunk.copy_from_slice(&hash.finish()[..chunk.len()]);
        }
        Ok(())
    }
}
