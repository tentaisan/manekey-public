use ch32_hal::{Peri, pac, peripherals};
use manekey::ctaphid::entropy::{EntropyError, EntropySource, SampleConditioner, SampleHealth};

/// Unqualified ADC noise source; conditioning/gross-failure checks do not establish min-entropy.
/// Caller exclusively reserves ADC1/temperature/Vref and keeps PCLK2 within the configured ADC clock limit.
pub struct AdcEntropy {
    _adc: Peri<'static, peripherals::ADC1>,
}

impl AdcEntropy {
    pub fn new(adc: Peri<'static, peripherals::ADC1>) -> Result<Self, EntropyError> {
        pac::RCC
            .cfgr0()
            .modify(|r| r.set_adcpre(pac::rcc::vals::Adcpre::DIV8));
        pac::RCC.apb2pcenr().modify(|r| r.set_adc1en(true));
        pac::RCC.apb2prstr().modify(|r| r.set_adc1rst(true));
        pac::RCC.apb2prstr().modify(|r| r.set_adc1rst(false));
        pac::ADC1.ctlr1().write(|r| r.0 = 0);
        pac::ADC1.ctlr2().write(|r| {
            r.set_adon(true);
            r.set_exttrig(true);
            r.set_extsel(pac::adc::vals::Extsel::SWSTART);
            r.set_tsvrefe(true);
        });
        for _ in 0..100_000 {
            core::hint::spin_loop();
        }
        pac::ADC1.ctlr2().modify(|r| r.set_rstcal(true));
        Self::wait(|| !pac::ADC1.ctlr2().read().rstcal())?;
        pac::ADC1.ctlr2().modify(|r| r.set_cal(true));
        Self::wait(|| !pac::ADC1.ctlr2().read().cal())?;
        pac::ADC1.rsqr1().write(|r| r.set_l(0));
        pac::ADC1.samptr1().modify(|r| {
            r.set_smp(6, pac::adc::vals::SampleTime::CYCLES239_5);
            r.set_smp(7, pac::adc::vals::SampleTime::CYCLES239_5);
        });
        Ok(Self { _adc: adc })
    }

    fn wait(mut ready: impl FnMut() -> bool) -> Result<(), EntropyError> {
        for _ in 0..1_000_000 {
            if ready() {
                return Ok(());
            }
        }
        Err(EntropyError::Unavailable)
    }

    fn sample(channel: u8) -> Result<u16, EntropyError> {
        pac::ADC1.rsqr3().modify(|r| r.set_sq(0, channel));
        pac::ADC1.ctlr2().modify(|r| r.set_swstart(true));
        Self::wait(|| pac::ADC1.statr().read().eoc())?;
        Ok(pac::ADC1.rdatar().read().data())
    }

    pub fn collect(&mut self, output: &mut [u8; 32]) -> Result<SampleHealth, EntropyError> {
        Self::collect_samples(output)
    }

    pub(crate) fn collect_samples(output: &mut [u8; 32]) -> Result<SampleHealth, EntropyError> {
        let mut hash = SampleConditioner::new();
        let mut health = SampleHealth::new();
        for _ in 0..1024 {
            let temp = Self::sample(16)?;
            let vref = Self::sample(17)?;
            health.observe(u32::from(temp));
            hash.update(&temp.to_le_bytes());
            hash.update(&vref.to_le_bytes());
        }
        output.copy_from_slice(&hash.finish());
        Ok(health)
    }
}

impl EntropySource for AdcEntropy {
    fn fill_entropy(&mut self, output: &mut [u8]) -> Result<(), EntropyError> {
        for chunk in output.chunks_mut(32) {
            let mut block = [0; 32];
            let health = self.collect(&mut block)?;

            health.check(1024, 64, 128..=896)?;
            chunk.copy_from_slice(&block[..chunk.len()]);
        }
        Ok(())
    }
}
