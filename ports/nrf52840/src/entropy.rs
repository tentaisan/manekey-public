use cortex_m::asm;
use manekey::ctaphid::entropy::{EntropyError, EntropySource};
use nrf_softdevice::Softdevice;
use nrf52840_pac::RNG;

/// Direct RNG owner; exclude SoftDevice/other drivers and keep clocks active.
/// Poll bounds are iterations, not wall-clock deadlines.
pub struct NrfRngEntropy {
    rng: RNG,
}

impl NrfRngEntropy {
    const WAIT_LIMIT: u32 = 1_000_000;

    pub fn new(rng: RNG) -> Self {
        let entropy = Self { rng };
        entropy.rng.config.write(|w| w.dercen().enabled());
        entropy.rng.events_valrdy.write(|w| unsafe { w.bits(0) });
        entropy.rng.tasks_start.write(|w| w.tasks_start().set_bit());
        entropy
    }

    fn read_byte(&mut self) -> Result<u8, EntropyError> {
        for _ in 0..Self::WAIT_LIMIT {
            if self.rng.events_valrdy.read().events_valrdy().bit_is_clear() {
                asm::nop();
                continue;
            }
            self.rng.events_valrdy.write(|w| unsafe { w.bits(0) });
            return Ok(self.rng.value.read().value().bits());
        }
        Err(EntropyError::Unavailable)
    }
}

impl EntropySource for NrfRngEntropy {
    fn fill_entropy(&mut self, output: &mut [u8]) -> Result<(), EntropyError> {
        for byte in output {
            *byte = self.read_byte()?;
        }
        Ok(())
    }
}

/// Requires an initialized active SoftDevice that exclusively owns RNG; do not use a direct RNG driver concurrently.
pub struct SoftdeviceEntropy {
    sd: &'static Softdevice,
}

impl SoftdeviceEntropy {
    const WAIT_LIMIT: u32 = 1_000_000;

    pub const fn new(sd: &'static Softdevice) -> Self {
        Self { sd }
    }

    fn fill_via_softdevice(&mut self, output: &mut [u8]) -> Result<(), EntropyError> {
        let mut offset = 0;
        let mut not_ready_spins = 0;
        while offset < output.len() {
            let end = core::cmp::min(offset + 16, output.len());
            if nrf_softdevice::random_bytes(self.sd, &mut output[offset..end]).is_ok() {
                offset = end;
                not_ready_spins = 0;
            } else {
                not_ready_spins += 1;
                if not_ready_spins >= Self::WAIT_LIMIT {
                    return Err(EntropyError::Unavailable);
                }
                asm::nop();
            }
        }
        Ok(())
    }
}

impl EntropySource for SoftdeviceEntropy {
    fn fill_entropy(&mut self, output: &mut [u8]) -> Result<(), EntropyError> {
        self.fill_via_softdevice(output)
    }
}
