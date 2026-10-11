#[cfg(feature = "experimental-adc-entropy")]
use manekey::ctaphid::entropy::{EntropyError, EntropySource};

#[cfg(all(not(feature = "experimental-adc-entropy"), not(any())))]
compile_error!(
    "select experimental-adc-entropy for a product or an explicit private entropy fixture"
);

#[cfg(feature = "experimental-adc-entropy")]
mod experimental {
    use super::*;
    use crate::adc_entropy::AdcEntropy;
    use manekey::ctaphid::entropy::HmacDrbgEntropy;

    struct AdcSamples;
    impl EntropySource for AdcSamples {
        fn fill_entropy(&mut self, output: &mut [u8]) -> Result<(), EntropyError> {
            for chunk in output.chunks_mut(32) {
                let mut block = [0; 32];
                let health = AdcEntropy::collect_samples(&mut block)?;
                health.check(1024, 64, 128..=896)?;
                chunk.copy_from_slice(&block[..chunk.len()]);
            }
            Ok(())
        }
    }

    static mut DRBG: Option<HmacDrbgEntropy<AdcSamples>> = None;

    /// Initialize once before executor use; keep the returned ADC owner alive.
    /// One synchronous dispatcher owns the shared DRBG; exclude reentry, IRQ, DMA and other-core access.
    pub fn initialize(
        adc: ch32_hal::Peri<'static, ch32_hal::peripherals::ADC1>,
    ) -> Result<AdcEntropy, EntropyError> {
        let owner = AdcEntropy::new(adc)?;
        let drbg = HmacDrbgEntropy::new(AdcSamples)?;
        unsafe {
            *core::ptr::addr_of_mut!(DRBG) = Some(drbg);
        }
        Ok(owner)
    }

    pub struct SelectedEntropy;
    impl SelectedEntropy {
        pub const fn new() -> Self {
            Self
        }
    }
    impl EntropySource for SelectedEntropy {
        fn fill_entropy(&mut self, output: &mut [u8]) -> Result<(), EntropyError> {
            unsafe { &mut *core::ptr::addr_of_mut!(DRBG) }
                .as_mut()
                .ok_or(EntropyError::Unavailable)?
                .fill_entropy(output)
        }
    }
}
#[cfg(feature = "experimental-adc-entropy")]
pub use experimental::{SelectedEntropy, initialize};
