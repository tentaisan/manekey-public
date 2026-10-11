use esp_hal::rng::Rng;
use manekey::ctaphid::entropy::{EntropyError, EntropySource, HmacDrbgEntropy};

/// RNG adapter; platform must keep an active RF entropy source, not merely the RNG peripheral.
pub struct EspRadioEntropy(Rng);

impl EntropySource for EspRadioEntropy {
    fn fill_entropy(&mut self, output: &mut [u8]) -> Result<(), EntropyError> {
        self.0.read(output);
        Ok(())
    }
}

pub type EspEntropy = HmacDrbgEntropy<EspRadioEntropy>;

/// Seed only after BLE controller startup; panics on seeding failure.
pub fn build_radio_entropy() -> EspEntropy {
    HmacDrbgEntropy::new(EspRadioEntropy(Rng::new()))
        .expect("seed ESP32-C5 HMAC-DRBG after BLE controller startup")
}

#[cfg(feature = "adc-entropy")]
pub type C5AdcDrbgEntropy = HmacDrbgEntropy<crate::adc_entropy::C5AdcEntropy<'static>>;
