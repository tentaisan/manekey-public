use esp_hal::rng::Trng;
use esp_println::println;
use manekey::ctaphid::entropy::{EntropyError, EntropySource, HmacDrbgEntropy};

/// HAL TRNG adapter; platform must keep the configured entropy source active.
pub struct EspTrngEntropy {
    trng: Trng,
}

impl EspTrngEntropy {
    pub const fn new(trng: Trng) -> Self {
        Self { trng }
    }
}

impl EntropySource for EspTrngEntropy {
    fn fill_entropy(&mut self, output: &mut [u8]) -> Result<(), EntropyError> {
        self.trng.read(output);
        Ok(())
    }
}

pub type EspEntropy = HmacDrbgEntropy<EspTrngEntropy>;

pub fn build_entropy_from_trng(trng: Trng) -> EspEntropy {
    HmacDrbgEntropy::new(EspTrngEntropy::new(trng)).expect("seed ESP HMAC-DRBG from TRNG")
}

/// Panics on initialization/seeding failure; not an entropy certification.
pub fn build_trng_entropy() -> EspEntropy {
    let entropy = build_entropy_from_trng(Trng::try_new().expect("ESP TRNG source is enabled"));
    println!("ESP TRNG entropy enabled");
    entropy
}
