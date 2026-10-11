use hmac::{Hmac, KeyInit, Mac};
use sha2::{Digest, Sha256};

type HmacSha256 = Hmac<Sha256>;
const HMAC_DRBG_SEED_LEN: usize = 48;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EntropyError {
    Unavailable,

    HealthCheckFailed,
}

/// Fills the entire output on success; callers must discard output after an error.
pub trait EntropySource {
    fn fill_entropy(&mut self, output: &mut [u8]) -> Result<(), EntropyError>;
}

/// Gross-failure sample checks, not an entropy estimate or SP800-90B validation.
pub struct SampleHealth {
    pub count: u32,
    pub min: u32,
    pub max: u32,
    pub lsb_ones: u32,
    pub longest_run: u32,
    previous: Option<u32>,
    run: u32,
}

impl SampleHealth {
    pub const fn new() -> Self {
        Self {
            count: 0,
            min: u32::MAX,
            max: 0,
            lsb_ones: 0,
            longest_run: 0,
            previous: None,
            run: 0,
        }
    }

    pub fn observe(&mut self, sample: u32) {
        self.count = self.count.saturating_add(1);
        self.min = self.min.min(sample);
        self.max = self.max.max(sample);
        self.lsb_ones = self.lsb_ones.saturating_add(sample & 1);
        self.run = if self.previous == Some(sample) {
            self.run.saturating_add(1)
        } else {
            1
        };
        self.longest_run = self.longest_run.max(self.run);
        self.previous = Some(sample);
    }

    pub fn check(
        &self,
        count: u32,
        max_run: u32,
        ones: core::ops::RangeInclusive<u32>,
    ) -> Result<(), EntropyError> {
        if self.count != count
            || self.min == self.max
            || self.longest_run >= max_run
            || !ones.contains(&self.lsb_ones)
        {
            Err(EntropyError::HealthCheckFailed)
        } else {
            Ok(())
        }
    }
}

impl Default for SampleHealth {
    fn default() -> Self {
        Self::new()
    }
}

/// SHA-256 conditioning does not create source entropy.
pub struct SampleConditioner(Sha256);
impl SampleConditioner {
    pub fn new() -> Self {
        Self(Sha256::new())
    }
    pub fn update(&mut self, bytes: &[u8]) {
        Digest::update(&mut self.0, bytes);
    }
    pub fn finish(self) -> [u8; 32] {
        self.0.finalize().into()
    }
}
impl Default for SampleConditioner {
    fn default() -> Self {
        Self::new()
    }
}

/// Experimental conditioned source, not a validated RNG or automatic state-erasure guarantee.
pub struct HmacDrbgEntropy<S: EntropySource> {
    source: S,
    k: [u8; 32],
    v: [u8; 32],
    reseed_counter: u32,
}

impl<S: EntropySource> HmacDrbgEntropy<S> {
    const RESEED_INTERVAL: u32 = 1024;

    pub fn new(source: S) -> Result<Self, EntropyError> {
        let mut drbg = Self {
            source,
            k: [0; 32],
            v: [1; 32],
            reseed_counter: 1,
        };
        drbg.reseed()?;
        Ok(drbg)
    }

    fn hmac(key: &[u8; 32], parts: &[&[u8]]) -> [u8; 32] {
        let mut mac = HmacSha256::new_from_slice(key).expect("HMAC accepts any key length");
        for part in parts {
            mac.update(part);
        }
        mac.finalize().into_bytes().into()
    }

    fn update(&mut self, provided_data: Option<&[u8]>) {
        let marker = [0x00];
        self.k = Self::hmac(&self.k, &[&self.v, &marker, provided_data.unwrap_or(&[])]);
        self.v = Self::hmac(&self.k, &[&self.v]);

        if let Some(data) = provided_data {
            let marker = [0x01];
            self.k = Self::hmac(&self.k, &[&self.v, &marker, data]);
            self.v = Self::hmac(&self.k, &[&self.v]);
        }
    }

    fn reseed(&mut self) -> Result<(), EntropyError> {
        let mut seed = [0u8; HMAC_DRBG_SEED_LEN];
        self.source.fill_entropy(&mut seed)?;
        if !seed_passes_startup_health_check(&seed) {
            return Err(EntropyError::HealthCheckFailed);
        }
        self.update(Some(&seed));
        self.reseed_counter = 1;
        Ok(())
    }
}

fn seed_passes_startup_health_check(seed: &[u8]) -> bool {
    if seed.is_empty() {
        return false;
    }

    let mut distinct = 0usize;
    let mut longest_run = 1usize;
    let mut current_run = 1usize;

    for (index, byte) in seed.iter().enumerate() {
        if seed[..index].iter().all(|seen| seen != byte) {
            distinct += 1;
        }

        if index > 0 && seed[index - 1] == *byte {
            current_run += 1;
            longest_run = longest_run.max(current_run);
        } else {
            current_run = 1;
        }
    }

    distinct >= 4 && longest_run < (seed.len() / 2)
}

impl<S: EntropySource> EntropySource for HmacDrbgEntropy<S> {
    fn fill_entropy(&mut self, output: &mut [u8]) -> Result<(), EntropyError> {
        if self.reseed_counter > Self::RESEED_INTERVAL {
            self.reseed()?;
        }

        for chunk in output.chunks_mut(32) {
            self.v = Self::hmac(&self.k, &[&self.v]);
            chunk.copy_from_slice(&self.v[..chunk.len()]);
        }
        self.update(None);
        self.reseed_counter = self.reseed_counter.saturating_add(1);
        Ok(())
    }
}
