use core::cell::RefCell;

use critical_section::Mutex;
use embassy_nrf::{crypto::rng, mode::Blocking};
use manekey::ctaphid::entropy::{EntropyError, EntropySource, HmacDrbgEntropy};
use rand_core_06::RngCore;
use static_cell::StaticCell;

type SharedRngCell = Mutex<RefCell<rng::Rng<'static, Blocking>>>;

static SHARED_RNG: StaticCell<SharedRngCell> = StaticCell::new();

#[cfg(feature = "ble-security")]
static EMBASSY_CRYPTO_RNG: Mutex<RefCell<Option<SharedNrf54Rng>>> = Mutex::new(RefCell::new(None));

#[derive(Clone, Copy)]
/// Serialized CRACEN RNG handle; exclude independent peripheral owners and reentry.
pub struct SharedNrf54Rng {
    inner: &'static SharedRngCell,
}

/// Initialize once before controller/CTAP/LESC use; keep the RNG runtime active.
pub fn init_shared_rng(rng: rng::Rng<'static, Blocking>) -> SharedNrf54Rng {
    let shared = SharedNrf54Rng {
        inner: SHARED_RNG.init(Mutex::new(RefCell::new(rng))),
    };
    #[cfg(feature = "ble-security")]
    critical_section::with(|cs| {
        EMBASSY_CRYPTO_RNG.borrow_ref_mut(cs).replace(shared);
    });
    shared
}

#[cfg(feature = "ble-security")]
struct Nrf54EmbassyCryptoRng;

#[cfg(feature = "ble-security")]
impl embassy_crypto::driver::Rng for Nrf54EmbassyCryptoRng {
    fn fill_bytes(output: &mut [u8]) {
        let mut rng = critical_section::with(|cs| {
            EMBASSY_CRYPTO_RNG
                .borrow_ref(cs)
                .as_ref()
                .copied()
                .expect("CRACEN RNG must be initialized before LESC")
        });
        rng.fill_bytes(output);
    }
}

#[cfg(feature = "ble-security")]
embassy_crypto::rng_impl!(Nrf54EmbassyCryptoRng);

impl RngCore for SharedNrf54Rng {
    fn next_u32(&mut self) -> u32 {
        critical_section::with(|cs| self.inner.borrow_ref_mut(cs).next_u32())
    }

    fn next_u64(&mut self) -> u64 {
        critical_section::with(|cs| self.inner.borrow_ref_mut(cs).next_u64())
    }

    fn fill_bytes(&mut self, output: &mut [u8]) {
        critical_section::with(|cs| self.inner.borrow_ref_mut(cs).fill_bytes(output));
    }

    fn try_fill_bytes(&mut self, output: &mut [u8]) -> Result<(), rand_core_06::Error> {
        self.fill_bytes(output);
        Ok(())
    }
}

impl rand_core_06::CryptoRng for SharedNrf54Rng {}

impl rand_core_09::RngCore for SharedNrf54Rng {
    fn next_u32(&mut self) -> u32 {
        critical_section::with(|cs| self.inner.borrow_ref_mut(cs).next_u32())
    }

    fn next_u64(&mut self) -> u64 {
        critical_section::with(|cs| self.inner.borrow_ref_mut(cs).next_u64())
    }

    fn fill_bytes(&mut self, output: &mut [u8]) {
        critical_section::with(|cs| self.inner.borrow_ref_mut(cs).fill_bytes(output));
    }
}

impl rand_core_09::CryptoRng for SharedNrf54Rng {}

pub struct Nrf54EntropySource(pub SharedNrf54Rng);

impl EntropySource for Nrf54EntropySource {
    fn fill_entropy(&mut self, output: &mut [u8]) -> Result<(), EntropyError> {
        self.0.fill_bytes(output);
        Ok(())
    }
}

pub type Nrf54Entropy = HmacDrbgEntropy<Nrf54EntropySource>;

pub fn build_entropy(rng: SharedNrf54Rng) -> Result<Nrf54Entropy, EntropyError> {
    HmacDrbgEntropy::new(Nrf54EntropySource(rng))
}
