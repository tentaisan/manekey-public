use core::cell::RefCell;
use critical_section::Mutex;
use embassy_stm32::{Peri, bind_interrupts, hash, mode::Blocking, peripherals};
use manekey::ctaphid::hash::{Sha256Backend, Sha256Error};

bind_interrupts!(struct Irqs {
    HASH => hash::InterruptHandler<peripherals::HASH>;
});
type Driver = hash::Hash<'static, peripherals::HASH, Blocking>;
static DRIVER: Mutex<RefCell<Option<Driver>>> = Mutex::new(RefCell::new(None));

#[derive(Clone, Copy)]
/// Shared HASH handle; a complete blocking digest holds the critical section.
pub struct Stm32Sha256;

/// Claims HASH once; all users must share the critical-section domain.
/// # Panics
/// Panics if HASH is already initialized.
pub fn initialize(peripheral: Peri<'static, peripherals::HASH>) {
    critical_section::with(|cs| {
        let mut driver = DRIVER.borrow(cs).borrow_mut();
        assert!(driver.is_none(), "HASH already owned");
        *driver = Some(hash::Hash::new_blocking(peripheral, Irqs));
    });
}

impl Sha256Backend for Stm32Sha256 {
    fn digest(&mut self, data: &[u8]) -> Result<[u8; 32], Sha256Error> {
        self.digest_parts(&[data])
    }

    fn digest_parts(&mut self, parts: &[&[u8]]) -> Result<[u8; 32], Sha256Error> {
        critical_section::with(|cs| {
            let mut driver = DRIVER
                .borrow(cs)
                .try_borrow_mut()
                .map_err(|_| Sha256Error::HardwareUnavailable)?;
            let driver = driver.as_mut().ok_or(Sha256Error::HardwareUnavailable)?;
            let mut context =
                driver.start::<hash::Sha256, hash::NonHmac>(hash::DataType::Width8, None);
            for part in parts {
                driver.update_blocking(&mut context, part);
            }
            let mut digest = [0; 32];
            if driver.finish_blocking(context, &mut digest) != digest.len() {
                return Err(Sha256Error::HardwareUnavailable);
            }
            Ok(digest)
        })
    }
}
