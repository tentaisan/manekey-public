#[cfg(all(target_arch = "arm", target_os = "none", feature = "chip-rp2040"))]
use manekey::ctaphid::entropy::{EntropyError, EntropySource};

#[cfg(all(target_arch = "arm", target_os = "none", feature = "chip-rp2040"))]
/// RP2040 ROSC entropy adapter; source quality is not cryptographic certification.
pub struct RoscEntropy;

#[cfg(all(target_arch = "arm", target_os = "none", feature = "chip-rp2040"))]
impl EntropySource for RoscEntropy {
    fn fill_entropy(&mut self, output: &mut [u8]) -> Result<(), EntropyError> {
        use embassy_rp::clocks::RoscRng;

        RoscRng.fill_bytes(output);
        Ok(())
    }
}
