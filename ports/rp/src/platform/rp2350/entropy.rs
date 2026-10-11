// TRNG initialization references Embassy; Copyright (c) Embassy project contributors.
// Source: https://github.com/embassy-rs/embassy/blob/0af1937a5ac77f52fea943b677088c38ef9e91c6/embassy-rp/src/trng.rs
// Original Embassy portions retain MIT OR Apache-2.0; see vendor/cyw43-portable license texts.
// Modified for RISC-V PAC access, bounded retry and explicit entropy errors.

#[cfg(any(
    all(target_arch = "arm", target_os = "none", feature = "chip-rp235xa"),
    all(
        feature = "riscv-rp2350-hal",
        target_arch = "riscv32",
        target_os = "none"
    )
))]
use manekey::ctaphid::entropy::{EntropyError, EntropySource};

#[cfg(all(
    feature = "riscv-rp2350-hal",
    target_arch = "riscv32",
    target_os = "none"
))]
pub fn riscv_entropy_error() -> u32 {
    1
}

#[cfg(all(target_arch = "arm", target_os = "none", feature = "chip-rp235xa"))]
/// Exclusive blocking TRNG owner; keep its HAL/clock environment active.
pub struct Rp2350Trng<'d, T: embassy_rp::trng::Instance>(embassy_rp::trng::Trng<'d, T>);

#[cfg(all(target_arch = "arm", target_os = "none", feature = "chip-rp235xa"))]
impl<'d, T: embassy_rp::trng::Instance> Rp2350Trng<'d, T> {
    pub fn new(trng: embassy_rp::trng::Trng<'d, T>) -> Self {
        Self(trng)
    }
}

#[cfg(all(target_arch = "arm", target_os = "none", feature = "chip-rp235xa"))]
impl<'d, T: embassy_rp::trng::Instance> EntropySource for Rp2350Trng<'d, T> {
    fn fill_entropy(&mut self, output: &mut [u8]) -> Result<(), EntropyError> {
        self.0.blocking_fill_bytes(output);
        Ok(())
    }
}

#[cfg(all(
    feature = "riscv-rp2350-hal",
    target_arch = "riscv32",
    target_os = "none"
))]
/// Exclusive TRNG owner requiring initialized TIMER0 for bounded generation waits.
/// Health failures return unavailable; no deterministic fallback is supplied.
pub struct RiscvTrng {
    regs: rp235x_hal::pac::TRNG,
}

#[cfg(all(
    feature = "riscv-rp2350-hal",
    target_arch = "riscv32",
    target_os = "none"
))]
impl RiscvTrng {
    const BLOCK_LEN: usize = 24;
    const GENERATION_ATTEMPTS: usize = 32;
    const GENERATION_TIMEOUT_US: u64 = 500_000;

    const SAMPLE_COUNT: u32 = 200;

    pub fn new(regs: rp235x_hal::pac::TRNG) -> Self {
        let trng = Self { regs };

        trng.reset_and_initialize();
        trng
    }

    fn reset_and_initialize(&self) {
        self.regs
            .trng_sw_reset()
            .write(|w| w.trng_sw_reset().set_bit());

        let _ = self.regs.trng_sw_reset().read();

        self.regs.rng_icr().write(|w| unsafe { w.bits(u32::MAX) });
        self.initialize();
    }

    fn initialize(&self) {
        unsafe {
            self.regs
                .rng_imr()
                .write(|w| w.ehr_valid_int_mask().clear_bit());
            self.regs.trng_config().write(|w| w.rnd_src_sel().bits(1));
            self.regs
                .sample_cnt1()
                .write(|w| w.sample_cntr1().bits(Self::SAMPLE_COUNT));
            self.regs.trng_debug_control().write(|w| {
                w.vnc_bypass()
                    .clear_bit()
                    .trng_crngt_bypass()
                    .clear_bit()
                    .auto_correlate_bypass()
                    .clear_bit()
            });
        }
    }

    fn start(&self) {
        self.regs
            .rnd_source_enable()
            .write(|w| w.rnd_src_en().set_bit());
    }

    fn now_us() -> u64 {
        let timer = unsafe { &*rp235x_hal::pac::TIMER0::ptr() };
        let mut high = timer.timerawh().read().bits();
        loop {
            let low = timer.timerawl().read().bits();
            let next_high = timer.timerawh().read().bits();
            if high == next_high {
                return (u64::from(high) << 32) | u64::from(low);
            }
            high = next_high;
        }
    }

    fn stop(&self) {
        self.regs
            .rnd_source_enable()
            .write(|w| w.rnd_src_en().clear_bit());
        self.regs
            .rst_bits_counter()
            .write(|w| w.rst_bits_counter().set_bit());
    }

    fn read_block(&mut self, block: &mut [u8; Self::BLOCK_LEN]) -> Result<(), EntropyError> {
        for attempt in 0..Self::GENERATION_ATTEMPTS {
            self.reset_and_initialize();
            self.start();
            let mut generation_started = false;
            let started_at = Self::now_us();

            while Self::now_us().saturating_sub(started_at) < Self::GENERATION_TIMEOUT_US {
                let isr = self.regs.rng_isr().read().bits() & 0x0f;
                if isr & 0x0e != 0 {
                    break;
                }
                let busy = self.regs.trng_busy().read().trng_busy().bit();
                let valid = self.regs.trng_valid().read().ehr_valid().bit();

                if !generation_started {
                    if busy {
                        generation_started = true;
                        continue;
                    }
                    if !valid {
                        continue;
                    }
                }

                if busy {
                    continue;
                }
                if !valid {
                    break;
                }

                let words = [
                    self.regs.ehr_data0().read().ehr_data0().bits(),
                    self.regs.ehr_data1().read().ehr_data1().bits(),
                    self.regs.ehr_data2().read().ehr_data2().bits(),
                    self.regs.ehr_data3().read().ehr_data3().bits(),
                    self.regs.ehr_data4().read().ehr_data4().bits(),
                    self.regs.ehr_data5().read().ehr_data5().bits(),
                ];
                for (chunk, word) in block.chunks_exact_mut(4).zip(words) {
                    chunk.copy_from_slice(&word.to_ne_bytes());
                }
                self.stop();

                return Ok(());
            }

            self.stop();
        }

        Err(EntropyError::Unavailable)
    }
}

#[cfg(all(
    feature = "riscv-rp2350-hal",
    target_arch = "riscv32",
    target_os = "none"
))]
impl EntropySource for RiscvTrng {
    fn fill_entropy(&mut self, output: &mut [u8]) -> Result<(), EntropyError> {
        for chunk in output.chunks_mut(Self::BLOCK_LEN) {
            let mut block = [0u8; Self::BLOCK_LEN];
            self.read_block(&mut block)?;
            chunk.copy_from_slice(&block[..chunk.len()]);
        }
        Ok(())
    }
}
