// Copyright 2019-2022 Google LLC
// SPDX-License-Identifier: Apache-2.0
// Adapted from OpenSK bootloader/src/crypto_cell.rs at
// 5e30a47bc3ea1f664c9e6845b146ce88980bddfd.
// Modified: direct MMIO, bounded polling, one-shot hashing and shared RAM scratch.

#[cfg(feature = "client-pin-volatile")]
use core::cell::RefCell;
use manekey::ctaphid::hash::{Sha256Backend, Sha256Error};

const SHA256_PARTS_SCRATCH_LEN: usize = 256;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Cc310Error {
    InvalidSignature,
    Timeout,
}

impl Cc310Error {
    #[allow(dead_code)]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::InvalidSignature => "invalid-signature",
            Self::Timeout => "timeout",
        }
    }
}

/// Exclusive CryptoCell SHA-256 handle; direct inputs must be DMA-readable RAM.
/// Poll limits are iterations, not wall-clock deadlines.
pub struct Cc310Sha256 {
    parts_scratch: [u8; SHA256_PARTS_SCRATCH_LEN],
}

impl Cc310Sha256 {
    const POWER_ENABLE: *mut u32 = 0x5002_a500 as *mut u32;
    const BASE: usize = 0x5002_b000;
    const HASH: usize = Self::BASE + 0x0640;
    const HASH_AUTO_HW_PADDING: *mut u32 = (Self::BASE + 0x0684) as *mut u32;
    const HASH_CONTROL: *mut u32 = (Self::BASE + 0x07c0) as *mut u32;
    const HASH_PADDING: *mut u32 = (Self::BASE + 0x07c4) as *mut u32;
    const HASH_PAD_CONFIG: *mut u32 = (Self::BASE + 0x07c8) as *mut u32;
    const HASH_LEN_LSB: *mut u32 = (Self::BASE + 0x07cc) as *mut u32;
    const HASH_LEN_MSB: *mut u32 = (Self::BASE + 0x07d0) as *mut u32;
    const MISC_HASH_CLK_ENABLE: *mut u32 = (Self::BASE + 0x0818) as *mut u32;
    const MISC_DMA_CLK_ENABLE: *mut u32 = (Self::BASE + 0x0820) as *mut u32;
    const CTRL_CRYPTO_CTL: *mut u32 = (Self::BASE + 0x0900) as *mut u32;
    const CTRL_CRYPTO_BUSY: *const u32 = (Self::BASE + 0x0910) as *const u32;
    const CTRL_HASH_BUSY: *const u32 = (Self::BASE + 0x091c) as *const u32;
    const HOST_INTERRUPTS: *const u32 = (Self::BASE + 0x0a00) as *const u32;
    const HOST_INTERRUPT_MASK: *mut u32 = (Self::BASE + 0x0a04) as *mut u32;
    const HOST_INTERRUPT_CLEAR: *mut u32 = (Self::BASE + 0x0a08) as *mut u32;
    const HOST_ENDIAN: *mut u32 = (Self::BASE + 0x0a0c) as *mut u32;
    const HOST_SIGNATURE: *const u32 = (Self::BASE + 0x0a24) as *const u32;
    const DIN_MEM_DMA_BUSY: *const u32 = (Self::BASE + 0x0c20) as *const u32;
    const DIN_SRC_LLI_WORD0: *mut u32 = (Self::BASE + 0x0c28) as *mut u32;
    const DIN_SRC_LLI_WORD1: *mut u32 = (Self::BASE + 0x0c2c) as *mut u32;

    const CC310_SIGNATURE: u32 = 0x20e0_0000;
    const SHA256_INIT: [u32; 8] = [
        0x6a09_e667,
        0xbb67_ae85,
        0x3c6e_f372,
        0xa54f_f53a,
        0x510e_527f,
        0x9b05_688c,
        0x1f83_d9ab,
        0x5be0_cd19,
    ];
    const CRYPTO_MODE_HASH: u32 = 7;
    const HASH_MODE_SHA256: u32 = 2;
    const TASK_ENABLE: u32 = 1;
    const TASK_DISABLE: u32 = 0;
    const PADDING_DO_PAD: u32 = 1 << 2;
    const INTERRUPT_MEM_TO_DIN: u32 = 1 << 6;
    const INTERRUPT_MASK_ERRORS_ONLY: u32 = (1 << 8) | (1 << 9) | (1 << 10);
    const WAIT_SPINS: usize = 1_000_000;

    /// # Safety
    /// Exclusively own CryptoCell across all drivers, interrupts and DMA operations.
    /// Direct hash inputs must remain in DMA-readable RAM until the operation returns.
    pub unsafe fn new_unchecked() -> Self {
        Self {
            parts_scratch: [0; SHA256_PARTS_SCRATCH_LEN],
        }
    }

    /// Requires DMA-readable RAM input; flash/rodata inputs must be copied first.
    pub fn digest_direct(&self, data: &[u8]) -> Result<[u8; 32], Cc310Error> {
        self.enable()?;
        let result = self.start_hash(data).map(|()| self.read_digest());

        self.disable();
        result
    }

    fn read_digest(&self) -> [u8; 32] {
        let mut digest = [0u8; 32];
        for index in 0..8 {
            let word = unsafe { core::ptr::read_volatile((Self::HASH + index * 4) as *const u32) };
            digest[index * 4..index * 4 + 4].copy_from_slice(&word.to_be_bytes());
        }
        digest
    }

    fn enable(&self) -> Result<(), Cc310Error> {
        unsafe {
            core::ptr::write_volatile(Self::POWER_ENABLE, Self::TASK_ENABLE);
        }
        for _ in 0..10 {
            let signature = unsafe { core::ptr::read_volatile(Self::HOST_SIGNATURE) };
            if signature == Self::CC310_SIGNATURE {
                unsafe {
                    core::ptr::write_volatile(Self::HOST_ENDIAN, 0);
                    core::ptr::write_volatile(Self::MISC_DMA_CLK_ENABLE, Self::TASK_ENABLE);
                    core::ptr::write_volatile(
                        Self::HOST_INTERRUPT_MASK,
                        Self::INTERRUPT_MASK_ERRORS_ONLY,
                    );
                }
                return Ok(());
            }
        }
        Err(Cc310Error::InvalidSignature)
    }

    fn disable(&self) {
        unsafe {
            core::ptr::write_volatile(Self::HOST_INTERRUPT_MASK, 0);
            core::ptr::write_volatile(Self::MISC_DMA_CLK_ENABLE, Self::TASK_DISABLE);
            core::ptr::write_volatile(Self::POWER_ENABLE, Self::TASK_DISABLE);
        }
    }

    fn start_hash(&self, data: &[u8]) -> Result<(), Cc310Error> {
        self.wait_ready()?;
        unsafe {
            core::ptr::write_volatile(Self::MISC_HASH_CLK_ENABLE, Self::TASK_ENABLE);
            core::ptr::write_volatile(Self::CTRL_CRYPTO_CTL, Self::CRYPTO_MODE_HASH);
            core::ptr::write_volatile(Self::HASH_PADDING, Self::TASK_ENABLE);
            core::ptr::write_volatile(Self::HASH_LEN_LSB, 0);
            core::ptr::write_volatile(Self::HASH_LEN_MSB, 0);
            core::ptr::write_volatile(Self::HASH_CONTROL, Self::HASH_MODE_SHA256);
        }

        for index in (0..Self::SHA256_INIT.len()).rev() {
            unsafe {
                core::ptr::write_volatile(
                    (Self::HASH + index * 4) as *mut u32,
                    Self::SHA256_INIT[index],
                );
            }
        }
        self.wait_hash_ready()?;

        if data.is_empty() {
            unsafe {
                core::ptr::write_volatile(Self::HASH_PAD_CONFIG, Self::PADDING_DO_PAD);
            }
        } else {
            unsafe {
                core::ptr::write_volatile(Self::HASH_AUTO_HW_PADDING, Self::TASK_ENABLE);
                core::ptr::write_volatile(Self::DIN_SRC_LLI_WORD0, data.as_ptr() as u32);
                core::ptr::write_volatile(Self::DIN_SRC_LLI_WORD1, data.len() as u32);
            }
            self.wait_interrupt(Self::INTERRUPT_MEM_TO_DIN)?;
            unsafe {
                core::ptr::write_volatile(Self::HOST_INTERRUPT_CLEAR, Self::INTERRUPT_MEM_TO_DIN);
            }
        }

        self.wait_ready()?;
        unsafe {
            core::ptr::write_volatile(Self::HASH_PADDING, Self::TASK_ENABLE);
            core::ptr::write_volatile(Self::HASH_AUTO_HW_PADDING, Self::TASK_DISABLE);
            core::ptr::write_volatile(Self::HASH_PAD_CONFIG, Self::TASK_DISABLE);
        }
        self.wait_crypto_ready()?;
        unsafe {
            core::ptr::write_volatile(Self::MISC_HASH_CLK_ENABLE, Self::TASK_DISABLE);
        }
        Ok(())
    }

    fn wait_ready(&self) -> Result<(), Cc310Error> {
        self.wait_hash_ready()?;
        self.wait_crypto_ready()?;
        self.wait_mem_dma_ready()
    }

    fn wait_hash_ready(&self) -> Result<(), Cc310Error> {
        self.wait_zero(Self::CTRL_HASH_BUSY)
    }

    fn wait_crypto_ready(&self) -> Result<(), Cc310Error> {
        self.wait_zero(Self::CTRL_CRYPTO_BUSY)
    }

    fn wait_mem_dma_ready(&self) -> Result<(), Cc310Error> {
        self.wait_zero(Self::DIN_MEM_DMA_BUSY)
    }

    fn wait_zero(&self, register: *const u32) -> Result<(), Cc310Error> {
        for _ in 0..Self::WAIT_SPINS {
            if unsafe { core::ptr::read_volatile(register) } & 1 == 0 {
                return Ok(());
            }
        }
        Err(Cc310Error::Timeout)
    }

    fn wait_interrupt(&self, mask: u32) -> Result<(), Cc310Error> {
        for _ in 0..Self::WAIT_SPINS {
            if unsafe { core::ptr::read_volatile(Self::HOST_INTERRUPTS) } & mask != 0 {
                return Ok(());
            }
        }
        Err(Cc310Error::Timeout)
    }

    fn clear_parts_scratch(&mut self) {
        for byte in &mut self.parts_scratch {
            unsafe { core::ptr::write_volatile(byte, 0) };
        }
    }
}

impl Sha256Backend for Cc310Sha256 {
    fn digest(&mut self, data: &[u8]) -> Result<[u8; 32], Sha256Error> {
        self.digest_direct(data)
            .map_err(|_| Sha256Error::HardwareUnavailable)
    }

    fn digest_parts(&mut self, parts: &[&[u8]]) -> Result<[u8; 32], Sha256Error> {
        let total_len = parts
            .iter()
            .try_fold(0usize, |total, part| total.checked_add(part.len()));
        let total_len = total_len
            .filter(|length| *length <= SHA256_PARTS_SCRATCH_LEN)
            .ok_or(Sha256Error::HardwareUnavailable)?;
        let mut offset = 0;
        for part in parts {
            self.parts_scratch[offset..offset + part.len()].copy_from_slice(part);
            offset += part.len();
        }

        let result = self
            .digest_direct(&self.parts_scratch[..total_len])
            .map_err(|_| Sha256Error::HardwareUnavailable);
        self.clear_parts_scratch();
        result
    }
}

#[cfg(feature = "client-pin-volatile")]
pub type SharedCc310Peripheral = critical_section::Mutex<RefCell<Cc310Sha256>>;

#[cfg(feature = "client-pin-volatile")]
#[derive(Clone, Copy)]
/// Serializes shared SHA access only; exclude other CryptoCell drivers and reentry.
pub struct SharedCc310Sha256 {
    shared: &'static SharedCc310Peripheral,
}

#[cfg(feature = "client-pin-volatile")]
impl SharedCc310Sha256 {
    pub const fn new(shared: &'static SharedCc310Peripheral) -> Self {
        Self { shared }
    }
}

#[cfg(feature = "client-pin-volatile")]
impl Sha256Backend for SharedCc310Sha256 {
    fn digest(&mut self, data: &[u8]) -> Result<[u8; 32], Sha256Error> {
        critical_section::with(|cs| self.shared.borrow_ref_mut(cs).digest(data))
    }

    fn digest_parts(&mut self, parts: &[&[u8]]) -> Result<[u8; 32], Sha256Error> {
        critical_section::with(|cs| self.shared.borrow_ref_mut(cs).digest_parts(parts))
    }
}
