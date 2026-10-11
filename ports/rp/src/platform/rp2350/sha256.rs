use manekey::ctaphid::hash::{Sha256Backend, Sha256Error};

/// Exclusive RP2350 SHA-256 MMIO backend with bounded spin waits.
pub struct Rp2350Sha256;

impl Rp2350Sha256 {
    const BASE: usize = 0x400f_8000;
    const CSR: *mut u32 = Self::BASE as *mut u32;
    const WDATA: *mut u32 = (Self::BASE + 0x04) as *mut u32;
    const SUM0: *const u32 = (Self::BASE + 0x08) as *const u32;
    const CSR_START: u32 = 1 << 0;
    const CSR_WDATA_RDY: u32 = 1 << 1;
    const CSR_SUM_VLD: u32 = 1 << 2;
    const CSR_ERR_WDATA_NOT_RDY: u32 = 1 << 4;
    const CSR_DMA_SIZE_32BIT: u32 = 2 << 8;
    const CSR_BSWAP: u32 = 1 << 12;
    const READY_SPINS: usize = 10_000;

    /// # Safety
    /// Enable peripheral clock/reset and access rights in this domain; exclude all competing tasks, cores, IRQs and DMA.
    pub unsafe fn new_unchecked() -> Self {
        Self
    }

    fn wait_for(mask: u32) -> Result<(), Sha256Error> {
        for _ in 0..Self::READY_SPINS {
            let csr = unsafe { core::ptr::read_volatile(Self::CSR) };
            if csr & Self::CSR_ERR_WDATA_NOT_RDY != 0 {
                return Err(Sha256Error::HardwareUnavailable);
            }
            if csr & mask == mask {
                return Ok(());
            }
        }
        Err(Sha256Error::HardwareUnavailable)
    }

    fn write_block(block: &[u8; 64]) -> Result<(), Sha256Error> {
        Self::wait_for(Self::CSR_WDATA_RDY)?;
        for chunk in block.chunks_exact(4) {
            let word = u32::from_le_bytes(chunk.try_into().expect("chunk is 4 bytes"));

            unsafe { core::ptr::write_volatile(Self::WDATA, word) };
        }
        Self::wait_for(Self::CSR_SUM_VLD)
    }
}

impl Sha256Backend for Rp2350Sha256 {
    fn digest(&mut self, data: &[u8]) -> Result<[u8; 32], Sha256Error> {
        self.digest_parts(&[data])
    }

    fn digest_parts(&mut self, parts: &[&[u8]]) -> Result<[u8; 32], Sha256Error> {
        unsafe {
            core::ptr::write_volatile(
                Self::CSR,
                Self::CSR_START | Self::CSR_DMA_SIZE_32BIT | Self::CSR_BSWAP,
            );
        }
        Self::wait_for(Self::CSR_WDATA_RDY | Self::CSR_SUM_VLD)?;

        manekey::ctaphid::hash::for_each_sha256_block(parts, Self::write_block)?;

        let mut digest = [0u8; 32];
        for (index, chunk) in digest.chunks_exact_mut(4).enumerate() {
            let word = unsafe { core::ptr::read_volatile(Self::SUM0.add(index)) };
            chunk.copy_from_slice(&word.to_be_bytes());
        }
        Ok(digest)
    }
}
