
use manekey::ctaphid::crypto::{Aes256BlockBackend, Aes256Error};
use zeroize::Zeroize;

unsafe extern "C" {
    fn manekey_sce5_aes256(key: *mut u32, input: *mut u32, output: *mut u32, decrypt: u32) -> u32;
}

pub struct SceAes256;

impl SceAes256 {
    fn apply(
        &mut self,
        key: &[u8; 32],
        block: &mut [u8; 16],
        decrypt: bool,
    ) -> Result<(), Aes256Error> {
        if !crate::entropy::sce_ready() {
            block.zeroize();
            return Err(Aes256Error::HardwareUnavailable);
        }
        let mut key_words = [0u32; 8];
        let mut input = [0u32; 4];
        let mut output = [0u32; 4];
        for (dst, src) in key_words.iter_mut().zip(key.chunks_exact(4)) {
            *dst = u32::from_le_bytes(src.try_into().unwrap());
        }
        for (dst, src) in input.iter_mut().zip(block.chunks_exact(4)) {
            *dst = u32::from_le_bytes(src.try_into().unwrap());
        }
        // Aligned, bounded private copies; C cannot retain caller pointers.
        let status = crate::entropy::with_sce(|| unsafe {
            manekey_sce5_aes256(
                key_words.as_mut_ptr(),
                input.as_mut_ptr(),
                output.as_mut_ptr(),
                decrypt as u32,
            )
        });
        key_words.zeroize();
        input.zeroize();
        block.zeroize();
        if status == Some(0) {
            for (dst, word) in block.chunks_exact_mut(4).zip(output.iter()) {
                dst.copy_from_slice(&word.to_le_bytes());
            }
        }
        output.zeroize();
        if status == Some(0) {
            Ok(())
        } else {
            Err(Aes256Error::HardwareUnavailable)
        }
    }
}

impl Aes256BlockBackend for SceAes256 {
    fn encrypt_block(&mut self, key: &[u8; 32], block: &mut [u8; 16]) -> Result<(), Aes256Error> {
        self.apply(key, block, false)
    }
    fn decrypt_block(&mut self, key: &[u8; 32], block: &mut [u8; 16]) -> Result<(), Aes256Error> {
        self.apply(key, block, true)
    }
}
