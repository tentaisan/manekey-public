
use manekey::ctaphid::crypto::Aes256Error;
use zeroize::Zeroizing;

unsafe extern "C" {
    fn manekey_sce5_wrap256(key: *mut u32, index: *mut u32) -> u32;
    fn manekey_sce5_wrapped256(
        index: *mut u32,
        input: *mut u32,
        output: *mut u32,
        decrypt: u32,
    ) -> u32;
}

pub struct WrappedAes256 {
    index: Zeroizing<[u32; 16]>,
}
#[cfg(feature = "hardware-wrapped-keys")]
impl manekey::ctaphid::key_wrap::OpaqueAes256Blocks for WrappedAes256 {
    fn encrypt(&mut self, block: &mut [u8; 16]) -> Result<(), ()> {
        self.apply(block, false).map_err(|_| ())
    }
    fn decrypt(&mut self, block: &mut [u8; 16]) -> Result<(), ()> {
        self.apply(block, true).map_err(|_| ())
    }
}
impl WrappedAes256 {
    pub fn wrap(key: &[u8; 32]) -> Result<Self, Aes256Error> {
        if !crate::entropy::sce_ready() {
            return Err(Aes256Error::HardwareUnavailable);
        }
        let mut private = Zeroizing::new(core::array::from_fn::<_, 8, _>(|i| {
            u32::from_le_bytes(key[i * 4..i * 4 + 4].try_into().unwrap())
        }));
        let mut index = Zeroizing::new([0; 16]);
        if crate::entropy::with_sce(|| unsafe {
            manekey_sce5_wrap256(private.as_mut_ptr(), index.as_mut_ptr())
        }) != Some(0)
        {
            return Err(Aes256Error::HardwareUnavailable);
        }
        Ok(Self { index })
    }
    pub fn from_blob(blob: &[u8; 64]) -> Self {
        Self {
            index: Zeroizing::new(core::array::from_fn(|i| {
                u32::from_le_bytes(blob[i * 4..i * 4 + 4].try_into().unwrap())
            })),
        }
    }
    pub fn blob(&self) -> Zeroizing<[u8; 64]> {
        let mut blob = Zeroizing::new([0; 64]);
        for (i, word) in self.index.iter().enumerate() {
            blob[i * 4..i * 4 + 4].copy_from_slice(&word.to_le_bytes());
        }
        blob
    }
    pub fn apply(&mut self, block: &mut [u8; 16], decrypt: bool) -> Result<(), Aes256Error> {
        use zeroize::Zeroize;
        let mut input = Zeroizing::new(core::array::from_fn::<_, 4, _>(|i| {
            u32::from_le_bytes(block[i * 4..i * 4 + 4].try_into().unwrap())
        }));
        let mut output = Zeroizing::new([0; 4]);
        let status = crate::entropy::with_sce(|| unsafe {
            manekey_sce5_wrapped256(
                self.index.as_mut_ptr(),
                input.as_mut_ptr(),
                output.as_mut_ptr(),
                decrypt as u32,
            )
        });
        block.zeroize();
        if status != Some(0) {
            return Err(Aes256Error::HardwareUnavailable);
        }
        for (dst, word) in block.chunks_exact_mut(4).zip(output.iter()) {
            dst.copy_from_slice(&word.to_le_bytes());
        }
        Ok(())
    }
}
