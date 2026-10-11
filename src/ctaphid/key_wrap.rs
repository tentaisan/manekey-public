use aes_kw::{
    AesKw, InnerInit,
    cipher::{
        Block, BlockCipherDecBackend, BlockCipherDecClosure, BlockCipherDecrypt,
        BlockCipherEncBackend, BlockCipherEncClosure, BlockCipherEncrypt,
        common::{BlockSizeUser, ParBlocksSizeUser},
        inout::InOut,
        typenum::{U1, U16},
    },
};
use core::cell::{Cell, RefCell};
use zeroize::{Zeroize, Zeroizing};

/// Key-bound AES block backend; adapters own key selection and hardware exclusion.
pub trait OpaqueAes256Blocks {
    fn encrypt(&mut self, block: &mut [u8; 16]) -> Result<(), ()>;
    fn decrypt(&mut self, block: &mut [u8; 16]) -> Result<(), ()>;
}
#[derive(Debug, PartialEq, Eq)]
pub enum KeyWrapError {
    Length,
    Hardware,
    Integrity,
}
struct Cipher<'a, B> {
    backend: RefCell<&'a mut B>,
    failed: Cell<bool>,
}
impl<B> BlockSizeUser for Cipher<'_, B> {
    type BlockSize = U16;
}
impl<B> ParBlocksSizeUser for Cipher<'_, B> {
    type ParBlocksSize = U1;
}
impl<B: OpaqueAes256Blocks> Cipher<'_, B> {
    fn apply(&self, mut block: InOut<'_, '_, Block<Self>>, decrypt: bool) {
        let mut private = Zeroizing::new([0; 16]);
        private.copy_from_slice(block.get_in());
        let result = if self.failed.get() {
            Err(())
        } else if decrypt {
            self.backend.borrow_mut().decrypt(&mut private)
        } else {
            self.backend.borrow_mut().encrypt(&mut private)
        };
        if result.is_err() {
            self.failed.set(true);
            private.zeroize();
        }
        block.get_out().copy_from_slice(&private[..]);
    }
}
impl<B: OpaqueAes256Blocks> BlockCipherEncBackend for Cipher<'_, B> {
    fn encrypt_block(&self, block: InOut<'_, '_, Block<Self>>) {
        self.apply(block, false);
    }
}
impl<B: OpaqueAes256Blocks> BlockCipherDecBackend for Cipher<'_, B> {
    fn decrypt_block(&self, block: InOut<'_, '_, Block<Self>>) {
        self.apply(block, true);
    }
}
impl<B: OpaqueAes256Blocks> BlockCipherEncrypt for Cipher<'_, B> {
    fn encrypt_with_backend(&self, closure: impl BlockCipherEncClosure<BlockSize = U16>) {
        closure.call(self);
    }
}
impl<B: OpaqueAes256Blocks> BlockCipherDecrypt for Cipher<'_, B> {
    fn decrypt_with_backend(&self, closure: impl BlockCipherDecClosure<BlockSize = U16>) {
        closure.call(self);
    }
}

/// RFC3394 wrapping; backend failures erase output, length errors may leave it unchanged.
pub fn wrap<B: OpaqueAes256Blocks>(
    backend: &mut B,
    input: &[u8],
    output: &mut [u8],
) -> Result<usize, KeyWrapError> {
    let len = input.len().checked_add(8).ok_or(KeyWrapError::Length)?;
    if input.len() < 16 || input.len() % 8 != 0 || output.len() < len {
        return Err(KeyWrapError::Length);
    }
    let cipher = Cipher {
        backend: RefCell::new(backend),
        failed: Cell::new(false),
    };
    let kw = AesKw::inner_init(&cipher);
    let result = kw.wrap_key(input, &mut output[..len]);
    if cipher.failed.get() {
        output.zeroize();
        return Err(KeyWrapError::Hardware);
    }
    result.map(|_| len).map_err(|_| KeyWrapError::Length)
}
/// RFC3394 unwrapping with 64-bit integrity; hardware/integrity failures erase output.
/// Length errors do not promise erasure; this does not prevent rollback.
pub fn unwrap<B: OpaqueAes256Blocks>(
    backend: &mut B,
    input: &[u8],
    output: &mut [u8],
) -> Result<usize, KeyWrapError> {
    if input.len() < 24 || input.len() % 8 != 0 || output.len() < input.len() - 8 {
        return Err(KeyWrapError::Length);
    }
    let len = input.len() - 8;
    let cipher = Cipher {
        backend: RefCell::new(backend),
        failed: Cell::new(false),
    };
    let kw = AesKw::inner_init(&cipher);
    let result = kw.unwrap_key(input, &mut output[..len]).map(|_| len);
    if cipher.failed.get() {
        output.zeroize();
        return Err(KeyWrapError::Hardware);
    }
    if result.is_err() {
        output.zeroize();
        return Err(KeyWrapError::Integrity);
    }
    result.map_err(|_| KeyWrapError::Integrity)
}
