use sha2::{Digest, Sha256};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Sha256Error {
    HardwareUnavailable,
}

/// SHA-256 backend; adapters own hardware exclusion. Default multipart hashing is unsupported.
pub trait Sha256Backend {
    fn digest(&mut self, data: &[u8]) -> Result<[u8; 32], Sha256Error>;

    fn digest_parts(&mut self, parts: &[&[u8]]) -> Result<[u8; 32], Sha256Error> {
        match parts {
            [data] => self.digest(data),
            _ => Err(Sha256Error::HardwareUnavailable),
        }
    }
}

/// Emits padded blocks until the sink fails; temporary blocks are not guaranteed erased.
pub fn for_each_sha256_block<E>(
    parts: &[&[u8]],
    mut write: impl FnMut(&[u8; 64]) -> Result<(), E>,
) -> Result<(), E> {
    let mut block = [0u8; 64];
    let mut used = 0;
    let mut total = 0u64;
    for part in parts {
        total = total.wrapping_add(part.len() as u64);
        let mut input = *part;
        while !input.is_empty() {
            let length = (64 - used).min(input.len());
            block[used..used + length].copy_from_slice(&input[..length]);
            used += length;
            input = &input[length..];
            if used == 64 {
                write(&block)?;
                used = 0;
                block.fill(0);
            }
        }
    }
    block[used] = 0x80;
    if used >= 56 {
        write(&block)?;
        block.fill(0);
    }
    block[56..].copy_from_slice(&total.wrapping_mul(8).to_be_bytes());
    write(&block)
}

#[derive(Clone, Copy, Debug, Default)]
pub struct SoftwareSha256;

impl Sha256Backend for SoftwareSha256 {
    fn digest(&mut self, data: &[u8]) -> Result<[u8; 32], Sha256Error> {
        Ok(Sha256::digest(data).into())
    }

    fn digest_parts(&mut self, parts: &[&[u8]]) -> Result<[u8; 32], Sha256Error> {
        let mut hasher = Sha256::new();
        for part in parts {
            hasher.update(part);
        }
        Ok(hasher.finalize().into())
    }
}

/// Product startup compatibility checks, not cryptographic validation or certification.
pub fn verify_sha256_backend<B: Sha256Backend>(backend: &mut B) -> Result<(), Sha256Error> {
    for data in [b"".as_slice(), b"abc".as_slice()] {
        if backend.digest(data)? != sha256_digest(data) {
            return Err(Sha256Error::HardwareUnavailable);
        }
    }
    let input = [0xa5; 1025];
    for length in [0, 1, 55, 56, 63, 64, 65, 127, 128, 129, 1023, 1024, 1025] {
        let data = &input[..length];
        let expected = sha256_digest(data);
        if backend.digest(data)? != expected {
            return Err(Sha256Error::HardwareUnavailable);
        }
        for split in [0, length / 2, length] {
            if backend.digest_parts(&[&data[..split], &[], &data[split..]])? != expected {
                return Err(Sha256Error::HardwareUnavailable);
            }
        }
    }
    Ok(())
}

pub fn sha256_digest(data: &[u8]) -> [u8; 32] {
    SoftwareSha256
        .digest(data)
        .expect("software SHA-256 backend is infallible")
}

pub fn sha256_digest_parts(parts: &[&[u8]]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    for part in parts {
        hasher.update(part);
    }
    hasher.finalize().into()
}
