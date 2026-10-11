// SPDX-License-Identifier: Apache-2.0





#![no_std]

// Experimental low-RAM integration, not a FIPS validation or a target stack-fit guarantee.
// Drop clears this wrapper's fields; it does not establish erasure of all C stack/register intermediates.

use core::ffi::c_int;
use zeroize::Zeroize;

pub const SEED_LEN: usize = 32;
pub const RANDOMNESS_LEN: usize = 32;
pub const PUBLIC_KEY_LEN: usize = 1_312;
pub const SECRET_KEY_LEN: usize = 2_560;
pub const SIGNATURE_LEN: usize = 2_420;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    BackendFailure,
    VerificationFailed,
}

pub struct NativeKeypair {
    public_key: [u8; PUBLIC_KEY_LEN],
    secret_key: [u8; SECRET_KEY_LEN],
    initialized: bool,
}

impl NativeKeypair {
    pub const fn empty() -> Self {
        Self {
            public_key: [0; PUBLIC_KEY_LEN],
            secret_key: [0; SECRET_KEY_LEN],
            initialized: false,
        }
    }


    pub fn regenerate(&mut self, seed: &[u8; SEED_LEN]) -> Result<(), Error> {
        self.zeroize();
        let result = unsafe {
            manekey_mldsa44_keypair_from_seed(
                self.public_key.as_mut_ptr(),
                self.secret_key.as_mut_ptr(),
                seed.as_ptr(),
            )
        };
        if result == 0 {
            self.initialized = true;
            Ok(())
        } else {
            self.zeroize();
            Err(Error::BackendFailure)
        }
    }

    pub fn from_seed(seed: &[u8; SEED_LEN]) -> Result<Self, Error> {
        let mut keypair = Self {
            public_key: [0; PUBLIC_KEY_LEN],
            secret_key: [0; SECRET_KEY_LEN],
            initialized: false,
        };
        let result = unsafe {
            manekey_mldsa44_keypair_from_seed(
                keypair.public_key.as_mut_ptr(),
                keypair.secret_key.as_mut_ptr(),
                seed.as_ptr(),
            )
        };
        if result == 0 {
            keypair.initialized = true;
            Ok(keypair)
        } else {
            keypair.zeroize();
            Err(Error::BackendFailure)
        }
    }

    pub fn public_key(&self) -> &[u8; PUBLIC_KEY_LEN] {
        &self.public_key
    }

    pub fn sign(
        &self,
        message: &[u8],
        randomness: &[u8; RANDOMNESS_LEN],
    ) -> Result<[u8; SIGNATURE_LEN], Error> {
        let mut signature = [0; SIGNATURE_LEN];
        self.sign_into(message, randomness, &mut signature)?;
        Ok(signature)
    }


    pub fn sign_into(
        &self,
        message: &[u8],
        randomness: &[u8; RANDOMNESS_LEN],
        signature: &mut [u8; SIGNATURE_LEN],
    ) -> Result<(), Error> {
        if !self.initialized {
            signature.zeroize();
            return Err(Error::BackendFailure);
        }
        let result = unsafe {
            manekey_mldsa44_sign(
                signature.as_mut_ptr(),
                message.as_ptr(),
                message.len(),
                randomness.as_ptr(),
                self.secret_key.as_ptr(),
            )
        };
        if result == 0 {
            Ok(())
        } else {
            signature.zeroize();
            Err(Error::BackendFailure)
        }
    }
}

impl Drop for NativeKeypair {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl Zeroize for NativeKeypair {
    fn zeroize(&mut self) {
        self.public_key.zeroize();
        self.secret_key.zeroize();
        self.initialized = false;
    }
}

pub fn verify(
    public_key: &[u8; PUBLIC_KEY_LEN],
    message: &[u8],
    signature: &[u8; SIGNATURE_LEN],
) -> Result<(), Error> {
    let result = unsafe {
        manekey_mldsa44_verify(
            signature.as_ptr(),
            message.as_ptr(),
            message.len(),
            public_key.as_ptr(),
        )
    };
    if result == 0 {
        Ok(())
    } else {
        Err(Error::VerificationFailed)
    }
}

unsafe extern "C" {
    fn manekey_mldsa44_keypair_from_seed(
        public_key: *mut u8,
        secret_key: *mut u8,
        seed: *const u8,
    ) -> c_int;
    fn manekey_mldsa44_sign(
        signature: *mut u8,
        message: *const u8,
        message_len: usize,
        randomness: *const u8,
        secret_key: *const u8,
    ) -> c_int;
    fn manekey_mldsa44_verify(
        signature: *const u8,
        message: *const u8,
        message_len: usize,
        public_key: *const u8,
    ) -> c_int;
}











































