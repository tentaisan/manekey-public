// Modified for product packaging: documentation and test-only code omitted.
use crate::types::Ph;
use rand_core::{CryptoRng, CryptoRngCore, RngCore};
#[cfg(feature = "default-rng")]
use rand_core::OsRng;



pub trait KeyGen {


    type PublicKey;



    type PrivateKey;



























    #[cfg(feature = "default-rng")]
    fn try_keygen() -> Result<(Self::PublicKey, Self::PrivateKey), &'static str> {
        Self::try_keygen_with_rng(&mut OsRng)
    }





























    fn try_keygen_with_rng(
        rng: &mut impl CryptoRngCore,
    ) -> Result<(Self::PublicKey, Self::PrivateKey), &'static str>;

































    #[must_use]
    fn keygen_from_seed(xi: &[u8; 32]) -> (Self::PublicKey, Self::PrivateKey);
}



pub trait Signer {

    type Signature;


    type PublicKey;































    #[cfg(feature = "default-rng")]
    fn try_sign(&self, message: &[u8], ctx: &[u8]) -> Result<Self::Signature, &'static str> {
        self.try_sign_with_rng(&mut OsRng, message, ctx)
    }

































    fn try_sign_with_rng(
        &self, rng: &mut impl CryptoRngCore, message: &[u8], ctx: &[u8],
    ) -> Result<Self::Signature, &'static str>;

































    fn try_sign_with_seed(
        &self, seed: &[u8; 32], message: &[u8], ctx: &[u8],
    ) -> Result<Self::Signature, &'static str> {
        self.try_sign_with_rng(&mut DummyRng {data: *seed}, message, ctx)
    }













    #[cfg(feature = "default-rng")]
    fn try_hash_sign(
        &self, message: &[u8], ctx: &[u8], ph: &Ph,
    ) -> Result<Self::Signature, &'static str> {
        self.try_hash_sign_with_rng(&mut OsRng, message, ctx, ph)
    }













    fn try_hash_sign_with_rng(
        &self, rng: &mut impl CryptoRngCore, message: &[u8], ctx: &[u8], ph: &Ph,
    ) -> Result<Self::Signature, &'static str>;












    fn try_hash_sign_with_seed(
        &self, seed: &[u8;32], message: &[u8], ctx: &[u8], ph: &Ph,
    ) -> Result<Self::Signature, &'static str> {
        self.try_hash_sign_with_rng(&mut DummyRng {data: *seed}, message, ctx, ph)
    }






















    fn get_public_key(&self) -> Self::PublicKey;
}

// This is for the deterministic signing functions; will be refactored more nicely
struct DummyRng { data: [u8; 32] }

impl RngCore for DummyRng {
    fn next_u32(&mut self) -> u32 { unimplemented!() }

    fn next_u64(&mut self) -> u64 { unimplemented!() }

    fn fill_bytes(&mut self, _out: &mut [u8]) { unimplemented!() }

    fn try_fill_bytes(&mut self, out: &mut [u8]) -> Result<(), rand_core::Error> {
        out.copy_from_slice(&self.data);
        Ok(())
    }
}

impl CryptoRng for DummyRng {}



pub trait Verifier {


    type Signature;






















    fn verify(&self, message: &[u8], signature: &Self::Signature, ctx: &[u8]) -> bool;




    fn hash_verify(&self, message: &[u8], sig: &Self::Signature, ctx: &[u8], ph: &Ph) -> bool;
}









pub trait SerDes {

    type ByteArray;





















    fn into_bytes(self) -> Self::ByteArray;
























    fn try_from_bytes(ba: Self::ByteArray) -> Result<Self, &'static str>
    where
        Self: Sized;
}
