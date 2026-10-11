// Modified for product packaging: documentation and test-only code omitted.
// Modified from fips204 0.4.6 for experimental scratch-workspace integration.
#![no_std]
#![deny(clippy::pedantic, warnings,               unsafe_code)]
// Almost all of the 'allow' category...
#![deny(absolute_paths_not_starting_with_crate, dead_code)]
#![deny(elided_lifetimes_in_paths, explicit_outlives_requirements, keyword_idents)]
#![deny(let_underscore_drop, macro_use_extern_crate, meta_variable_misuse, missing_abi)]
#![deny(non_ascii_idents, rust_2021_incompatible_closure_captures)]
#![deny(rust_2021_incompatible_or_patterns, rust_2021_prefixes_incompatible_syntax)]
#![deny(rust_2021_prelude_collisions, single_use_lifetimes, trivial_casts)]
#![deny(trivial_numeric_casts, unreachable_pub, unsafe_op_in_unsafe_fn, unstable_features)]
#![deny(unused_extern_crates, unused_import_braces, unused_lifetimes, unused_macro_rules)]
#![deny(unused_qualifications, unused_results, variant_size_differences)]
//



// Experimental scratch-workspace fork; not a validated cryptographic module.
// RNG and seed quality are caller responsibilities. Returned secret encodings and
// intermediate copies are not covered by the key/workspace object's zeroization.


// Implements FIPS 204 Module-Lattice-Based Digital Signature Standard.
// See <https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.204.pdf>

// Functionality map per FIPS 204
//
// Algorithm 1 ML-DSA.KeyGen() on page 17                   --> from lib.rs to ml_dsa.rs
// Algorithm 2 ML-DSA.Sign(sk,M,ctx) on page 18             --> lib.rs
// Algorithm 3 ML-DSA.Verify(pk,M,s,ctx) on page 18         --> lib.rs
// Algorithm 4 HashML-DSA.Sign(sk,M,ctx,PH) on page 20      --> lib.rs
// Algorithm 5 HashML-DSA.Verify(sk,M,s,ctx,PH) on page 21  --> lib.rs
// Algorithm 6 ML-DSA.KeyGen_internal(x) on page 23         --> ml_dsa.rs
// Algorithm 7 ML-DSA.Sign_internal(sk,M',rnd) on page 25   --> ml_dsa.rs
// Algorithm 8 ML-DSA.Verify_internal(pk,M',s) on page 27   --> ml_dsa.rs
// Algorithm 9 IntegerToBits(x,a) one page 28               --> (optimized away) conversion.rs
// Algorithm 10 BitsToInteger(y,a) on page 28               --> (optimized away) conversion.rs
// Algorithm 11 IntegerToBytes(x,a) on page 28              --> (optimized away) conversion.rs
// Algorithm 12 BitsToBytes(y) on page 29                   --> (optimized away) conversion.rs
// Algorithm 13 BytesToBits(z) on page 29                   --> (optimized away) conversion.rs
// Algorithm 14 CoefFromThreeBytes(b0,b1,b2) on page 29     --> conversion.rs
// Algorithm 15 CoefFromHalfByte(b) on page 30              --> conversion.rs
// Algorithm 16 SimpleBitPack(w,b) on page 30               --> conversion.rs
// Algorithm 17 BitPack(w,a,b) on page 30                   --> conversion.rs
// Algorithm 18 SimpleBitUnpack(v,b) on page 31             --> conversion.rs
// Algorithm 19 BitUnpack(v,a,b) on page 31                 --> conversion.rs
// Algorithm 20 HintBitPack(h) on page 32                   --> conversion.rs
// Algorithm 21 HintBitUnpack(y) on page 32                 --> conversion.rs
// Algorithm 22 pkEncode(ρ,t1) on page 33                   --> encodings.rs
// Algorithm 23 pkDecode(pk) on page 33                     --> encodings.rs
// Algorithm 24 skEncode(ρ,K,tr,s1,s2,t0) on page 34        --> encodings.rs
// Algorithm 25 skDecode(sk) on page 34                     --> encodings.rs
// Algorithm 26 sigEncode(c˜,z,h) on page 35                --> encodings.rs
// Algorithm 27 sigDecode(σ) on page 35                     --> encodings.rs
// Algorithm 28 w1Encode(w1) on page 35                     --> encodings.rs
// Algorithm 29 SampleInBall(ρ) on page 36                  --> hashing.rs
// Algorithm 30 RejNTTPoly(ρ) on page 37                    --> hashing.rs
// Algorithm 31 RejBoundedPoly(ρ) on page 37                --> hashing.rs
// Algorithm 32 ExpandA(ρ) on page 38                       --> hashing.rs
// Algorithm 33 ExpandS(ρ) on page 38                       --> hashing.rs
// Algorithm 34 ExpandMask(ρ,µ) on page 38                  --> hashing.rs
// Algorithm 35 Power2Round(r) on page 40                   --> high_low.rs
// Algorithm 36 Decompose(r) on page 40                     --> high_low.rs
// Algorithm 37 HighBits(r) on page 40                      --> high_low.rs
// Algorithm 38 LowBits(r) on page 41                       --> high_low.rs
// Algorithm 39 MakeHint(z,r) on page 41                    --> high_low.rs
// Algorithm 40 UseHint(h,r) on page 41                     --> high_low.rs
// Algorithm 41 NTT(w) on page 43                           --> ntt.rs
// Algorithm 42 NTT−1(wˆ) on page 44                        --> ntt.rs
// Algorithm 43 BitRev8(m) on page 44                       --> not needed to to zeta table
// Algorithm 44 AddNTT(a,b)̂ on page 45                      --> helpers.rs within 46:AddVectorNTT
// Algorithm 45 MultiplyNTT(a,b)̂ on page 45                 --> helpers.rs
// Algorithm 46 AddVectorNTT(v,w) on page 45                --> helpers.rs
// Algorithm 47 ScalarVectorNTT(c,v)̂ on page 46             --> not implemented standalone
// Algorithm 48 MatrixVectorNTT(M,v) on page 46             --> not implemented standalone
// Algorithm 49 MontgomeryReduce(a) on page 50              --> helpers.rs
// Types are in types.rs, traits are in traits.rs...

// Note that debug_assert! statements enforce correct program construction and are not involved
// in any operational dataflow (so are good fuzz targets). The ensure! statements implement
// conservative dataflow validation and do not panic. Separately, functions are only generic
// over security parameters that are directly involved in memory allocation (on the stack).
// Some coding oddities are driven by 'clippy pedantic' and the fact that Rust doesn't currently
// do well with arithmetic on generic parameters.

// Operational entrypoints use CTEST=false and retain normal rejection sampling.
// This selection does not certify constant-time execution on every target.



pub use rand_core::{CryptoRng, Error as RngError, RngCore};

mod conversion;
mod encodings;
mod hashing;
mod helpers;
mod high_low;
mod ml_dsa;
mod ntt;
mod types;


pub mod traits;
pub use crate::types::Ph;

// Applies across all security parameter sets
const Q: i32 = 8_380_417; // 2^23 - 2^13 + 1 = 0x7FE001; page 15 table 1 first row
const ZETA: i32 = 1753; // See section 2.5 of FIPS 204; page 15 table 1 second row
const D: u32 = 13; // See page 15 table 1 third row


// This common functionality is injected into each security parameter set namespace, and is
// largely a lightweight wrapper into the ml_dsa functions.
macro_rules! functionality {
    () => {
        use crate::encodings;
        use crate::hashing;
        use crate::helpers;
        use crate::ml_dsa;
        use crate::ntt;
        use crate::traits::{KeyGen, SerDes, Signer, Verifier};
        use crate::types;
        use rand_core::CryptoRngCore;
        use zeroize::{Zeroize, ZeroizeOnDrop};

        use crate::{D, Q};
        const BETA: i32 = TAU * ETA;
        const LAMBDA_DIV4: usize = LAMBDA / 4;
        const W1_LEN: usize = 32 * K * helpers::bit_length((Q - 1) / (2 * GAMMA2) - 1);
        const CTEST: bool = false; // When true, the logic goes into CT test mode


        // ----- 'EXTERNAL' DATA TYPES -----



        #[derive(Zeroize, ZeroizeOnDrop)]
        pub struct KG();






        // Note: #[derive(Zeroize, ZeroizeOnDrop)] is implemented on the underlying struct.
        pub type PrivateKey = crate::types::PrivateKey<K, L>;






        // Note: #[derive(Zeroize, ZeroizeOnDrop)] is implemented on the underlying struct.
        pub type PublicKey = crate::types::PublicKey<K, L>;


        pub type KeyGenScratch = crate::types::KeyGenScratch<K, L>;


        pub type SignScratch = crate::types::SignScratch<K, L>;


        // Note: (public) Signature is just a vanilla fixed-size byte array


        // ----- PRIMARY FUNCTIONS ---































        #[cfg(feature = "default-rng")]
        pub fn try_keygen() -> Result<(PublicKey, PrivateKey), &'static str> { KG::try_keygen() }


































        pub fn try_keygen_with_rng(rng: &mut impl CryptoRngCore) -> Result<(PublicKey, PrivateKey), &'static str> {
            KG::try_keygen_with_rng(rng)
        }





        #[must_use]
        pub fn keygen_from_seed_with_scratch(
            xi: &[u8; 32], scratch: &mut KeyGenScratch,
        ) -> (PublicKey, PrivateKey) {
            ml_dsa::key_gen_internal_with_scratch::<CTEST, K, L, PK_LEN, SK_LEN>(
                ETA, xi, scratch,
            )
        }




        #[must_use]
        pub fn keygen_from_seed_with_sign_scratch(
            xi: &[u8; 32], scratch: &mut SignScratch,
        ) -> (PublicKey, PrivateKey) {
            ml_dsa::key_gen_internal_with_sign_scratch::<CTEST, K, L, PK_LEN, SK_LEN>(
                ETA, xi, scratch,
            )
        }





        pub fn try_sign_with_seed_and_scratch(
            private_key: &PrivateKey, seed: &[u8; 32], message: &[u8], ctx: &[u8],
            scratch: &mut SignScratch,
        ) -> Result<[u8; SIG_LEN], &'static str> {
            helpers::ensure!(ctx.len() < 256, "ML-DSA.Sign: ctx too long");
            Ok(ml_dsa::sign_internal_with_scratch::<
                CTEST, K, L, LAMBDA_DIV4, SIG_LEN, SK_LEN, W1_LEN,
            >(
                BETA, GAMMA1, GAMMA2, OMEGA, TAU, private_key, message, ctx, &[], &[], *seed,
                false, scratch,
            ))
        }


        impl KeyGen for KG {
            type PrivateKey = PrivateKey;
            type PublicKey = PublicKey;



            fn try_keygen_with_rng(rng: &mut impl CryptoRngCore) -> Result<(PublicKey, PrivateKey), &'static str> {
                let (pk, sk) = ml_dsa::key_gen::<CTEST, K, L, PK_LEN, SK_LEN>(rng, ETA)?;
                Ok((pk, sk))
            }


            fn keygen_from_seed(xi: &[u8; 32]) -> (Self::PublicKey, Self::PrivateKey) {
                let (pk, sk) = ml_dsa::key_gen_internal::<CTEST, K, L, PK_LEN, SK_LEN>(ETA, xi);
                (pk, sk)
            }
        }

















































        impl Signer for PrivateKey {
            type Signature = [u8; SIG_LEN];
            type PublicKey = PublicKey;











            fn try_sign_with_rng(
                &self, rng: &mut impl CryptoRngCore, message: &[u8], ctx: &[u8],
            ) -> Result<Self::Signature, &'static str> {
                // 1: if |ctx| > 255 then
                // 2:   return ⊥    ▷ return an error indication if the context string is too long
                // 3: end if
                helpers::ensure!(ctx.len() < 256, "ML-DSA.Sign: ctx too long");

                // 4:  (blank line in spec)

                // 5: rnd ← 𝔹^{32}     ▷ for the optional deterministic variant, substitute rnd ← {0}^32
                // 6: if rnd = NULL then
                // 7:   return ⊥    ▷ return an error indication if random bit generation failed
                // 8: end if
                let mut rnd = [0u8; 32];
                rng.try_fill_bytes(&mut rnd).map_err(|_| "ML-DSA.Sign: random number generator failed")?;

                // 9:  (blank line in spec)

                // Note: step 10 is done within sign_internal() and 'below'
                // 10: 𝑀 ′ ← BytesToBits(IntegerToBytes(0, 1) ∥ IntegerToBytes(|𝑐𝑡𝑥|, 1) ∥ 𝑐𝑡𝑥) ∥ 𝑀
                // 11: 𝜎 ← ML-DSA.Sign_internal(𝑠𝑘, 𝑀 ′ , 𝑟𝑛𝑑)
                let sig = ml_dsa::sign_internal::<CTEST, K, L, LAMBDA_DIV4, SIG_LEN, SK_LEN, W1_LEN>(
                    BETA, GAMMA1, GAMMA2, OMEGA, TAU, &self, message, ctx, &[], &[], rnd, false
                );

                // 12: return 𝜎
                Ok(sig)
            }













            fn try_hash_sign_with_rng(
                &self, rng: &mut impl CryptoRngCore, message: &[u8], ctx: &[u8], ph: &types::Ph,
            ) -> Result<Self::Signature, &'static str> {
                // 1: if |ctx| > 255 then
                // 2:   return ⊥    ▷ return an error indication if the context string is too long
                // 3: end if
                helpers::ensure!(ctx.len() < 256, "HashML-DSA.Sign: ctx too long");

                // 4:  (blank line in spec)

                // 5: rnd ← 𝔹^{32}     ▷ for the optional deterministic variant, substitute rnd ← {0}^32
                // 6: if rnd = NULL then
                // 7:   return ⊥    ▷ return an error indication if random bit generation failed
                // 8: end if
                let mut rnd = [0u8; 32];
                rng.try_fill_bytes(&mut rnd).map_err(|_| "HashML-DSA.Sign: random number generator failed")?;

                // 9:  (blank line in spec)

                // Note: steps 10-22 are performed within `hash_message()` below
                let mut phm = [0u8; 64];  // hashers don't all play well with each other
                let (oid, phm_len) = hashing::hash_message(message, ph, &mut phm);

                // Note: step 23 is performed within `sign_internal()` and below.
                // 23: 𝑀 ′ ← BytesToBits(IntegerToBytes(1, 1) ∥ IntegerToBytes(|𝑐𝑡𝑥|, 1) ∥ 𝑐𝑡𝑥 ∥ OID ∥ PH𝑀 )
                // 24: 𝜎 ← ML-DSA.Sign_internal(𝑠𝑘, 𝑀 ′ , 𝑟𝑛𝑑)
                let sig = ml_dsa::sign_internal::<CTEST, K, L, LAMBDA_DIV4, SIG_LEN, SK_LEN, W1_LEN>(
                    BETA, GAMMA1, GAMMA2, OMEGA, TAU, &self, message, ctx, &oid, &phm[0..phm_len], rnd, false
                );

                // 25: return 𝜎
                Ok(sig)
            }


            // Documented in traits.rs
            #[allow(clippy::cast_lossless)]
            fn get_public_key(&self) -> Self::PublicKey {
                ml_dsa::private_to_public_key(&self)
            }
        }


        impl Verifier for PublicKey {
            type Signature = [u8; SIG_LEN];









            fn verify(&self, message: &[u8], sig: &Self::Signature, ctx: &[u8]) -> bool {
                // 1: if |ctx| > 255 then
                // 2:   return ⊥    ▷ return an error indication if the context string is too long
                // 3: end if
                if ctx.len() > 255 {
                    return false;
                };

                // 4:  (blank line in spec)

                // Note: step 5 is performed within `verify_internal()` and below.
                // 5: 𝑀′ ← BytesToBits(IntegerToBytes(0, 1) ∥ IntegerToBytes(|ctx|, 1) ∥ ctx) ∥ 𝑀
                // 6: return ML-DSA.Verify_internal(pk, 𝑀′, 𝜎)
                ml_dsa::verify_internal::<CTEST, K, L, LAMBDA_DIV4, PK_LEN, SIG_LEN, W1_LEN>(
                    BETA, GAMMA1, GAMMA2, OMEGA, TAU, &self, &message, &sig, ctx, &[], &[], false
                )
            }










            fn hash_verify(&self, message: &[u8], sig: &Self::Signature, ctx: &[u8], ph: &types::Ph) -> bool {
                // 1: if |ctx| > 255 then
                // 2:   return ⊥    ▷ return an error indication if the context string is too long
                // 3: end if
                if ctx.len() > 255 {
                    return false;
                };

                // 4:  (blank line in spec)

                // Note: steps 5-17 are performed within `hash_message()` below
                let mut phm = [0u8; 64];  // hashers don't all play well with each other
                let (oid, phm_len) = hashing::hash_message(message, ph, &mut phm);

                // Note: step 18 is performed within `verify_internal()` and below.
                // 18: 𝑀′ ← BytesToBits(IntegerToBytes(1, 1) ∥ IntegerToBytes(|ctx|, 1) ∥ ctx ∥ OID ∥ PH𝑀 )
                // 19: return ML-DSA.Verify_internal(𝑝𝑘, 𝑀′ , 𝜎)
                ml_dsa::verify_internal::<CTEST, K, L, LAMBDA_DIV4, PK_LEN, SIG_LEN, W1_LEN>(
                    BETA, GAMMA1, GAMMA2, OMEGA, TAU, &self, &message, &sig, ctx, &oid, &phm[0..phm_len], false
                )
            }
        }


        // ----- SERIALIZATION AND DESERIALIZATION ---

        impl SerDes for PrivateKey {
            type ByteArray = [u8; SK_LEN];


            fn try_from_bytes(sk: Self::ByteArray) -> Result<Self, &'static str> {
                let esk = ml_dsa::expand_private::<K, L, SK_LEN>(ETA, &sk)?;
                Ok(esk)
            }


            fn into_bytes(self) -> Self::ByteArray {
                // Extract the pre-computes
                let PrivateKey {rho, cap_k, tr, s_1_hat_mont: s_hat_1_mont, s_2_hat_mont: s_hat_2_mont, t_0_hat_mont: t_hat_0_mont, ..} = &self;

                // mont->norm each n coeff, of L entries of T, then inverse NTT
                let s_1: [types::R; L] = ntt::inv_ntt(
                    &core::array::from_fn(|l|
                        types::T(core::array::from_fn(|n|
                            helpers::mont_reduce(i64::from(s_hat_1_mont[l].0[n]))))));
                // correct each coeff such that they are centered around 0
                let s_1: [types::R; L] =
                    core::array::from_fn(|l|
                        types::R(core::array::from_fn(|n|
                            if s_1[l].0[n] > (Q / 2) {s_1[l].0[n] - Q} else {s_1[l].0[n]})));

                let s_2: [types::R; K] = ntt::inv_ntt(
                    &core::array::from_fn(|k|
                        types::T(core::array::from_fn(|n|
                            helpers::mont_reduce(i64::from(s_hat_2_mont[k].0[n]))))));
                let s_2: [types::R; K] =
                    core::array::from_fn(|k|
                        types::R(core::array::from_fn(|n|
                            if s_2[k].0[n] > (Q / 2) {s_2[k].0[n] - Q} else {s_2[k].0[n]})));


                let t_0: [types::R; K] = ntt::inv_ntt(
                    &core::array::from_fn(|k|
                        types::T(core::array::from_fn(|n|
                            helpers::mont_reduce(i64::from(t_hat_0_mont[k].0[n]))))));
                let t_0: [types::R; K] =
                    core::array::from_fn(|k|
                        types::R(core::array::from_fn(|n|
                            if t_0[k].0[n] > (Q / 2) {t_0[k].0[n] - Q} else {t_0[k].0[n]})));

                // Encode and return
                encodings::sk_encode::<K, L, SK_LEN>(ETA, rho, cap_k, tr, &s_1, &s_2, &t_0)
            }
        }


        impl SerDes for PublicKey {
            type ByteArray = [u8; PK_LEN];


            fn try_from_bytes(pk: Self::ByteArray) -> Result<Self, &'static str> {
                let epk = ml_dsa::expand_public(&pk)?;
                Ok(epk)

            }


            fn into_bytes(self) -> Self::ByteArray {
                // Extract the pre-computes
                let PublicKey {rho, tr: _tr, t1_d2_hat_mont} = &self;

                // reconstruct t1_d2 then t1
                let t1_d2: [types::R; K] = ntt::inv_ntt(
                    &core::array::from_fn(|k|
                        types::T(core::array::from_fn(|n|
                            helpers::mont_reduce(i64::from(t1_d2_hat_mont[k].0[n]))))));

                let t1: [types::R; K] = core::array::from_fn(|k|
                    types::R(core::array::from_fn(|n|
                        t1_d2[k].0[n] >> D)));

                encodings::pk_encode(rho, &t1)
             }
        }






















































































































    };
}























#[cfg(feature = "ml-dsa-44")]
pub mod ml_dsa_44 {
    const TAU: i32 = 39;
    const LAMBDA: usize = 128;
    const GAMMA1: i32 = 1 << 17;
    const GAMMA2: i32 = (Q - 1) / 88;
    const K: usize = 4;
    const L: usize = 4;
    const ETA: i32 = 2;
    const OMEGA: i32 = 80;

    pub const SK_LEN: usize = 2560;

    pub const PK_LEN: usize = 1312;

    pub const SIG_LEN: usize = 2420;

    functionality!();
}























#[cfg(feature = "ml-dsa-65")]
pub mod ml_dsa_65 {
    const TAU: i32 = 49;
    const LAMBDA: usize = 192;
    const GAMMA1: i32 = 1 << 19;
    const GAMMA2: i32 = (Q - 1) / 32;
    const K: usize = 6;
    const L: usize = 5;
    const ETA: i32 = 4;
    const OMEGA: i32 = 55;

    pub const SK_LEN: usize = 4032;

    pub const PK_LEN: usize = 1952;

    pub const SIG_LEN: usize = 3309;

    functionality!();
}























#[cfg(feature = "ml-dsa-87")]
pub mod ml_dsa_87 {
    const TAU: i32 = 60;
    const LAMBDA: usize = 256;
    const GAMMA1: i32 = 1 << 19;
    const GAMMA2: i32 = (Q - 1) / 32;
    const K: usize = 8;
    const L: usize = 7;
    const ETA: i32 = 2;
    const OMEGA: i32 = 75;

    pub const SK_LEN: usize = 4896;

    pub const PK_LEN: usize = 2592;

    pub const SIG_LEN: usize = 4627;

    functionality!();
}
