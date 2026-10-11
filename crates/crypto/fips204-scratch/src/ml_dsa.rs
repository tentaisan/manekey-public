// Modified for product packaging: documentation and test-only code omitted.
// Modified from fips204 0.4.6 for experimental scratch-workspace integration.
// This file implements functionality from FIPS 204 sections 6/7: Key Generation, Signing, Verification

use crate::encodings::{pk_decode, pk_encode, sig_decode, sig_encode, sk_decode, w1_encode};
use crate::hashing::{
    expand_a, expand_a_into, expand_mask, expand_mask_into, expand_s_into, h256_xof, sample_in_ball,
};
use crate::helpers::{
    add_vector_ntt, center_mod, full_reduce32, infinity_norm, mat_vec_mul, mat_vec_mul_into,
    mont_reduce, partial_reduce32, to_mont, to_mont_in_place,
};
use crate::high_low::{high_bits, low_bits, make_hint, power2round, use_hint};
use crate::ntt::{inv_ntt, inv_ntt_into, ntt, ntt_into};
use crate::types::{KeyGenScratch, PrivateKey, PublicKey, R, SignScratch, T, T0};
use crate::{D, Q};
use rand_core::CryptoRngCore;
use sha3::digest::XofReader;











pub(crate) fn key_gen<
    const CTEST: bool,
    const K: usize,
    const L: usize,
    const PK_LEN: usize,
    const SK_LEN: usize,
>(
    rng: &mut impl CryptoRngCore, eta: i32,
) -> Result<(PublicKey<K, L>, PrivateKey<K, L>), &'static str> {
    //
    // 1: ξ ← B^{32}    ▷ Choose random seed
    // 2: if ξ = NULL then
    // 3:   return ⊥    ▷ return an error indication if random bit generation failed
    // 4: end if
    let mut xi = [0u8; 32];
    rng.try_fill_bytes(&mut xi).map_err(|_| "KeyGen: Random number generator failed")?;

    // 5: return ML-DSA.KeyGen_internal(𝜉)
    Ok(key_gen_internal::<CTEST, K, L, PK_LEN, SK_LEN>(eta, &xi))
}











pub(crate) fn key_gen_internal<
    const CTEST: bool,
    const K: usize,
    const L: usize,
    const PK_LEN: usize,
    const SK_LEN: usize,
>(
    eta: i32, xi: &[u8; 32],
) -> (PublicKey<K, L>, PrivateKey<K, L>) {
    let mut scratch = KeyGenScratch::new();
    key_gen_internal_with_scratch::<CTEST, K, L, PK_LEN, SK_LEN>(eta, xi, &mut scratch)
}


pub(crate) fn key_gen_internal_with_scratch<
    const CTEST: bool,
    const K: usize,
    const L: usize,
    const PK_LEN: usize,
    const SK_LEN: usize,
>(eta: i32, xi: &[u8; 32], scratch: &mut KeyGenScratch<K, L>) -> (PublicKey<K, L>, PrivateKey<K, L>) {
    key_gen_internal_with_parts::<CTEST, K, L, PK_LEN, SK_LEN>(
        eta,
        xi,
        KeyGenScratchParts {
            cap_a_hat: &mut scratch.cap_a_hat,
            s_1: &mut scratch.s_1,
            s_2: &mut scratch.s_2,
            s_1_hat: &mut scratch.s_1_hat,
            work_hat: &mut scratch.work_hat,
            work: &mut scratch.work,
        },
    )
}


struct KeyGenScratchParts<'a, const K: usize, const L: usize> {
    cap_a_hat: &'a mut [[T; L]; K],
    s_1: &'a mut [R; L],
    s_2: &'a mut [R; K],
    s_1_hat: &'a mut [T; L],
    work_hat: &'a mut [T; K],
    work: &'a mut [R; K],
}

fn key_gen_internal_with_parts<
    const CTEST: bool,
    const K: usize,
    const L: usize,
    const PK_LEN: usize,
    const SK_LEN: usize,
>(
    eta: i32, xi: &[u8; 32], mut scratch: KeyGenScratchParts<'_, K, L>,
) -> (PublicKey<K, L>, PrivateKey<K, L>) {
    //
    // 1: (rho, rho′, 𝐾) ∈ 𝔹^{32} × 𝔹^{64} × 𝔹^{32} ← H(𝜉||IntegerToBytes(𝑘,1)||IntegerToBytes(ℓ,1),128)
    let mut h2 = h256_xof(&[xi, &[K.to_le_bytes()[0]], &[L.to_le_bytes()[0]]]);
    let mut rho = [0u8; 32];
    h2.read(&mut rho);
    let mut rho_prime = [0u8; 64];
    h2.read(&mut rho_prime);
    let mut cap_k = [0u8; 32];
    h2.read(&mut cap_k);

    // There is effectively no step 2 due to formatting error in spec

    // 4: (s_1, s_2) ← ExpandS(ρ′)
    expand_s_into::<CTEST, K, L>(eta, &rho_prime, &mut scratch.s_1, &mut scratch.s_2);

    // 3: cap_a_hat ← ExpandA(ρ)    ▷ A is generated and stored in NTT representation as Â
    // 5: t ← NTT−1(cap_a_hat ◦ NTT(s_1)) + s_2    ▷ Compute t = As1 + s2
    // 6: (t_1, t_0) ← Power2Round(t, d)    ▷ Compress t
    expand_a_into::<CTEST, K, L>(&rho, &mut scratch.cap_a_hat);
    ntt_into(&scratch.s_1, &mut scratch.s_1_hat);
    mat_vec_mul_into(&scratch.cap_a_hat, &scratch.s_1_hat, &mut scratch.work_hat);
    inv_ntt_into(&scratch.work_hat, &mut scratch.work);
    for (t_not_reduced, s_2) in scratch.work.iter_mut().zip(scratch.s_2.iter()) {
        for (coefficient, s_2_coefficient) in t_not_reduced.0.iter_mut().zip(&s_2.0) {
            *coefficient = full_reduce32(*coefficient + *s_2_coefficient);
        }
    }
    let (t_1, t_0): ([R; K], [R; K]) = power2round(&scratch.work);

    // There is effectively no step 7 due to formatting error in spec

    // 8: pk ← pkEncode(ρ, t_1)
    // 9: tr ← H(BytesToBits(pk), 64)
    let mut tr = [0u8; 64];
    let mut h8 = h256_xof(&[&pk_encode::<K, PK_LEN>(&rho, &t_1)]);
    h8.read(&mut tr);

    // 10: sk ← skEncode(ρ, K, tr, s_1, s_2, t_0)     ▷ K and tr are for use in signing
    // The sk struct has pre-computes rather than byte array; see deserialize process for latter

    // Precompute the last term of algorithm 8 `Verify()` step 9 on page 27
    // 9: 𝐰Approx ← NTT (𝐀 ∘ NTT(𝐳) − NTT(𝑐) ∘ NTT(𝐭1 ⋅ 2𝑑 ))    ▷ 𝐰Approx = 𝐀𝐳 − 𝑐𝐭1 ⋅ 2𝑑
    ntt_into(&t_1, &mut scratch.work_hat);
    to_mont_in_place(&mut scratch.work_hat);
    for polynomial in scratch.work_hat.iter_mut() {
        for coefficient in &mut polynomial.0 {
            *coefficient = mont_reduce(i64::from(*coefficient) << D);
        }
    }
    to_mont_in_place(&mut scratch.work_hat);
    let t1_d2_hat_mont = core::mem::replace(scratch.work_hat, [T0; K]);

    // Now we have everything we need for public key struct
    let pk = PublicKey { rho, tr, t1_d2_hat_mont };

    // Now we shift to Algorithm 7 `Sign()` on page 25

    // 2: s_1_hat ← NTT(s_1)
    ntt_into(&scratch.s_1, &mut scratch.s_1_hat);
    to_mont_in_place(&mut scratch.s_1_hat);
    let s_1_hat_mont = core::mem::replace(scratch.s_1_hat, [T0; L]);

    // 3: s_2_hat ← NTT(s_2)
    ntt_into(&scratch.s_2, &mut scratch.work_hat);
    to_mont_in_place(&mut scratch.work_hat);
    let s_2_hat_mont = core::mem::replace(scratch.work_hat, [T0; K]);

    // 4: t_0_hat ← NTT(t_0)
    ntt_into(&t_0, &mut scratch.work_hat);
    to_mont_in_place(&mut scratch.work_hat);
    let t_0_hat_mont = core::mem::replace(scratch.work_hat, [T0; K]);

    // Now we have everything we need for private key struct
    let sk = PrivateKey { rho, cap_k, tr, s_1_hat_mont, s_2_hat_mont, t_0_hat_mont };

    // 11: return (pk, sk)
    (pk, sk)
}





pub(crate) fn key_gen_internal_with_sign_scratch<
    const CTEST: bool,
    const K: usize,
    const L: usize,
    const PK_LEN: usize,
    const SK_LEN: usize,
>(eta: i32, xi: &[u8; 32], scratch: &mut SignScratch<K, L>) -> (PublicKey<K, L>, PrivateKey<K, L>) {
    key_gen_internal_with_parts::<CTEST, K, L, PK_LEN, SK_LEN>(
        eta,
        xi,
        KeyGenScratchParts {
            cap_a_hat: &mut scratch.cap_a_hat,
            s_1: &mut scratch.y,
            s_2: &mut scratch.h,
            s_1_hat: &mut scratch.l_hat,
            work_hat: &mut scratch.k_hat,
            work: &mut scratch.work,
        },
    )
}








// Note the M' is assembled here from provided elements, rather than by caller.
// Further, a deserialized private key struct has a variety of pre-computed
// elements ready-to-go.
#[allow(
    clippy::similar_names,
    clippy::many_single_char_names,
    clippy::too_many_arguments,
    clippy::too_many_lines
)]
pub(crate) fn sign_internal<
    const CTEST: bool,
    const K: usize,
    const L: usize,
    const LAMBDA_DIV4: usize,
    const SIG_LEN: usize,
    const SK_LEN: usize,
    const W1_LEN: usize,
>(
    beta: i32, gamma1: i32, gamma2: i32, omega: i32, tau: i32, esk: &PrivateKey<K, L>,
    message: &[u8], ctx: &[u8], oid: &[u8], phm: &[u8], rnd: [u8; 32], nist: bool,
) -> [u8; SIG_LEN] {
    //
    // 1: (ρ, K, tr, s_1, s_2, t_0) ← skDecode(sk)
    // --> calculated in `expand_private()` near the bottom of this file
    // Extract elements from private key
    let PrivateKey { rho, cap_k, tr, s_1_hat_mont, s_2_hat_mont, t_0_hat_mont } = esk;
    //
    // 2: s_1_hat ← NTT(s_1)
    // --> the montgomery form is extracted from the private key struct above
    //
    // 3: s_2_hat ← NTT(s_2)
    // --> the montgomery form is extracted from the private key struct above
    //
    // 4: t_0_hat ← NTT(t_0)
    // --> the montgomery form is extracted from the private key struct above
    //
    // 5: cap_a_hat ← ExpandA(ρ)    ▷ A is generated and stored in NTT representation as Â
    let cap_a_hat: [[T; L]; K] = expand_a::<CTEST, K, L>(rho);

    // 6: 𝜇 ← H(BytesToBits(𝑡𝑟)||𝑀 , 64)    ▷ Compute message representative µ
    // Calculate mu based on which of the three different paths led us here
    let mut h6 = if nist {
        // 6a. NIST vectors are being applied to "internal" functions
        h256_xof(&[tr, message])
    } else if oid.is_empty() {
        // 6b. From ML-DSA.Sign():  𝑀′ ← BytesToBits(IntegerToBytes(0,1) ∥ IntegerToBytes(|𝑐𝑡𝑥|,1) ∥ 𝑐𝑡𝑥) ∥ 𝑀
        h256_xof(&[tr, &[0u8], &[ctx.len().to_le_bytes()[0]], ctx, message])
    } else {
        // 6c. From HashML-DSA.Sign(): 𝑀′ ← BytesToBits(IntegerToBytes(1,1) ∥ IntegerToBytes(|𝑐𝑡𝑥|,1) ∥ 𝑐𝑡𝑥 ∥ OID ∥ PH𝑀 )
        h256_xof(&[tr, &[1u8], &[ctx.len().to_le_bytes()[0]], ctx, oid, phm])
    };
    let mut mu = [0u8; 64];
    h6.read(&mut mu);

    // 7: ρ′' ← H(K || rnd || µ, 64)    ▷ Compute private random seed
    let mut h7 = h256_xof(&[cap_k, &rnd, &mu]);
    let mut rho_prime = [0u8; 64];
    h7.read(&mut rho_prime);

    // 8: κ ← 0    ▷ Initialize counter κ
    let mut kappa_ctr = 0u16;

    // 9: (z, h) ← ⊥    ▷ we will handle ⊥ inline with 'continue'
    let mut z: [R; L];
    let mut h: [R; K];
    let mut c_tilde = [0u8; LAMBDA_DIV4];

    // 10: while (z, h) = ⊥ do    ▷ Rejection sampling loop (with continue for ⊥)
    loop {
        //
        // 11: y ← ExpandMask(ρ′', κ)
        let y: [R; L] = expand_mask(gamma1, &rho_prime, kappa_ctr);

        // 12: w ← NTT−1(cap_a_hat ◦ NTT(y))
        let w: [R; K] = {
            let y_hat: [T; L] = ntt(&y);
            let ay_hat: [T; K] = mat_vec_mul(&cap_a_hat, &y_hat);
            inv_ntt(&ay_hat)
        };

        // 13: w_1 ← HighBits(w)    ▷ Signer’s commitment
        let w_1: [R; K] =
            core::array::from_fn(|k| R(core::array::from_fn(|n| high_bits(gamma2, w[k].0[n]))));

        // There is effectively no step 14 due to formatting oddity in spec

        // 15: c_tildẽ ← H(mu||w1Encode(w_1), 𝜆/4)    ▷ commitment hash
        let mut w1_tilde = [0u8; W1_LEN];
        w1_encode::<K>(gamma2, &w_1, &mut w1_tilde);
        let mut h15 = h256_xof(&[&mu, &w1_tilde]);
        h15.read(&mut c_tilde);

        // 16: c ∈ 𝑅𝑞 ← SampleInBall(c_tilde_1)    ▷ Verifier’s challenge
        let c: R = sample_in_ball::<CTEST>(tau, &c_tilde);

        // 17: c_hat ← NTT(c)
        let c_hat: &T = &ntt(&[c])[0];

        // 18: ⟨⟨c_s_1⟩⟩ ← NTT−1(c_hat ◦ s_1_hat)
        let c_s_1: [R; L] = {
            let cs1_hat: [T; L] = core::array::from_fn(|l| {
                T(core::array::from_fn(|n| {
                    mont_reduce(i64::from(c_hat.0[n]) * i64::from(s_1_hat_mont[l].0[n]))
                }))
            });
            inv_ntt(&cs1_hat)
        };

        // 19: ⟨⟨c_s_2⟩⟩ ← NTT−1(c_hat ◦ s_2_hat)
        let c_s_2: [R; K] = {
            let cs2_hat: [T; K] = core::array::from_fn(|k| {
                T(core::array::from_fn(|n| {
                    mont_reduce(i64::from(c_hat.0[n]) * i64::from(s_2_hat_mont[k].0[n]))
                }))
            });
            inv_ntt(&cs2_hat)
        };

        // 20: z ← y + ⟨⟨c_s_1⟩⟩    ▷ Signer’s response
        z = core::array::from_fn(|l| {
            R(core::array::from_fn(|n| partial_reduce32(y[l].0[n] + c_s_1[l].0[n])))
        });

        // 21: r0 ← LowBits(w − ⟨⟨c_s_2⟩⟩)
        let r0: [R; K] = core::array::from_fn(|k| {
            R(core::array::from_fn(|n| {
                low_bits(gamma2, partial_reduce32(w[k].0[n] - c_s_2[k].0[n]))
            }))
        });

        // There is effectively no step 22 due to formatting oddity in spec

        // 23: if ||z||∞ ≥ Gamma1 − β or ||r0||∞ ≥ Gamma2 − β then (z, h) ← ⊥    ▷ Validity checks
        let z_norm = infinity_norm(&z);
        let r0_norm = infinity_norm(&r0);
        // CTEST is used only for constant-time measurements via `dudect`
        if !CTEST && ((z_norm >= (gamma1 - beta)) || (r0_norm >= (gamma2 - beta))) {
            kappa_ctr += u16::try_from(L).expect("cannot fail; L is static parameter");
            continue;
            //
            // 24: else  ... not needed with 'continue'
        }

        // 25: ⟨⟨c_t_0⟩⟩ ← NTT−1(c_hat ◦ t_hat_0)
        let c_t_0: [R; K] = {
            let ct0_hat: [T; K] = core::array::from_fn(|k| {
                T(core::array::from_fn(|n| {
                    mont_reduce(i64::from(c_hat.0[n]) * i64::from(t_0_hat_mont[k].0[n]))
                }))
            });
            inv_ntt(&ct0_hat)
        };

        // 26: h ← MakeHint(−⟨⟨c_t_0⟩⟩, w − ⟨⟨c_s_2⟩⟩ + ⟨⟨c_t_0⟩⟩)    ▷ Signer’s hint
        h = core::array::from_fn(|k| {
            R(core::array::from_fn(|n| {
                i32::from(make_hint(
                    gamma2,
                    Q - c_t_0[k].0[n], // no reduce
                    partial_reduce32(w[k].0[n] - c_s_2[k].0[n] + c_t_0[k].0[n]),
                ))
            }))
        });

        // There is effectively no step 22 due to formatting error in spec

        // 28: if ||⟨⟨c_t_0⟩⟩||∞ ≥ Gamma2 or the number of 1’s in h is greater than ω, then (z, h) ← ⊥
        // CTEST is used only for constant-time measurements via `dudect`
        if !CTEST
            && ((infinity_norm(&c_t_0) >= gamma2)
                || (h.iter().map(|h_i| h_i.0.iter().sum::<i32>()).sum::<i32>() > omega))
        {
            kappa_ctr += u16::try_from(L).expect("cannot fail; L is static parameter");
            continue;
            // 29: end if
        }

        // 30: end if  (not needed as ⊥-related logic uses continue

        // 31: κ ← κ + ℓ ▷ Increment counter
        // this is done just prior to each of the 'continue' statements above

        // if we made it here, we passed the 'continue' conditions, so have a solution
        break;

        // 32: end while
    }

    // 33: σ ← sigEncode(c_tilde, z mod± q, h)
    // 34: return σ
    let zmodq: [R; L] =
        core::array::from_fn(|l| R(core::array::from_fn(|n| center_mod(z[l].0[n]))));
    sig_encode::<CTEST, K, L, LAMBDA_DIV4, SIG_LEN>(gamma1, omega, &c_tilde, &zmodq, &h)
}


#[allow(clippy::similar_names, clippy::too_many_arguments, clippy::too_many_lines)]
pub(crate) fn sign_internal_with_scratch<
    const CTEST: bool,
    const K: usize,
    const L: usize,
    const LAMBDA_DIV4: usize,
    const SIG_LEN: usize,
    const SK_LEN: usize,
    const W1_LEN: usize,
>(
    beta: i32, gamma1: i32, gamma2: i32, omega: i32, tau: i32, esk: &PrivateKey<K, L>,
    message: &[u8], ctx: &[u8], oid: &[u8], phm: &[u8], rnd: [u8; 32], nist: bool,
    scratch: &mut SignScratch<K, L>,
) -> [u8; SIG_LEN] {
    let PrivateKey { rho, cap_k, tr, s_1_hat_mont, s_2_hat_mont, t_0_hat_mont } = esk;
    expand_a_into::<CTEST, K, L>(rho, &mut scratch.cap_a_hat);

    let mut h6 = if nist {
        h256_xof(&[tr, message])
    } else if oid.is_empty() {
        h256_xof(&[tr, &[0u8], &[ctx.len().to_le_bytes()[0]], ctx, message])
    } else {
        h256_xof(&[tr, &[1u8], &[ctx.len().to_le_bytes()[0]], ctx, oid, phm])
    };
    let mut mu = [0u8; 64];
    h6.read(&mut mu);
    let mut h7 = h256_xof(&[cap_k, &rnd, &mu]);
    let mut rho_prime = [0u8; 64];
    h7.read(&mut rho_prime);
    let mut kappa_ctr = 0u16;
    let mut c_tilde = [0u8; LAMBDA_DIV4];

    loop {
        expand_mask_into(gamma1, &rho_prime, kappa_ctr, &mut scratch.y);
        ntt_into(&scratch.y, &mut scratch.l_hat);
        mat_vec_mul_into(&scratch.cap_a_hat, &scratch.l_hat, &mut scratch.k_hat);
        inv_ntt_into(&scratch.k_hat, &mut scratch.w);

        for (w_1, w) in scratch.w_1.iter_mut().zip(&scratch.w) {
            for (out, coefficient) in w_1.0.iter_mut().zip(&w.0) {
                *out = high_bits(gamma2, *coefficient);
            }
        }
        let mut w1_tilde = [0u8; W1_LEN];
        w1_encode::<K>(gamma2, &scratch.w_1, &mut w1_tilde);
        let mut h15 = h256_xof(&[&mu, &w1_tilde]);
        h15.read(&mut c_tilde);

        scratch.w_1[0] = sample_in_ball::<CTEST>(tau, &c_tilde);
        ntt_into(
            core::array::from_ref(&scratch.w_1[0]),
            core::array::from_mut(&mut scratch.c_hat),
        );
        for (out, secret) in scratch.l_hat.iter_mut().zip(s_1_hat_mont) {
            for (n, coefficient) in out.0.iter_mut().enumerate() {
                *coefficient = mont_reduce(i64::from(scratch.c_hat.0[n]) * i64::from(secret.0[n]));
            }
        }
        inv_ntt_into(&scratch.l_hat, &mut scratch.z);

        for (out, secret) in scratch.k_hat.iter_mut().zip(s_2_hat_mont) {
            for (n, coefficient) in out.0.iter_mut().enumerate() {
                *coefficient = mont_reduce(i64::from(scratch.c_hat.0[n]) * i64::from(secret.0[n]));
            }
        }
        inv_ntt_into(&scratch.k_hat, &mut scratch.c_s_2);
        for (z, y) in scratch.z.iter_mut().zip(&scratch.y) {
            for (out, y_coefficient) in z.0.iter_mut().zip(&y.0) {
                *out = partial_reduce32(*y_coefficient + *out);
            }
        }

        for ((out, w), c_s_2) in scratch.work.iter_mut().zip(&scratch.w).zip(&scratch.c_s_2) {
            for ((coefficient, w_coefficient), c_s_2_coefficient) in out.0.iter_mut().zip(&w.0).zip(&c_s_2.0) {
                *coefficient = low_bits(gamma2, partial_reduce32(*w_coefficient - *c_s_2_coefficient));
            }
        }
        if !CTEST && ((infinity_norm(&scratch.z) >= (gamma1 - beta)) || (infinity_norm(&scratch.work) >= (gamma2 - beta))) {
            kappa_ctr += u16::try_from(L).expect("cannot fail; L is static parameter");
            continue;
        }

        for (out, secret) in scratch.k_hat.iter_mut().zip(t_0_hat_mont) {
            for (n, coefficient) in out.0.iter_mut().enumerate() {
                *coefficient = mont_reduce(i64::from(scratch.c_hat.0[n]) * i64::from(secret.0[n]));
            }
        }
        inv_ntt_into(&scratch.k_hat, &mut scratch.work);
        for (((h, w), c_s_2), c_t_0) in scratch.h.iter_mut().zip(&scratch.w).zip(&scratch.c_s_2).zip(&scratch.work) {
            for (((out, w_coefficient), c_s_2_coefficient), c_t_0_coefficient) in h.0.iter_mut().zip(&w.0).zip(&c_s_2.0).zip(&c_t_0.0) {
                *out = i32::from(make_hint(gamma2, Q - *c_t_0_coefficient, partial_reduce32(*w_coefficient - *c_s_2_coefficient + *c_t_0_coefficient)));
            }
        }
        if !CTEST && ((infinity_norm(&scratch.work) >= gamma2) || (scratch.h.iter().map(|h_i| h_i.0.iter().sum::<i32>()).sum::<i32>() > omega)) {
            kappa_ctr += u16::try_from(L).expect("cannot fail; L is static parameter");
            continue;
        }
        break;
    }

    for z in &mut scratch.z {
        for coefficient in &mut z.0 {
            *coefficient = center_mod(*coefficient);
        }
    }
    sig_encode::<CTEST, K, L, LAMBDA_DIV4, SIG_LEN>(gamma1, omega, &c_tilde, &scratch.z, &scratch.h)
}









// Note the M' is assembled here from provided elements, rather than by caller.
// Further, a deserialized public key struct has a variety of pre-computed
// elements ready-to-go.
#[allow(clippy::too_many_arguments, clippy::similar_names, clippy::type_complexity)]
pub(crate) fn verify_internal<
    const CTEST: bool,
    const K: usize,
    const L: usize,
    const LAMBDA_DIV4: usize,
    const PK_LEN: usize,
    const SIG_LEN: usize,
    const W1_LEN: usize,
>(
    beta: i32, gamma1: i32, gamma2: i32, omega: i32, tau: i32, epk: &PublicKey<K, L>, m: &[u8],
    sig: &[u8; SIG_LEN], ctx: &[u8], oid: &[u8], phm: &[u8], nist: bool,
) -> bool {
    //
    // 1: (ro, t_1) ← pkDecode(pk)  pull out pre-computed elements
    let PublicKey { rho, tr, t1_d2_hat_mont } = epk;

    // 2: (c_tilde, z, h) ← sigDecode(σ)    ▷ Signer’s commitment hash c_tilde, response z and hint h
    let Ok((c_tilde, z, h)): Result<([u8; LAMBDA_DIV4], [R; L], Option<[R; K]>), &'static str> =
        sig_decode(gamma1, omega, sig)
    else {
        return false;
    };

    // 3: if h = ⊥ then return false     ▷ Hint was not properly encoded
    // 4: end if
    let Some(h) = h else { return false };

    debug_assert!(infinity_norm(&z) <= gamma1, "Alg 8: i_norm out of range"); // Fuzz target


    // 6: tr ← H(pk, 64)
    // --> extracted from public key pre-computes in step 1 above

    // 7: 𝜇 ← (H(BytesToBits(tr)||𝑀′, 64))    ▷ Compute message representative µ
    // Calculate mu based on which of the three different paths led us here
    let mut h7 = if nist {
        // 7a. NIST vectors are being applied to "internal" functions
        h256_xof(&[tr, m])
    } else if oid.is_empty() {
        // 7b. From ML-DSA.Verify(): 5: 𝑀′ ← BytesToBits(IntegerToBytes(0,1) ∥ IntegerToBytes(|𝑐𝑡𝑥|,1) ∥ 𝑐𝑡𝑥) ∥ 𝑀
        h256_xof(&[tr, &[0u8], &[ctx.len().to_le_bytes()[0]], ctx, m])
    } else {
        // 7c. From HashML-DSA.Verify(): 18: 𝑀′ ← BytesToBits(IntegerToBytes(1,1) ∥ IntegerToBytes(|𝑐𝑡𝑥|,1) ∥ 𝑐𝑡𝑥 ∥ OID ∥ PH𝑀 )
        h256_xof(&[tr, &[1u8], &[ctx.len().to_le_bytes()[0]], ctx, oid, phm])
    };
    let mut mu = [0u8; 64];
    h7.read(&mut mu);

    // 8: c ∈ 𝑅𝑞 ← SampleInBall(c_tilde_1)    ▷ Compute verifier’s challenge from c_tilde
    let c: R = sample_in_ball::<false>(tau, &c_tilde); // CTEST is always false (as no CT guarantees)

    // 5: cap_a_hat ← ExpandA(ρ)    ▷ A is generated and stored in NTT representation as cap_A_hat
    // 9: w′_Approx ← invNTT(cap_A_hat ◦ NTT(z) - NTT(c) ◦ NTT(t_1 · 2^d)    ▷ w′_Approx = Az − ct1·2^d
    let wp_approx: [R; K] = {
        // CTEST is always false (as no CT guarantees); from step 5 above
        let cap_a_hat: [[T; L]; K] = expand_a::<CTEST, K, L>(rho);
        let z_hat: [T; L] = ntt(&z);
        let az_hat: [T; K] = mat_vec_mul(&cap_a_hat, &z_hat);
        // NTT(t_1 · 2^d) --> extracted from public key struct
        let c_hat: &T = &ntt(&[c])[0];
        inv_ntt(&core::array::from_fn(|k| {
            T(core::array::from_fn(|n| {
                az_hat[k].0[n]
                    - mont_reduce(i64::from(c_hat.0[n]) * i64::from(t1_d2_hat_mont[k].0[n]))
            }))
        }))
    };

    // 10: w′_1 ← UseHint(h, w′_Approx)    ▷ Reconstruction of signer’s commitment
    let wp_1: [R; K] = core::array::from_fn(|k| {
        R(core::array::from_fn(|n| use_hint(gamma2, h[k].0[n], wp_approx[k].0[n])))
    });

    // There is effectively no step 11 due to formatting oddity in spec

    // 12: c_tilde_′ ← H(µ || w1Encode(w′_1), λ/4)     ▷ Hash it; this should match c_tilde
    let mut tmp = [0u8; W1_LEN];
    w1_encode::<K>(gamma2, &wp_1, &mut tmp);
    let mut h12 = h256_xof(&[&mu, &tmp]);
    let mut c_tilde_p = [0u8; LAMBDA_DIV4];
    h12.read(&mut c_tilde_p);

    // 13: return [[ ||z||∞ < γ1 −β]] and [[c_tilde = c_tilde_′]]
    let left = infinity_norm(&z) < (gamma1 - beta);
    let right = c_tilde == c_tilde_p; // verify() is not CT
    left && right
}







pub(crate) fn expand_private<const K: usize, const L: usize, const SK_LEN: usize>(
    eta: i32, sk: &[u8; SK_LEN],
) -> Result<PrivateKey<K, L>, &'static str> {
    //
    // 1: (ρ, K, tr, s_1, s_2, t_0) ← skDecode(sk)
    let (rho, cap_k, tr, s_1, s_2, t_0) = sk_decode(eta, sk)?;

    // 2: s_hat_1 ← NTT(s_1)
    let s_1_hat_mont: [T; L] = to_mont(&ntt(&s_1));

    // 3: s_hat_2 ← NTT(s_2)
    let s_2_hat_mont: [T; K] = to_mont(&ntt(&s_2));

    // 4: t_hat_0 ← NTT(t_0)
    let t_0_hat_mont: [T; K] = to_mont(&ntt(&t_0));

    Ok(PrivateKey {
        rho: *rho,
        cap_k: *cap_k,
        tr: *tr,
        s_1_hat_mont,
        s_2_hat_mont,
        t_0_hat_mont,
    })
}







pub(crate) fn expand_public<const K: usize, const L: usize, const PK_LEN: usize>(
    pk: &[u8; PK_LEN],
) -> Result<PublicKey<K, L>, &'static str> {
    //
    // 1: (ρ,t_1) ← pkDecode(pk)
    let (rho, t_1): (&[u8; 32], [R; K]) = pk_decode(pk)?;


    // 6: tr ← H(pk, 64)
    let mut h6 = h256_xof(&[pk]);
    let mut tr = [0u8; 64];
    h6.read(&mut tr);

    // the last term of:
    // 9: 𝐰Approx ← NTT (𝐀 ∘ NTT(𝐳) − NTT(𝑐) ∘ NTT(𝐭1 ⋅ 2𝑑 ))    ▷ 𝐰Approx = 𝐀𝐳 − 𝑐𝐭1 ⋅ 2𝑑
    let t1_hat_mont: [T; K] = to_mont(&ntt(&t_1));
    let t1_d2_hat_mont: [T; K] = to_mont(&core::array::from_fn(|k| {
        T(core::array::from_fn(|n| mont_reduce(i64::from(t1_hat_mont[k].0[n]) << D)))
    }));

    Ok(PublicKey { rho: *rho, tr, t1_d2_hat_mont })
}



pub(crate) fn private_to_public_key<const K: usize, const L: usize>(
    sk: &PrivateKey<K, L>,
) -> PublicKey<K, L> {
    // Extract the pre-computes
    let PrivateKey { rho, cap_k: _, tr, s_1_hat_mont, s_2_hat_mont, t_0_hat_mont } = sk;

    let cap_a_hat: [[T; L]; K] = expand_a::<false, K, L>(rho);

    // mont->norm elements to recover s_1_hat
    let s_1_hat: [T; L] = core::array::from_fn(|l| {
        T(core::array::from_fn(|n| mont_reduce(i64::from(s_1_hat_mont[l].0[n]))))
    });

    // mont->norm each n coeff, of L entries of T, then inverse NTT into R
    let s_2: [R; K] = inv_ntt(&core::array::from_fn(|k| {
        T(core::array::from_fn(|n| mont_reduce(i64::from(s_2_hat_mont[k].0[n]))))
    }));
    // correct each coeff such that they are centered around 0
    let s_2: [R; K] = core::array::from_fn(|k| {
        R(core::array::from_fn(|n| {
            if s_2[k].0[n] > (Q / 2) {
                s_2[k].0[n] - Q
            } else {
                s_2[k].0[n]
            }
        }))
    });

    let t_0: [R; K] = inv_ntt(&core::array::from_fn(|k| {
        T(core::array::from_fn(|n| mont_reduce(i64::from(t_0_hat_mont[k].0[n]))))
    }));
    let sk_t_0: [R; K] = core::array::from_fn(|k| {
        R(core::array::from_fn(|n| {
            if t_0[k].0[n] > (Q / 2) {
                t_0[k].0[n] - Q
            } else {
                t_0[k].0[n]
            }
        }))
    });

    // 5: t ← NTT−1(cap_a_hat ◦ NTT(s_1)) + s_2    ▷ Compute t = As1 + s2
    let t: [R; K] = {
        let as1_hat: [T; K] = mat_vec_mul(&cap_a_hat, &s_1_hat);
        let t_not_reduced: [R; K] = add_vector_ntt(&inv_ntt(&as1_hat), &s_2);
        core::array::from_fn(|k| R(core::array::from_fn(|n| full_reduce32(t_not_reduced[k].0[n]))))
    };

    // 6: (t_1, t_0) ← Power2Round(t, d)    ▷ Compress t
    let (t_1, pk_t_0): ([R; K], [R; K]) = power2round(&t);
    debug_assert_eq!(sk_t_0, pk_t_0); // fuzz target

    // 7: pk ← pkEncode(ρ, t_1)
    // 9: 𝐰Approx ← NTT (𝐀 ∘ NTT(𝐳) − NTT(𝑐) ∘ NTT(𝐭1 ⋅ 2𝑑 ))    ▷ 𝐰Approx = 𝐀𝐳 − 𝑐𝐭1 ⋅ 2𝑑
    let t1_hat_mont: [T; K] = to_mont(&ntt(&t_1));
    let t1_d2_hat_mont: [T; K] = to_mont(&core::array::from_fn(|k| {
        T(core::array::from_fn(|n| mont_reduce(i64::from(t1_hat_mont[k].0[n]) << D)))
    }));

    // 10: return pk
    PublicKey { rho: *rho, tr: *tr, t1_d2_hat_mont }
}
