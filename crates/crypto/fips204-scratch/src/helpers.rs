// Modified for product packaging: documentation and test-only code omitted.
// Modified from fips204 0.4.6 for experimental scratch-workspace integration.
use crate::types::{R, T, T0};
use crate::{Q, ZETA};

// Some arith routines leverage dilithium https://github.com/PQClean/PQClean/tree/master/crypto_sign


// # Algorithm 43 `BitRev8()` is not implemented; zetas are pulled from pre-computed table
// `ZETA_TABLE_MONT`; see below (near end)



// Upstream fips204 attributes this macro to anyhow: https://github.com/dtolnay/anyhow
macro_rules! ensure {
    ($cond:expr, $msg:literal $(,)?) => {
        if !$cond {
            return Err($msg);
        }
    };
}

pub(crate) use ensure; // make available throughout crate




pub(crate) fn is_in_range(w: &R, lo: i32, hi: i32) -> bool {
    w.0.iter().all(|&e| (e >= -lo) && (e <= hi)) // success is CT, failure vartime
}



// The input and intermediate ranges must satisfy the reduction bounds below.
#[allow(clippy::cast_possible_truncation)]
pub(crate) const fn partial_reduce64(a: i64) -> i32 {
    const M: i64 = (1 << 48) / (Q as i64);
    debug_assert!(a.abs() < (67_058_539 << 32), "partial_reduce64 input");
    let x = a >> 23;
    let a = a - x * (Q as i64);
    let x = a >> 23;
    let a = a - x * (Q as i64);
    let q = (a * M) >> 48;
    let res = a - q * (Q as i64);
    debug_assert!(res.abs() < 2 * Q as i64, "partial_reduce64 output");
    res as i32
}













// Considering the positive case for `a`, bits 23 and above can be loosely
// viewed as the 'number of Q' contained within `a` (with some rounding-down
// error). So, increment these bits and then subtract off the corresponding
// number of Q. The result is within (better than) -Q < res < Q.
pub(crate) const fn partial_reduce32(a: i32) -> i32 {
    debug_assert!(a.abs() < 2_143_289_344, "partial_reduce32 input");
    let x = (a + (1 << 22)) >> 23;
    let res = a - x * Q;
    debug_assert!(res.abs() < Q, "partial_reduce32 output");
    res
}


pub(crate) const fn full_reduce32(a: i32) -> i32 {
    debug_assert!(a.abs() < 2_143_289_344, "full_reduce32 input");
    let x = partial_reduce32(a); // puts us within better than -Q to +Q
    let res = x + ((x >> 31) & Q); // add Q if negative
    debug_assert!(res < Q, "full_reduce32 output");
    res
}


// Note: this is only used on 'fixed' security parameters (not secret values), so as not to impact CT

pub(crate) const fn bit_length(x: i32) -> usize { x.ilog2() as usize + 1 }






pub(crate) fn center_mod(m: i32) -> i32 {
    debug_assert!(m.abs() < 2_143_289_344, "center_mod input"); // for clarity; caught in full_reduce32
    let t = full_reduce32(m);
    let over2 = (Q / 2) - t; // check if t is larger than Q/2
    let res = t - ((over2 >> 31) & Q); // sub Q if over2 is negative
    debug_assert_eq!(m.rem_euclid(Q), res.rem_euclid(Q), "center_mod output");
    res
}



#[must_use]
pub(crate) fn mat_vec_mul<const K: usize, const L: usize>(
    a_hat: &[[T; L]; K], u_hat: &[T; L],
) -> [T; K] {
    let mut w_hat = [T0; K];
    let u_hat_mont = to_mont(u_hat);
    for i in 0..K {
        #[allow(clippy::needless_range_loop)] // clarity
        for j in 0..L {
            w_hat[i].0.iter_mut().enumerate().for_each(|(n, e)| {
                *e += mont_reduce(i64::from(a_hat[i][j].0[n]) * i64::from(u_hat_mont[j].0[n]));
            });
        }
    }
    w_hat
}


pub(crate) fn mat_vec_mul_into<const K: usize, const L: usize>(
    a_hat: &[[T; L]; K], u_hat: &[T; L], w_hat: &mut [T; K],
) {
    let u_hat_mont = to_mont(u_hat);
    for (out, row) in w_hat.iter_mut().zip(a_hat) {
        *out = T0;
        for (column, polynomial) in row.iter().enumerate() {
            out.0.iter_mut().enumerate().for_each(|(n, coefficient)| {
                *coefficient += mont_reduce(
                    i64::from(polynomial.0[n]) * i64::from(u_hat_mont[column].0[n]),
                );
            });
        }
    }
}


// Note Algorithm 44 has been dissolved into its place of use(s)






#[must_use]
pub(crate) fn add_vector_ntt<const K: usize>(v_hat: &[R; K], w_hat: &[R; K]) -> [R; K] {
    core::array::from_fn(|k| R(core::array::from_fn(|n| v_hat[k].0[n] + w_hat[k].0[n])))
}


#[allow(clippy::cast_possible_truncation)] // as i32
pub(crate) fn to_mont<const L: usize>(vec_a: &[T; L]) -> [T; L] {
    core::array::from_fn(|l| {
        T(core::array::from_fn(|n| partial_reduce64(i64::from(vec_a[l].0[n]) << 32)))
    })
}


pub(crate) fn to_mont_in_place<const L: usize>(vec_a: &mut [T; L]) {
    for polynomial in vec_a {
        for coefficient in &mut polynomial.0 {
            *coefficient = partial_reduce64(i64::from(*coefficient) << 32);
        }
    }
}


pub(crate) fn infinity_norm<const ROW: usize>(w: &[R; ROW]) -> i32 {
    w.iter()
        .flat_map(|row| row.0)
        .map(|element| center_mod(element).abs())
        // .max() might be non-CT on some targets. infinity_norm() is used in signature generation and
        // verification; the values are ultimately revealed in the signature, so worst case is leaking
        // which vector element failed. Not a problem since the whole thing is permutation-agnostic
        .max()
        .expect("infinity norm fails")
}







#[allow(clippy::cast_possible_truncation)] // a as i32, res as i32
pub(crate) const fn mont_reduce(a: i64) -> i32 {
    const QINV: i32 = 58_728_449; // (Q * QINV) % 2**32 = 1
    debug_assert!(a >= -17_996_808_479_301_632, "mont_reduce input (a)");
    debug_assert!(a <= 17_996_808_470_921_215, "mont_reduce input (b)");
    let t = (a as i32).wrapping_mul(QINV);
    let res = (a - (t as i64).wrapping_mul(Q as i64)) >> 32;
    debug_assert!(res < (Q as i64), "mont_reduce output 1");
    debug_assert!(-(Q as i64) < res, "mont_reduce output 2");
    res as i32
}


// ----- The following function only runs at compile time (thus, not CT etc) -----

#[allow(clippy::cast_possible_truncation)]
const fn gen_zeta_table_mont() -> [i32; 256] {
    let mut result = [0i32; 256];
    let mut x = 1i64;
    let mut i = 0u32;
    while i < 256 {
        result[(i as u8).reverse_bits() as usize] = ((x << 32) % (Q as i64)) as i32;
        x = (x * ZETA as i64) % (Q as i64);
        i += 1;
    }
    result
}


pub(crate) static ZETA_TABLE_MONT: [i32; 256] = gen_zeta_table_mont();
































