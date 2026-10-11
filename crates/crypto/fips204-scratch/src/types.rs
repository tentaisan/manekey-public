// Modified for product packaging: documentation and test-only code omitted.
// Modified from fips204 0.4.6 for experimental scratch-workspace integration.
use core::mem::MaybeUninit;

use zeroize::{Zeroize, ZeroizeOnDrop};



pub enum Ph {

    SHA256,

    SHA512,

    SHAKE128,
}






#[derive(Clone, Zeroize, ZeroizeOnDrop)]
#[repr(align(8))]
pub struct PrivateKey<const K: usize, const L: usize> {
    pub(crate) rho: [u8; 32],
    pub(crate) cap_k: [u8; 32],
    pub(crate) tr: [u8; 64],
    pub(crate) s_1_hat_mont: [T; L],
    pub(crate) s_2_hat_mont: [T; K],
    pub(crate) t_0_hat_mont: [T; K],
}






#[derive(Clone, Zeroize, ZeroizeOnDrop)]
#[repr(align(8))]
pub struct PublicKey<const K: usize, const L: usize> {
    pub(crate) rho: [u8; 32],
    pub(crate) tr: [u8; 64],
    pub(crate) t1_d2_hat_mont: [T; K],
}







#[derive(Zeroize, ZeroizeOnDrop)]
#[repr(align(8))]
pub struct KeyGenScratch<const K: usize, const L: usize> {
    // Experimental caller-owned secret workspace; one operation owns it exclusively.
    // Do not share it with another task/interrupt while an operation is active.
    pub(crate) cap_a_hat: [[T; L]; K],
    pub(crate) s_1: [R; L],
    pub(crate) s_2: [R; K],
    pub(crate) s_1_hat: [T; L],
    pub(crate) work_hat: [T; K],
    pub(crate) work: [R; K],
}

impl<const K: usize, const L: usize> KeyGenScratch<K, L> {




    #[allow(unsafe_code)]
    pub fn init_zeroed(slot: &mut MaybeUninit<Self>) -> &mut Self {
        // All fields are integer polynomial arrays valid at zero. Use a fresh,
        // exclusively owned slot; this does not initialize arbitrary other types.
        unsafe {
            core::ptr::write_bytes(slot.as_mut_ptr(), 0, 1);
            slot.assume_init_mut()
        }
    }


    #[must_use]
    pub fn new() -> Self {
        Self {
            cap_a_hat: core::array::from_fn(|_| core::array::from_fn(|_| T0)),
            s_1: core::array::from_fn(|_| R0),
            s_2: core::array::from_fn(|_| R0),
            s_1_hat: core::array::from_fn(|_| T0),
            work_hat: core::array::from_fn(|_| T0),
            work: core::array::from_fn(|_| R0),
        }
    }
}

impl<const K: usize, const L: usize> Default for KeyGenScratch<K, L> {
    fn default() -> Self {
        Self::new()
    }
}





#[derive(Zeroize, ZeroizeOnDrop)]
#[repr(align(8))]
pub struct SignScratch<const K: usize, const L: usize> {
    // Contains secret rejection-loop intermediates. ZeroizeOnDrop covers this object,
    // not copies, registers or all call-stack frames; caller owns exclusive access.
    pub(crate) cap_a_hat: [[T; L]; K],
    pub(crate) y: [R; L],
    pub(crate) z: [R; L],
    pub(crate) w: [R; K],
    pub(crate) c_s_2: [R; K],
    pub(crate) work: [R; K],
    pub(crate) h: [R; K],
    pub(crate) w_1: [R; K],
    pub(crate) l_hat: [T; L],
    pub(crate) k_hat: [T; K],
    pub(crate) c_hat: T,
}

impl<const K: usize, const L: usize> SignScratch<K, L> {




    #[allow(unsafe_code)]
    pub fn init_zeroed(slot: &mut MaybeUninit<Self>) -> &mut Self {
        // All fields are integer polynomial arrays valid at zero; use a fresh exclusive slot.
        unsafe {
            core::ptr::write_bytes(slot.as_mut_ptr(), 0, 1);
            slot.assume_init_mut()
        }
    }


    #[must_use]
    pub fn new() -> Self {
        Self {
            cap_a_hat: core::array::from_fn(|_| core::array::from_fn(|_| T0)),
            y: core::array::from_fn(|_| R0),
            z: core::array::from_fn(|_| R0),
            w: core::array::from_fn(|_| R0),
            c_s_2: core::array::from_fn(|_| R0),
            work: core::array::from_fn(|_| R0),
            h: core::array::from_fn(|_| R0),
            w_1: core::array::from_fn(|_| R0),
            l_hat: core::array::from_fn(|_| T0),
            k_hat: core::array::from_fn(|_| T0),
            c_hat: T0,
        }
    }





    pub fn is_zeroed(&self) -> bool {
        // Logical coefficient check only, not constant-time or a physical memory-scrub proof.
        self.cap_a_hat.iter().flatten().all(T::is_zeroed)
            && self.y.iter().all(R::is_zeroed)
            && self.z.iter().all(R::is_zeroed)
            && self.w.iter().all(R::is_zeroed)
            && self.c_s_2.iter().all(R::is_zeroed)
            && self.work.iter().all(R::is_zeroed)
            && self.h.iter().all(R::is_zeroed)
            && self.w_1.iter().all(R::is_zeroed)
            && self.l_hat.iter().all(T::is_zeroed)
            && self.k_hat.iter().all(T::is_zeroed)
            && self.c_hat.is_zeroed()
    }
}

impl<const K: usize, const L: usize> Default for SignScratch<K, L> {
    fn default() -> Self {
        Self::new()
    }
}



#[derive(Clone, Debug, PartialEq, Zeroize, ZeroizeOnDrop)]
#[repr(align(8))]
pub(crate) struct R(pub(crate) [i32; 256]);
pub(crate) const R0: R = R([0i32; 256]);

impl R {
    fn is_zeroed(&self) -> bool {
        self.0.iter().all(|coefficient| *coefficient == 0)
    }
}



#[derive(Clone, Zeroize, ZeroizeOnDrop)]
#[repr(align(8))]
pub(crate) struct T(pub(crate) [i32; 256]);
pub(crate) const T0: T = T([0i32; 256]);

impl T {
    fn is_zeroed(&self) -> bool {
        self.0.iter().all(|coefficient| *coefficient == 0)
    }
}



pub(crate) type Zq = i32;
