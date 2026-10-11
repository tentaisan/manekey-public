#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum VerificationResult {
    Verified,

    Denied,

    Unavailable,
}

impl VerificationResult {
    pub const fn is_verified(self) -> bool {
        matches!(self, Self::Verified)
    }
}

/// Reports identity verification independently of presence.
pub trait UserVerification {
    fn verify(&mut self) -> VerificationResult;
}

pub struct UnavailableUserVerification;

impl UserVerification for UnavailableUserVerification {
    fn verify(&mut self) -> VerificationResult {
        VerificationResult::Unavailable
    }
}

/// Identity-verification bypass for explicit test profiles, not genuine UV.
pub struct AlwaysVerified;

impl UserVerification for AlwaysVerified {
    fn verify(&mut self) -> VerificationResult {
        VerificationResult::Verified
    }
}
