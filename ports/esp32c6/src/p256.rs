use esp_hal::{
    Blocking,
    ecc::{Ecc, EllipticCurve, OperationError},
    peripherals::ECC,
};
use manekey::ctaphid::crypto::{
    P256_GENERATOR_X, P256_GENERATOR_Y, P256EcdhBackend, P256EcdhError,
    p256_private_scalar_is_valid,
};

/// Blocking ECC adapter for ClientPIN P-256; not an ES256 signing backend.
pub struct EspP256Ecdh<'d> {
    ecc: Ecc<'d, Blocking>,
}

impl<'d> EspP256Ecdh<'d> {
    pub fn new(ecc: ECC<'d>) -> Self {
        Self {
            ecc: Ecc::new(ecc, Default::default()),
        }
    }

    fn little_endian(value: &[u8; 32]) -> [u8; 32] {
        let mut output = *value;
        output.reverse();
        output
    }

    fn big_endian(mut value: [u8; 32]) -> [u8; 32] {
        value.reverse();
        value
    }

    fn map_result_error(error: OperationError) -> P256EcdhError {
        match error {
            OperationError::PointNotOnCurve => P256EcdhError::InvalidKey,
            OperationError::ParameterLengthMismatch => P256EcdhError::HardwareUnavailable,
        }
    }
}

impl P256EcdhBackend for EspP256Ecdh<'_> {
    fn public_key_xy(
        &mut self,
        private_key: &[u8; 32],
    ) -> Result<([u8; 32], [u8; 32]), P256EcdhError> {
        if !p256_private_scalar_is_valid(private_key) {
            return Err(P256EcdhError::InvalidKey);
        }

        let scalar = Self::little_endian(private_key);
        let mut x = Self::little_endian(&P256_GENERATOR_X);
        let mut y = Self::little_endian(&P256_GENERATOR_Y);
        let result = self
            .ecc
            .affine_point_multiplication(EllipticCurve::P256, &scalar, &x, &y)
            .map_err(|_| P256EcdhError::HardwareUnavailable)?;
        result
            .read_affine_point_result(&mut x, &mut y)
            .map_err(Self::map_result_error)?;
        Ok((Self::big_endian(x), Self::big_endian(y)))
    }

    fn ecdh(
        &mut self,
        private_key: &[u8; 32],
        peer_x: &[u8; 32],
        peer_y: &[u8; 32],
    ) -> Result<[u8; 32], P256EcdhError> {
        if !p256_private_scalar_is_valid(private_key) {
            return Err(P256EcdhError::InvalidKey);
        }

        let scalar = Self::little_endian(private_key);
        let mut x = Self::little_endian(peer_x);
        let mut y = Self::little_endian(peer_y);
        let result = self
            .ecc
            .affine_point_verification_multiplication(EllipticCurve::P256, &scalar, &x, &y)
            .map_err(|_| P256EcdhError::HardwareUnavailable)?;
        result
            .read_affine_point_result(&mut x, &mut y)
            .map_err(Self::map_result_error)?;
        Ok(Self::big_endian(x))
    }
}
