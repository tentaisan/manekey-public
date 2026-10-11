#[cfg(feature = "experimental-ml-dsa-rustcrypto")]
use ml_dsa::{
    EncodedSignature, EncodedVerifyingKey, Keypair, MlDsa44, Signature, SigningKey, VerifyingKey,
    signature::{MultipartSigner, MultipartVerifier},
};

use crate::ctaphid::cbor;
pub use crate::ctaphid::credential_signature::{
    CredentialSignatureBackend, CredentialSignatureError,
};
#[cfg(feature = "experimental-ml-dsa-rustcrypto")]
use crate::ctaphid::{credential::CredentialAlgorithm, entropy::EntropySource};

pub const ML_DSA_44_COSE_ALGORITHM: i32 = -48;

pub const ML_DSA_COSE_KEY_TYPE: u64 = 7;

pub const ML_DSA_SEED_LEN: usize = 32;

pub const ML_DSA_44_PUBLIC_KEY_LEN: usize = 1_312;

pub const ML_DSA_44_SIGNATURE_LEN: usize = 2_420;

pub const ML_DSA_44_COSE_PUBLIC_KEY_LEN: usize = 1_322;

/// Checks key length and writes COSE bytes; callers validate public-key contents.
pub fn write_ml_dsa_44_cose_public_key<'a>(
    output: &'a mut [u8],
    public_key: &[u8],
) -> Result<&'a [u8], CredentialSignatureError> {
    if public_key.len() != ML_DSA_44_PUBLIC_KEY_LEN {
        return Err(CredentialSignatureError::InvalidPublicKey);
    }
    if output.len() < ML_DSA_44_COSE_PUBLIC_KEY_LEN {
        return Err(CredentialSignatureError::BufferTooSmall);
    }

    let mut writer = cbor::Writer::new(output);
    writer
        .write_map_len(3)
        .ok_or(CredentialSignatureError::BufferTooSmall)?;
    writer
        .write_uint(1)
        .ok_or(CredentialSignatureError::BufferTooSmall)?;
    writer
        .write_uint(ML_DSA_COSE_KEY_TYPE)
        .ok_or(CredentialSignatureError::BufferTooSmall)?;
    writer
        .write_uint(3)
        .ok_or(CredentialSignatureError::BufferTooSmall)?;
    writer
        .write_negint(ML_DSA_44_COSE_ALGORITHM as i8)
        .ok_or(CredentialSignatureError::BufferTooSmall)?;
    writer
        .write_negint(-1)
        .ok_or(CredentialSignatureError::BufferTooSmall)?;
    writer
        .write_bytes(public_key)
        .ok_or(CredentialSignatureError::BufferTooSmall)?;
    Ok(writer.finish())
}

#[derive(Clone, Copy, Debug, Default)]
#[cfg(feature = "experimental-ml-dsa-rustcrypto")]
/// Experimental RustCrypto seed-based adapter; not a validated authenticator or target-memory guarantee.
pub struct SoftwareMlDsa44;

#[cfg(feature = "experimental-ml-dsa-rustcrypto")]
impl SoftwareMlDsa44 {
    fn signing_key(key_material: &[u8]) -> Result<SigningKey<MlDsa44>, CredentialSignatureError> {
        let seed: &[u8; ML_DSA_SEED_LEN] = key_material
            .try_into()
            .map_err(|_| CredentialSignatureError::InvalidKeyMaterial)?;
        Ok(SigningKey::from_seed(seed.into()))
    }
}

#[cfg(feature = "experimental-ml-dsa-rustcrypto")]
impl CredentialSignatureBackend for SoftwareMlDsa44 {
    fn algorithm(&self) -> CredentialAlgorithm {
        CredentialAlgorithm::MlDsa44
    }

    fn supports_current_build(&self) -> bool {
        cfg!(feature = "experimental-large-message-buffers")
    }

    fn create_key_material(
        &mut self,
        entropy: &mut dyn EntropySource,
    ) -> Result<[u8; ML_DSA_SEED_LEN], CredentialSignatureError> {
        let mut seed = [0u8; ML_DSA_SEED_LEN];
        entropy
            .fill_entropy(&mut seed)
            .map_err(|_| CredentialSignatureError::EntropyUnavailable)?;
        Ok(seed)
    }

    fn public_key<'a>(
        &mut self,
        key_material: &[u8],
        output: &'a mut [u8],
    ) -> Result<&'a [u8], CredentialSignatureError> {
        if output.len() < ML_DSA_44_PUBLIC_KEY_LEN {
            return Err(CredentialSignatureError::BufferTooSmall);
        }

        let encoded = Self::signing_key(key_material)?.verifying_key().encode();
        output[..ML_DSA_44_PUBLIC_KEY_LEN].copy_from_slice(&encoded);
        Ok(&output[..ML_DSA_44_PUBLIC_KEY_LEN])
    }

    fn write_public_key_cose<'a>(
        &mut self,
        key_material: &[u8],
        output: &'a mut [u8],
    ) -> Result<&'a [u8], CredentialSignatureError> {
        let mut public_key = [0u8; ML_DSA_44_PUBLIC_KEY_LEN];
        let public_key = self.public_key(key_material, &mut public_key)?;
        write_ml_dsa_44_cose_public_key(output, public_key)
    }

    fn sign<'a>(
        &mut self,
        key_material: &[u8],
        message: &[&[u8]],
        output: &'a mut [u8],
    ) -> Result<&'a [u8], CredentialSignatureError> {
        if output.len() < ML_DSA_44_SIGNATURE_LEN {
            return Err(CredentialSignatureError::BufferTooSmall);
        }

        let signature: Signature<MlDsa44> = Self::signing_key(key_material)?
            .try_multipart_sign(message)
            .map_err(|_| CredentialSignatureError::BackendFailure)?;
        let encoded = signature.encode();
        output[..ML_DSA_44_SIGNATURE_LEN].copy_from_slice(&encoded);
        Ok(&output[..ML_DSA_44_SIGNATURE_LEN])
    }

    fn verify(
        &mut self,
        public_key: &[u8],
        message: &[&[u8]],
        signature: &[u8],
    ) -> Result<(), CredentialSignatureError> {
        let encoded_public_key: &EncodedVerifyingKey<MlDsa44> = public_key
            .try_into()
            .map_err(|_| CredentialSignatureError::InvalidPublicKey)?;
        let encoded_signature: &EncodedSignature<MlDsa44> = signature
            .try_into()
            .map_err(|_| CredentialSignatureError::InvalidSignature)?;
        let signature: Signature<MlDsa44> = Signature::decode(encoded_signature)
            .ok_or(CredentialSignatureError::InvalidSignature)?;

        VerifyingKey::decode(encoded_public_key)
            .multipart_verify(message, &signature)
            .map_err(|_| CredentialSignatureError::VerificationFailed)
    }
}
