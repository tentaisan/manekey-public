use manekey_mldsa_native::{
    NativeKeypair, PUBLIC_KEY_LEN, RANDOMNESS_LEN, SEED_LEN, SIGNATURE_LEN,
};

use crate::ctaphid::{
    credential::CredentialAlgorithm,
    credential_signature::{CredentialSignatureBackend, CredentialSignatureError},
    entropy::EntropySource,
    pqc_signature::{
        ML_DSA_44_PUBLIC_KEY_LEN, ML_DSA_44_SIGNATURE_LEN, ML_DSA_SEED_LEN,
        write_ml_dsa_44_cose_public_key,
    },
};

const ML_DSA_MESSAGE_BUFFER_LEN: usize = 1_536 + 32;
const DETERMINISTIC_SIGNING_SEED: [u8; RANDOMNESS_LEN] = [0; RANDOMNESS_LEN];

const _: () = assert!(SEED_LEN == ML_DSA_SEED_LEN);
const _: () = assert!(PUBLIC_KEY_LEN == ML_DSA_44_PUBLIC_KEY_LEN);
const _: () = assert!(SIGNATURE_LEN == ML_DSA_44_SIGNATURE_LEN);

#[derive(Clone, Copy, Debug, Default)]

/// Experimental native adapter with deterministic signing randomness.
/// Reduced RAM configuration does not establish target stack fit or cryptographic validation.
pub struct MldsaNativeMlDsa44;

impl MldsaNativeMlDsa44 {
    fn seed(key_material: &[u8]) -> Result<&[u8; ML_DSA_SEED_LEN], CredentialSignatureError> {
        key_material
            .try_into()
            .map_err(|_| CredentialSignatureError::InvalidKeyMaterial)
    }

    fn concatenate_message<'a>(
        message: &[&[u8]],
        output: &'a mut [u8; ML_DSA_MESSAGE_BUFFER_LEN],
    ) -> Result<&'a [u8], CredentialSignatureError> {
        let mut len = 0usize;
        for part in message {
            let end = len
                .checked_add(part.len())
                .filter(|end| *end <= output.len())
                .ok_or(CredentialSignatureError::BufferTooSmall)?;
            output[len..end].copy_from_slice(part);
            len = end;
        }
        Ok(&output[..len])
    }
}

impl CredentialSignatureBackend for MldsaNativeMlDsa44 {
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
        let mut keypair = NativeKeypair::empty();
        keypair
            .regenerate(Self::seed(key_material)?)
            .map_err(|_| CredentialSignatureError::BackendFailure)?;
        output[..ML_DSA_44_PUBLIC_KEY_LEN].copy_from_slice(keypair.public_key());
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
        let mut message_buffer = [0u8; ML_DSA_MESSAGE_BUFFER_LEN];
        let message = Self::concatenate_message(message, &mut message_buffer)?;
        let mut keypair = NativeKeypair::empty();
        keypair
            .regenerate(Self::seed(key_material)?)
            .map_err(|_| CredentialSignatureError::BackendFailure)?;
        let signature: &mut [u8; SIGNATURE_LEN] = (&mut output[..SIGNATURE_LEN])
            .try_into()
            .map_err(|_| CredentialSignatureError::BufferTooSmall)?;
        keypair
            .sign_into(message, &DETERMINISTIC_SIGNING_SEED, signature)
            .map_err(|_| CredentialSignatureError::BackendFailure)?;
        Ok(&output[..ML_DSA_44_SIGNATURE_LEN])
    }

    fn verify(
        &mut self,
        public_key: &[u8],
        message: &[&[u8]],
        signature: &[u8],
    ) -> Result<(), CredentialSignatureError> {
        let public_key: &[u8; ML_DSA_44_PUBLIC_KEY_LEN] = public_key
            .try_into()
            .map_err(|_| CredentialSignatureError::InvalidPublicKey)?;
        let signature: &[u8; ML_DSA_44_SIGNATURE_LEN] = signature
            .try_into()
            .map_err(|_| CredentialSignatureError::InvalidSignature)?;
        let mut message_buffer = [0u8; ML_DSA_MESSAGE_BUFFER_LEN];
        let message = Self::concatenate_message(message, &mut message_buffer)?;
        manekey_mldsa_native::verify(public_key, message, signature).map_err(|error| match error {
            manekey_mldsa_native::Error::VerificationFailed => {
                CredentialSignatureError::VerificationFailed
            }
            manekey_mldsa_native::Error::BackendFailure => CredentialSignatureError::BackendFailure,
        })
    }
}
