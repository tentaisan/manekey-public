use manekey_fips204_scratch::{
    ml_dsa_44::{self, PrivateKey, PublicKey, SignScratch},
    traits::{SerDes, Verifier},
};
use zeroize::Zeroize;

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
const DETERMINISTIC_SIGNING_SEED: [u8; 32] = [0; 32];

pub trait ScratchClearObserver {}

#[derive(Default)]
pub struct NoopScratchClearObserver;

impl ScratchClearObserver for NoopScratchClearObserver {}

/// Experimental modified backend requiring exclusive secret-workspace ownership across IRQ/tasks.
/// Zeroize calls do not prove all-path erasure, physical-remanence or side-channel protection.
/// Signing uses deterministic randomness; upstream evaluation does not cover this fork.
pub struct Fips204ScratchMlDsa44<'scratch, Observer = NoopScratchClearObserver> {
    sign_scratch: &'scratch mut SignScratch,

    observer: core::marker::PhantomData<Observer>,
}

impl<'scratch> Fips204ScratchMlDsa44<'scratch> {
    pub fn new(sign_scratch: &'scratch mut SignScratch) -> Self {
        Self {
            sign_scratch,

            observer: core::marker::PhantomData,
        }
    }
}

impl<'scratch, Observer> Fips204ScratchMlDsa44<'scratch, Observer>
where
    Observer: ScratchClearObserver,
{
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

    fn keypair(
        &mut self,
        key_material: &[u8],
    ) -> Result<(PublicKey, PrivateKey), CredentialSignatureError> {
        let keypair = ml_dsa_44::keygen_from_seed_with_sign_scratch(
            Self::seed(key_material)?,
            self.sign_scratch,
        );
        self.sign_scratch.zeroize();

        Ok(keypair)
    }
}

impl<Observer> CredentialSignatureBackend for Fips204ScratchMlDsa44<'_, Observer>
where
    Observer: ScratchClearObserver,
{
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
        let (public_key, mut private_key) = self.keypair(key_material)?;
        private_key.zeroize();
        output[..ML_DSA_44_PUBLIC_KEY_LEN].copy_from_slice(&public_key.into_bytes());
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
        let (_, mut private_key) = self.keypair(key_material)?;
        let signing_result = ml_dsa_44::try_sign_with_seed_and_scratch(
            &private_key,
            &DETERMINISTIC_SIGNING_SEED,
            message,
            &[],
            self.sign_scratch,
        );
        private_key.zeroize();
        self.sign_scratch.zeroize();

        message_buffer.zeroize();
        let signature = signing_result.map_err(|_| CredentialSignatureError::BackendFailure)?;
        output[..ML_DSA_44_SIGNATURE_LEN].copy_from_slice(&signature);
        Ok(&output[..ML_DSA_44_SIGNATURE_LEN])
    }

    fn verify(
        &mut self,
        public_key: &[u8],
        message: &[&[u8]],
        signature: &[u8],
    ) -> Result<(), CredentialSignatureError> {
        let public_key: [u8; ML_DSA_44_PUBLIC_KEY_LEN] = public_key
            .try_into()
            .map_err(|_| CredentialSignatureError::InvalidPublicKey)?;
        let signature: &[u8; ML_DSA_44_SIGNATURE_LEN] = signature
            .try_into()
            .map_err(|_| CredentialSignatureError::InvalidSignature)?;
        let public_key = PublicKey::try_from_bytes(public_key)
            .map_err(|_| CredentialSignatureError::InvalidPublicKey)?;
        let mut message_buffer = [0u8; ML_DSA_MESSAGE_BUFFER_LEN];
        let message = Self::concatenate_message(message, &mut message_buffer)?;
        let accepted = public_key.verify(message, signature, &[]);
        message_buffer.zeroize();
        accepted
            .then_some(())
            .ok_or(CredentialSignatureError::VerificationFailed)
    }
}
