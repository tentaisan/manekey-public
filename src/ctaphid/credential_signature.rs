use crate::ctaphid::{
    auth_data,
    credential::CredentialAlgorithm,
    crypto::{Es256Backend, Es256Error, SoftwareEs256},
    entropy::EntropySource,
};

pub const CREDENTIAL_KEY_MATERIAL_LEN: usize = 32;

pub const ES256_PUBLIC_KEY_LEN: usize = 64;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CredentialSignatureError {
    BufferTooSmall,
    EntropyUnavailable,
    InvalidKeyMaterial,
    InvalidPublicKey,
    InvalidSignature,
    VerificationFailed,
    BackendFailure,
}

/// Credential signature interface; key material remains sensitive and default verify is unsupported.
pub trait CredentialSignatureBackend {
    fn algorithm(&self) -> CredentialAlgorithm;

    fn supports_current_build(&self) -> bool {
        true
    }

    fn create_key_material(
        &mut self,
        entropy: &mut dyn EntropySource,
    ) -> Result<[u8; CREDENTIAL_KEY_MATERIAL_LEN], CredentialSignatureError>;

    fn public_key<'a>(
        &mut self,
        key_material: &[u8],
        output: &'a mut [u8],
    ) -> Result<&'a [u8], CredentialSignatureError>;

    fn write_public_key_cose<'a>(
        &mut self,
        key_material: &[u8],
        output: &'a mut [u8],
    ) -> Result<&'a [u8], CredentialSignatureError>;

    fn sign<'a>(
        &mut self,
        key_material: &[u8],
        message: &[&[u8]],
        output: &'a mut [u8],
    ) -> Result<&'a [u8], CredentialSignatureError>;

    fn verify(
        &mut self,
        _public_key: &[u8],
        _message: &[&[u8]],
        _signature: &[u8],
    ) -> Result<(), CredentialSignatureError> {
        Err(CredentialSignatureError::BackendFailure)
    }
}

#[derive(Clone, Copy, Debug, Default)]
/// Raw private-scalar ES256 adapter; sign expects authenticator data and a 32-byte client hash.
pub struct Es256CredentialSignature<B = SoftwareEs256> {
    backend: B,
}

impl<B> Es256CredentialSignature<B> {
    pub const fn new(backend: B) -> Self {
        Self { backend }
    }

    pub fn into_inner(self) -> B {
        self.backend
    }
}

impl<B: Es256Backend> Es256CredentialSignature<B> {
    pub fn public_key_xy(
        &mut self,
        key_material: &[u8],
    ) -> Result<([u8; 32], [u8; 32]), CredentialSignatureError> {
        let private_key: &[u8; CREDENTIAL_KEY_MATERIAL_LEN] = key_material
            .try_into()
            .map_err(|_| CredentialSignatureError::InvalidKeyMaterial)?;
        self.backend
            .public_key_xy(private_key)
            .map_err(map_es256_error)
    }
}

fn map_es256_error(error: Es256Error) -> CredentialSignatureError {
    match error {
        Es256Error::HardwareUnavailable => CredentialSignatureError::BackendFailure,
        Es256Error::InvalidPrivateKey => CredentialSignatureError::InvalidKeyMaterial,
        Es256Error::BufferTooSmall => CredentialSignatureError::BufferTooSmall,
    }
}

impl<B: Es256Backend> CredentialSignatureBackend for Es256CredentialSignature<B> {
    fn algorithm(&self) -> CredentialAlgorithm {
        CredentialAlgorithm::Es256
    }

    fn create_key_material(
        &mut self,
        entropy: &mut dyn EntropySource,
    ) -> Result<[u8; CREDENTIAL_KEY_MATERIAL_LEN], CredentialSignatureError> {
        for _ in 0..16 {
            let mut private_key = [0u8; CREDENTIAL_KEY_MATERIAL_LEN];
            entropy
                .fill_entropy(&mut private_key)
                .map_err(|_| CredentialSignatureError::EntropyUnavailable)?;
            if self.backend.public_key_xy(&private_key).is_ok() {
                return Ok(private_key);
            }
        }
        Err(CredentialSignatureError::BackendFailure)
    }

    fn public_key<'a>(
        &mut self,
        key_material: &[u8],
        output: &'a mut [u8],
    ) -> Result<&'a [u8], CredentialSignatureError> {
        if output.len() < ES256_PUBLIC_KEY_LEN {
            return Err(CredentialSignatureError::BufferTooSmall);
        }
        let (x, y) = self.public_key_xy(key_material)?;
        output[..32].copy_from_slice(&x);
        output[32..ES256_PUBLIC_KEY_LEN].copy_from_slice(&y);
        Ok(&output[..ES256_PUBLIC_KEY_LEN])
    }

    fn write_public_key_cose<'a>(
        &mut self,
        key_material: &[u8],
        output: &'a mut [u8],
    ) -> Result<&'a [u8], CredentialSignatureError> {
        let (x, y) = self.public_key_xy(key_material)?;
        auth_data::write_cose_key(output, &x, &y).ok_or(CredentialSignatureError::BufferTooSmall)
    }

    fn sign<'a>(
        &mut self,
        key_material: &[u8],
        message: &[&[u8]],
        output: &'a mut [u8],
    ) -> Result<&'a [u8], CredentialSignatureError> {
        let private_key: &[u8; CREDENTIAL_KEY_MATERIAL_LEN] = key_material
            .try_into()
            .map_err(|_| CredentialSignatureError::InvalidKeyMaterial)?;
        let [authenticator_data, client_data_hash] = message else {
            return Err(CredentialSignatureError::BackendFailure);
        };
        let client_data_hash: &[u8; 32] = (*client_data_hash)
            .try_into()
            .map_err(|_| CredentialSignatureError::BackendFailure)?;
        self.backend
            .sign_webauthn_der(private_key, authenticator_data, client_data_hash, output)
            .map_err(map_es256_error)
    }
}
