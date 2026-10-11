use crate::ctaphid::{
    auth_data,
    credential::{CREDENTIAL_ID_LEN, CredentialAlgorithm},
    credential_signature::{
        CREDENTIAL_KEY_MATERIAL_LEN, CredentialSignatureBackend, Es256CredentialSignature,
    },
    crypto::{self, Es256Backend, SoftwareEs256},
    entropy::EntropySource,
    hash::{Sha256Backend, Sha256Error, SoftwareSha256, sha256_digest_parts},
};

pub const KEY_MATERIAL_LEN: usize = CREDENTIAL_KEY_MATERIAL_LEN;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KeyLifecycleError {
    BackendFailure,
    InvalidHandle,
}

/// Stored material may be a secret scalar or backend handle.
/// Resource-owning stores must override the default no-op release/reset hooks.
pub trait PrivateKeyStore {
    fn release_key_material(
        &mut self,
        _algorithm: CredentialAlgorithm,
        _key_material: &[u8; KEY_MATERIAL_LEN],
    ) -> Result<(), KeyLifecycleError> {
        Ok(())
    }

    fn reset_credential_keys(&mut self) -> Result<(), KeyLifecycleError> {
        Ok(())
    }

    fn supports_algorithm(&self, algorithm: CredentialAlgorithm) -> bool {
        algorithm == CredentialAlgorithm::Es256
    }

    fn create_key_material<E: EntropySource>(
        &mut self,
        credential_id: &[u8; CREDENTIAL_ID_LEN],
        entropy: &mut E,
    ) -> Option<[u8; KEY_MATERIAL_LEN]>;

    fn create_key_material_for_algorithm<E: EntropySource>(
        &mut self,
        algorithm: CredentialAlgorithm,
        credential_id: &[u8; CREDENTIAL_ID_LEN],
        entropy: &mut E,
    ) -> Option<[u8; KEY_MATERIAL_LEN]> {
        (algorithm == CredentialAlgorithm::Es256)
            .then(|| self.create_key_material(credential_id, entropy))?
    }

    fn public_key_xy(
        &mut self,
        key_material: &[u8; KEY_MATERIAL_LEN],
    ) -> Option<([u8; 32], [u8; 32])>;

    fn write_public_key_cose<'a>(
        &mut self,
        algorithm: CredentialAlgorithm,
        key_material: &[u8; KEY_MATERIAL_LEN],
        output: &'a mut [u8],
    ) -> Option<&'a [u8]> {
        if algorithm != CredentialAlgorithm::Es256 {
            return None;
        }
        let (x, y) = self.public_key_xy(key_material)?;
        auth_data::write_cose_key(output, &x, &y)
    }

    fn sign<'a>(
        &mut self,
        key_material: &[u8; KEY_MATERIAL_LEN],
        auth_data: &[u8],
        client_data_hash: &[u8; 32],
        signature_buf: &'a mut [u8],
    ) -> Option<&'a [u8]>;

    fn sign_for_algorithm<'a>(
        &mut self,
        algorithm: CredentialAlgorithm,
        key_material: &[u8; KEY_MATERIAL_LEN],
        auth_data: &[u8],
        client_data_hash: &[u8; 32],
        signature_buf: &'a mut [u8],
    ) -> Option<&'a [u8]> {
        if algorithm != CredentialAlgorithm::Es256 {
            return None;
        }
        self.sign(key_material, auth_data, client_data_hash, signature_buf)
    }

    fn hmac_secret_cred_random(
        &mut self,
        _key_material: &[u8; KEY_MATERIAL_LEN],
        _user_verified: bool,
    ) -> Option<[u8; 32]> {
        None
    }
}

/// Additional signatures retain complete material in the journal, not external persistent slots.
pub struct AdditionalSignaturePrivateKeyStore<K, S> {
    fallback: K,
    additional: S,
}

impl<K, S> AdditionalSignaturePrivateKeyStore<K, S> {
    pub const fn new(fallback: K, additional: S) -> Self {
        Self {
            fallback,
            additional,
        }
    }

    pub fn into_inner(self) -> (K, S) {
        (self.fallback, self.additional)
    }
}

impl<K: PrivateKeyStore, S: CredentialSignatureBackend> PrivateKeyStore
    for AdditionalSignaturePrivateKeyStore<K, S>
{
    fn release_key_material(
        &mut self,
        algorithm: CredentialAlgorithm,
        material: &[u8; KEY_MATERIAL_LEN],
    ) -> Result<(), KeyLifecycleError> {
        if self.fallback.supports_algorithm(algorithm) {
            return self.fallback.release_key_material(algorithm, material);
        }

        if self.additional.algorithm() == algorithm {
            Ok(())
        } else {
            Err(KeyLifecycleError::InvalidHandle)
        }
    }

    fn reset_credential_keys(&mut self) -> Result<(), KeyLifecycleError> {
        self.fallback.reset_credential_keys()
    }

    fn supports_algorithm(&self, algorithm: CredentialAlgorithm) -> bool {
        self.fallback.supports_algorithm(algorithm)
            || (self.additional.algorithm() == algorithm
                && self.additional.supports_current_build())
    }

    fn create_key_material<E: EntropySource>(
        &mut self,
        credential_id: &[u8; CREDENTIAL_ID_LEN],
        entropy: &mut E,
    ) -> Option<[u8; KEY_MATERIAL_LEN]> {
        self.fallback.create_key_material(credential_id, entropy)
    }

    fn create_key_material_for_algorithm<E: EntropySource>(
        &mut self,
        algorithm: CredentialAlgorithm,
        credential_id: &[u8; CREDENTIAL_ID_LEN],
        entropy: &mut E,
    ) -> Option<[u8; KEY_MATERIAL_LEN]> {
        if self.fallback.supports_algorithm(algorithm) {
            return self.fallback.create_key_material_for_algorithm(
                algorithm,
                credential_id,
                entropy,
            );
        }
        (self.additional.algorithm() == algorithm && self.additional.supports_current_build())
            .then(|| self.additional.create_key_material(entropy).ok())?
    }

    fn public_key_xy(
        &mut self,
        key_material: &[u8; KEY_MATERIAL_LEN],
    ) -> Option<([u8; 32], [u8; 32])> {
        self.fallback.public_key_xy(key_material)
    }

    fn write_public_key_cose<'a>(
        &mut self,
        algorithm: CredentialAlgorithm,
        key_material: &[u8; KEY_MATERIAL_LEN],
        output: &'a mut [u8],
    ) -> Option<&'a [u8]> {
        if self.fallback.supports_algorithm(algorithm) {
            return self
                .fallback
                .write_public_key_cose(algorithm, key_material, output);
        }
        (self.additional.algorithm() == algorithm && self.additional.supports_current_build())
            .then(|| {
                self.additional
                    .write_public_key_cose(key_material, output)
                    .ok()
            })?
    }

    fn sign<'a>(
        &mut self,
        key_material: &[u8; KEY_MATERIAL_LEN],
        auth_data: &[u8],
        client_data_hash: &[u8; 32],
        signature_buf: &'a mut [u8],
    ) -> Option<&'a [u8]> {
        self.fallback
            .sign(key_material, auth_data, client_data_hash, signature_buf)
    }

    fn sign_for_algorithm<'a>(
        &mut self,
        algorithm: CredentialAlgorithm,
        key_material: &[u8; KEY_MATERIAL_LEN],
        auth_data: &[u8],
        client_data_hash: &[u8; 32],
        signature_buf: &'a mut [u8],
    ) -> Option<&'a [u8]> {
        if self.fallback.supports_algorithm(algorithm) {
            return self.fallback.sign_for_algorithm(
                algorithm,
                key_material,
                auth_data,
                client_data_hash,
                signature_buf,
            );
        }
        (self.additional.algorithm() == algorithm && self.additional.supports_current_build())
            .then(|| {
                self.additional
                    .sign(key_material, &[auth_data, client_data_hash], signature_buf)
                    .ok()
            })?
    }

    fn hmac_secret_cred_random(
        &mut self,
        key_material: &[u8; KEY_MATERIAL_LEN],
        user_verified: bool,
    ) -> Option<[u8; 32]> {
        self.fallback
            .hmac_secret_cred_random(key_material, user_verified)
    }
}

fn hmac_secret_label(user_verified: bool) -> &'static [u8] {
    if user_verified {
        b"manekey-hmac-secret-with-uv-v1"
    } else {
        b"manekey-hmac-secret-without-uv-v1"
    }
}

/// Uses material as a private scalar; callers provide storage and boundary protection.
pub struct FlashPrivateKeyStore;

impl PrivateKeyStore for FlashPrivateKeyStore {
    fn create_key_material<E: EntropySource>(
        &mut self,
        _credential_id: &[u8; CREDENTIAL_ID_LEN],
        entropy: &mut E,
    ) -> Option<[u8; KEY_MATERIAL_LEN]> {
        Es256CredentialSignature::<SoftwareEs256>::default()
            .create_key_material(entropy)
            .ok()
    }

    fn public_key_xy(
        &mut self,
        key_material: &[u8; KEY_MATERIAL_LEN],
    ) -> Option<([u8; 32], [u8; 32])> {
        Es256CredentialSignature::<SoftwareEs256>::default()
            .public_key_xy(key_material)
            .ok()
    }

    fn sign<'a>(
        &mut self,
        key_material: &[u8; KEY_MATERIAL_LEN],
        auth_data: &[u8],
        client_data_hash: &[u8; 32],
        signature_buf: &'a mut [u8],
    ) -> Option<&'a [u8]> {
        Es256CredentialSignature::<SoftwareEs256>::default()
            .sign(key_material, &[auth_data, client_data_hash], signature_buf)
            .ok()
    }

    fn hmac_secret_cred_random(
        &mut self,
        key_material: &[u8; KEY_MATERIAL_LEN],
        user_verified: bool,
    ) -> Option<[u8; 32]> {
        let mut hash = SoftwareSha256;
        crypto::hmac_sha256_with_hash(&mut hash, key_material, &[hmac_secret_label(user_verified)])
    }
}

/// Caller-protected device root; this adapter is not a hardware security boundary.
pub struct DerivedPrivateKeyStore<H = SoftwareSha256, E = SoftwareEs256> {
    device_secret: [u8; KEY_MATERIAL_LEN],
    hash: H,
    es256: Es256CredentialSignature<E>,
}

impl DerivedPrivateKeyStore<SoftwareSha256> {
    pub const fn new(device_secret: [u8; KEY_MATERIAL_LEN]) -> Self {
        Self {
            device_secret,
            hash: SoftwareSha256,
            es256: Es256CredentialSignature::new(SoftwareEs256),
        }
    }

    /// Public device IDs yield reproducible public-derived keys, not secret device roots.
    pub fn from_device_id(device_id: &[u8]) -> Self {
        let label = b"rp2040-fido2-device-secret-v1";
        Self::new(sha256_digest_parts(&[label, device_id]))
    }
}

impl<H: Sha256Backend> DerivedPrivateKeyStore<H, SoftwareEs256> {
    pub const fn new_with_hash(device_secret: [u8; KEY_MATERIAL_LEN], hash: H) -> Self {
        Self {
            device_secret,
            hash,
            es256: Es256CredentialSignature::new(SoftwareEs256),
        }
    }
}

impl<H: Sha256Backend> DerivedPrivateKeyStore<H, SoftwareEs256> {
    /// Hardware hashing does not make a public device ID secret.
    pub fn from_device_id_with_hash(device_id: &[u8], mut hash: H) -> Result<Self, Sha256Error> {
        let label = b"rp2040-fido2-device-secret-v1";
        let mut input = [0u8; 64];
        let total_len = label.len() + device_id.len();
        if total_len > input.len() {
            return Err(Sha256Error::HardwareUnavailable);
        }
        input[..label.len()].copy_from_slice(label);
        input[label.len()..total_len].copy_from_slice(device_id);
        let device_secret = hash.digest(&input[..total_len])?;
        Ok(Self::new_with_hash(device_secret, hash))
    }
}

impl<H: Sha256Backend, E: Es256Backend> DerivedPrivateKeyStore<H, E> {
    pub const fn new_with_backends(
        device_secret: [u8; KEY_MATERIAL_LEN],
        hash: H,
        es256: E,
    ) -> Self {
        Self {
            device_secret,
            hash,
            es256: Es256CredentialSignature::new(es256),
        }
    }

    fn key_material_for(
        &mut self,
        credential_id: &[u8; CREDENTIAL_ID_LEN],
    ) -> Option<[u8; KEY_MATERIAL_LEN]> {
        let mut input = [0u8; 48];
        let label = b"rp2040-fido2-key-reference-v1";
        input[..label.len()].copy_from_slice(label);
        input[label.len()..label.len() + credential_id.len()].copy_from_slice(credential_id);
        self.hash
            .digest(&input[..label.len() + credential_id.len()])
            .ok()
    }

    fn derive_private_key(
        &mut self,
        key_material: &[u8; KEY_MATERIAL_LEN],
    ) -> Option<[u8; KEY_MATERIAL_LEN]> {
        for counter in 0u8..16 {
            let mut input = [0u8; 96];
            let label = b"rp2040-fido2-derived-es256-v1";
            input[..label.len()].copy_from_slice(label);
            input[label.len()..label.len() + self.device_secret.len()]
                .copy_from_slice(&self.device_secret);
            let offset = label.len() + self.device_secret.len();
            input[offset..offset + key_material.len()].copy_from_slice(key_material);
            input[offset + key_material.len()] = counter;
            let candidate = self
                .hash
                .digest(&input[..offset + key_material.len() + 1])
                .ok()?;

            if self.es256.public_key_xy(&candidate).is_ok() {
                return Some(candidate);
            }
        }

        None
    }
}

impl<H: Sha256Backend, E: Es256Backend> PrivateKeyStore for DerivedPrivateKeyStore<H, E> {
    fn create_key_material<R: EntropySource>(
        &mut self,
        credential_id: &[u8; CREDENTIAL_ID_LEN],
        _entropy: &mut R,
    ) -> Option<[u8; KEY_MATERIAL_LEN]> {
        self.key_material_for(credential_id)
    }

    fn public_key_xy(
        &mut self,
        key_material: &[u8; KEY_MATERIAL_LEN],
    ) -> Option<([u8; 32], [u8; 32])> {
        let private_key = self.derive_private_key(key_material)?;
        self.es256.public_key_xy(&private_key).ok()
    }

    fn sign<'a>(
        &mut self,
        key_material: &[u8; KEY_MATERIAL_LEN],
        auth_data: &[u8],
        client_data_hash: &[u8; 32],
        signature_buf: &'a mut [u8],
    ) -> Option<&'a [u8]> {
        let private_key = self.derive_private_key(key_material)?;

        self.es256
            .sign(&private_key, &[auth_data, client_data_hash], signature_buf)
            .ok()
    }

    fn hmac_secret_cred_random(
        &mut self,
        key_material: &[u8; KEY_MATERIAL_LEN],
        user_verified: bool,
    ) -> Option<[u8; 32]> {
        crypto::hmac_sha256_with_hash(
            &mut self.hash,
            &self.device_secret,
            &[hmac_secret_label(user_verified), key_material],
        )
    }
}

/// Element adapter owns key protection and lifecycle; default release/reset fail.
pub trait SecureElement {
    fn release_key(&mut self, _material: &[u8; KEY_MATERIAL_LEN]) -> Result<(), KeyLifecycleError> {
        Err(KeyLifecycleError::BackendFailure)
    }

    fn reset_credential_keys(&mut self) -> Result<(), KeyLifecycleError> {
        Err(KeyLifecycleError::BackendFailure)
    }

    fn generate_es256_key(&mut self, key_material: &[u8; KEY_MATERIAL_LEN]) -> Option<()>;

    fn public_key_xy(
        &mut self,
        key_material: &[u8; KEY_MATERIAL_LEN],
    ) -> Option<([u8; 32], [u8; 32])>;

    fn sign<'a>(
        &mut self,
        key_material: &[u8; KEY_MATERIAL_LEN],
        auth_data: &[u8],
        client_data_hash: &[u8; 32],
        signature_buf: &'a mut [u8],
    ) -> Option<&'a [u8]>;

    fn hmac_secret_cred_random(
        &mut self,
        _key_material: &[u8; KEY_MATERIAL_LEN],
        _user_verified: bool,
    ) -> Option<[u8; 32]> {
        None
    }
}

pub struct SecureElementPrivateKeyStore<E> {
    element: E,
}

impl<E> SecureElementPrivateKeyStore<E> {
    pub const fn new(element: E) -> Self {
        Self { element }
    }

    pub fn into_inner(self) -> E {
        self.element
    }
}

impl<S: SecureElement> PrivateKeyStore for SecureElementPrivateKeyStore<S> {
    fn release_key_material(
        &mut self,
        algorithm: CredentialAlgorithm,
        material: &[u8; KEY_MATERIAL_LEN],
    ) -> Result<(), KeyLifecycleError> {
        if algorithm != CredentialAlgorithm::Es256 {
            return Err(KeyLifecycleError::InvalidHandle);
        }
        self.element.release_key(material)
    }

    fn reset_credential_keys(&mut self) -> Result<(), KeyLifecycleError> {
        self.element.reset_credential_keys()
    }
    fn create_key_material<E: EntropySource>(
        &mut self,
        _credential_id: &[u8; CREDENTIAL_ID_LEN],
        entropy: &mut E,
    ) -> Option<[u8; KEY_MATERIAL_LEN]> {
        let key_material = crypto::generate_random_bytes(entropy)?;
        self.element.generate_es256_key(&key_material)?;
        Some(key_material)
    }

    fn public_key_xy(
        &mut self,
        key_material: &[u8; KEY_MATERIAL_LEN],
    ) -> Option<([u8; 32], [u8; 32])> {
        self.element.public_key_xy(key_material)
    }

    fn sign<'a>(
        &mut self,
        key_material: &[u8; KEY_MATERIAL_LEN],
        auth_data: &[u8],
        client_data_hash: &[u8; 32],
        signature_buf: &'a mut [u8],
    ) -> Option<&'a [u8]> {
        self.element
            .sign(key_material, auth_data, client_data_hash, signature_buf)
    }

    fn hmac_secret_cred_random(
        &mut self,
        key_material: &[u8; KEY_MATERIAL_LEN],
        user_verified: bool,
    ) -> Option<[u8; 32]> {
        self.element
            .hmac_secret_cred_random(key_material, user_verified)
    }
}
