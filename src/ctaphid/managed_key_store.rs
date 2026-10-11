


use zeroize::Zeroizing;

use super::{
    credential::CredentialAlgorithm,
    crypto::{self, Es256Backend},
    entropy::EntropySource,
    hash::{Sha256Backend, SoftwareSha256},
    key_handle::{ManagedKeyHeader, authenticate_managed_key, bind_managed_key},
    key_store::{KeyLifecycleError, PrivateKeyStore},
    storage::{MAX_RECORDS, Storage, StorageBackend},
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ManagedKeyError {
    Timeout,
    Hardware,
    ForeignAsset,
    MissingAsset,
    InvalidHandle,
    Entropy,
    Full,
    CorruptStorage,
    InvalidConfiguration,
}


#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KeyPersistenceProtection {
    // Describes the medium only, not boundary isolation, debug protection or K3.
    Plaintext,
    HardwareAccessControlled,
    HardwareWrapped,
}








pub trait RamKeyStorage {
    // Single-owner synchronous storage with a final incarnation commit.
    // nonce returns None only for absent/uncommitted assets, never for I/O failures.
    // provision cannot replace a live asset. release is idempotent, invalidates
    // control before reclaiming material and cannot erase another owner's asset.
    // This interface requires legitimate RAM expansion; CPU-invisible keys need
    // a separate operation interface. Dispatcher/port owns authorization/isolation.
    fn capacity(&self) -> usize;
    fn protection(&self) -> KeyPersistenceProtection;
    fn nonce(&mut self, index: usize) -> Result<Option<[u8; 16]>, ManagedKeyError>;
    fn load_private(&mut self, index: usize) -> Result<Zeroizing<[u8; 32]>, ManagedKeyError>;
    fn provision(
        &mut self,
        index: usize,
        private: &[u8; 32],
        nonce: &[u8; 16],
    ) -> Result<(), ManagedKeyError>;
    fn release(&mut self, index: usize) -> Result<(), ManagedKeyError>;
}

pub struct ManagedPrivateKeyStore<S, C, H = SoftwareSha256> {
    storage: S,
    root: Zeroizing<[u8; 32]>,
    signature: C,
    hash: H,
    domain: &'static [u8],
    cred_random_domain: &'static [u8],
}

impl<S: RamKeyStorage, C: Es256Backend> ManagedPrivateKeyStore<S, C> {
    pub fn new(
        storage: S,
        root: Zeroizing<[u8; 32]>,
        signature: C,
        domain: &'static [u8],
        cred_random_domain: &'static [u8],
    ) -> Result<Self, ManagedKeyError> {
        Self::new_with_hash(
            storage,
            root,
            signature,
            domain,
            cred_random_domain,
            SoftwareSha256,
        )
    }
}

impl<S: RamKeyStorage, C: Es256Backend, H: Sha256Backend> ManagedPrivateKeyStore<S, C, H> {
    pub fn new_with_hash(
        storage: S,
        root: Zeroizing<[u8; 32]>,
        signature: C,
        domain: &'static [u8],
        cred_random_domain: &'static [u8],
        hash: H,
    ) -> Result<Self, ManagedKeyError> {
        if storage.capacity() == 0
            || storage.capacity() > MAX_RECORDS
            || domain.is_empty()
            || cred_random_domain.is_empty()
        {
            return Err(ManagedKeyError::InvalidConfiguration);
        }
        Ok(Self {
            storage,
            root,
            signature,
            hash,
            domain,
            cred_random_domain,
        })
    }

    pub fn protection(&self) -> KeyPersistenceProtection {
        self.storage.protection()
    }

    pub fn into_storage(self) -> S {
        self.storage
    }

    fn authenticate(&mut self, material: &[u8; 32]) -> Result<ManagedKeyHeader, ManagedKeyError> {
        let header =
            ManagedKeyHeader::decode(&material[..16]).ok_or(ManagedKeyError::InvalidHandle)?;
        if usize::from(header.resource) >= self.storage.capacity() {
            return Err(ManagedKeyError::InvalidHandle);
        }
        let nonce = self
            .storage
            .nonce(usize::from(header.resource))?
            .ok_or(ManagedKeyError::InvalidHandle)?;
        authenticate_managed_key(
            &mut self.hash,
            &self.root,
            self.domain,
            material,
            &nonce,
            self.storage.capacity(),
        )
        .ok_or(ManagedKeyError::InvalidHandle)
    }

    fn private(&mut self, material: &[u8; 32]) -> Result<Zeroizing<[u8; 32]>, ManagedKeyError> {
        let header = self.authenticate(material)?;
        let private = self.storage.load_private(usize::from(header.resource))?;
        if !crypto::p256_private_scalar_is_valid(&private) {
            return Err(ManagedKeyError::InvalidHandle);
        }
        Ok(private)
    }


    pub fn reconcile<B: StorageBackend>(
        &mut self,
        journal: &mut Storage<B>,
    ) -> Result<(), ManagedKeyError> {
        let mut live = [false; MAX_RECORDS];
        for index in 0..MAX_RECORDS {
            let Some(record) = journal
                .load_record_checked(index)
                .map_err(|_| ManagedKeyError::CorruptStorage)?
            else {
                continue;
            };
            if record.credential.algorithm != CredentialAlgorithm::Es256 {
                continue;
            }
            let header = self.authenticate(&record.credential.key_material)?;
            let resource = usize::from(header.resource);
            if live[resource] {
                return Err(ManagedKeyError::InvalidHandle);
            }
            self.private(&record.credential.key_material)?;
            live[resource] = true;
        }
        for (index, active) in live[..self.storage.capacity()].iter().enumerate() {
            if !active {
                self.storage.release(index)?;
            }
        }
        Ok(())
    }

    fn generate<E: EntropySource>(&mut self, entropy: &mut E) -> Result<[u8; 32], ManagedKeyError> {
        let mut available = None;
        for index in 0..self.storage.capacity() {
            if self.storage.nonce(index)?.is_none() {
                available = Some(index);
                break;
            }
        }
        let index = available.ok_or(ManagedKeyError::Full)?;
        self.storage.release(index)?;
        let private =
            Zeroizing::new(crypto::generate_private_key(entropy).ok_or(ManagedKeyError::Entropy)?);
        let nonce: [u8; 16] =
            crypto::generate_random_bytes(entropy).ok_or(ManagedKeyError::Entropy)?;
        let handle = bind_managed_key(
            &mut self.hash,
            &self.root,
            self.domain,
            ManagedKeyHeader {
                resource: index as u16,
                generation: u64::from_le_bytes(nonce[..8].try_into().unwrap()),
            },
            &nonce,
        )
        .ok_or(ManagedKeyError::Hardware)?;
        if let Err(error) = self.storage.provision(index, &private, &nonce) {
            self.storage.release(index)?;
            return Err(error);
        }
        Ok(handle)
    }
}

impl<S: RamKeyStorage, C: Es256Backend, H: Sha256Backend> PrivateKeyStore
    for ManagedPrivateKeyStore<S, C, H>
{
    fn create_key_material<E: EntropySource>(
        &mut self,
        _: &[u8; 16],
        entropy: &mut E,
    ) -> Option<[u8; 32]> {
        self.generate(entropy).ok()
    }

    fn public_key_xy(&mut self, material: &[u8; 32]) -> Option<([u8; 32], [u8; 32])> {
        let private = self.private(material).ok()?;
        self.signature.public_key_xy(&private).ok()
    }

    fn sign<'a>(
        &mut self,
        material: &[u8; 32],
        auth_data: &[u8],
        client_hash: &[u8; 32],
        output: &'a mut [u8],
    ) -> Option<&'a [u8]> {
        let private = self.private(material).ok()?;
        self.signature
            .sign_webauthn_der(&private, auth_data, client_hash, output)
            .ok()
    }

    fn hmac_secret_cred_random(&mut self, material: &[u8; 32], verified: bool) -> Option<[u8; 32]> {
        self.private(material).ok()?;
        crypto::hmac_sha256_with_hash(
            &mut self.hash,
            &*self.root,
            &[self.cred_random_domain, &[u8::from(verified)], material],
        )
    }

    fn release_key_material(
        &mut self,
        algorithm: CredentialAlgorithm,
        material: &[u8; 32],
    ) -> Result<(), KeyLifecycleError> {
        if algorithm != CredentialAlgorithm::Es256 {
            return Err(KeyLifecycleError::InvalidHandle);
        }
        let header =
            ManagedKeyHeader::decode(&material[..16]).ok_or(KeyLifecycleError::InvalidHandle)?;
        let index = usize::from(header.resource);
        if index >= self.storage.capacity() {
            return Err(KeyLifecycleError::InvalidHandle);
        }
        if self
            .storage
            .nonce(index)
            .map_err(|_| KeyLifecycleError::BackendFailure)?
            .is_some()
        {
            self.authenticate(material)
                .map_err(|_| KeyLifecycleError::InvalidHandle)?;
        }
        self.storage
            .release(index)
            .map_err(|_| KeyLifecycleError::BackendFailure)
    }

    fn reset_credential_keys(&mut self) -> Result<(), KeyLifecycleError> {
        for index in 0..self.storage.capacity() {
            self.storage
                .release(index)
                .map_err(|_| KeyLifecycleError::BackendFailure)?;
        }
        Ok(())
    }
}



