use crate::ctaphid::{
    crypto,
    entropy::EntropySource,
    key_store::{KEY_MATERIAL_LEN as KEY_STORE_MATERIAL_LEN, PrivateKeyStore},
    storage::{MAX_RECORDS, Storage, StorageBackend},
};

pub const CREDENTIAL_ID_LEN: usize = 16;

pub const SIGN_COUNT_LEN: usize = 4;

pub const KEY_MATERIAL_LEN: usize = KEY_STORE_MATERIAL_LEN;

pub const PRIVATE_KEY_LEN: usize = KEY_MATERIAL_LEN;

pub const RP_ID_HASH_LEN: usize = 32;

pub const RP_ID_MAX_LEN: usize = 64;

pub const USER_ID_MAX_LEN: usize = 32;

pub const USER_NAME_MAX_LEN: usize = 32;

pub const USER_DISPLAY_NAME_MAX_LEN: usize = 32;

pub const CRED_BLOB_MAX_LEN: usize = 32;

pub(crate) const V5_RECORD_LEN: usize = 254;

pub(crate) const V6_RECORD_LEN: usize = V5_RECORD_LEN + 1 + CRED_BLOB_MAX_LEN;

pub const RECORD_LEN: usize = V6_RECORD_LEN + 1;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CredentialAlgorithm {
    Es256,
    MlDsa44,
}

impl CredentialAlgorithm {
    pub const fn cose_algorithm(self) -> i8 {
        match self {
            Self::Es256 => -7,
            Self::MlDsa44 => -48,
        }
    }

    pub const fn from_cose_algorithm(value: i64) -> Option<Self> {
        match value {
            -7 => Some(Self::Es256),
            -48 => Some(Self::MlDsa44),
            _ => None,
        }
    }

    const fn storage_id(self) -> u8 {
        match self {
            Self::Es256 => 1,
            Self::MlDsa44 => 2,
        }
    }

    const fn from_storage_id(value: u8) -> Option<Self> {
        match value {
            1 => Some(Self::Es256),
            2 => Some(Self::MlDsa44),
            _ => None,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CredentialProtection {
    UserVerificationOptional = 1,

    UserVerificationOptionalWithCredentialIdList = 2,

    UserVerificationRequired = 3,
}

impl CredentialProtection {
    pub const fn from_ctap_value(value: u64) -> Option<Self> {
        match value {
            1 => Some(Self::UserVerificationOptional),
            2 => Some(Self::UserVerificationOptionalWithCredentialIdList),
            3 => Some(Self::UserVerificationRequired),
            _ => None,
        }
    }

    pub const fn ctap_value(self) -> u8 {
        self as u8
    }
}

const MAGIC: [u8; 4] = *b"FDC5";
const V6_MAGIC: [u8; 4] = *b"FDC4";
const V5_MAGIC: [u8; 4] = *b"FDC3";

#[derive(Clone, Copy)]
/// Contains sensitive key material and user data; Copy duplicates it and drop does not erase it.
pub struct Credential {
    pub id: [u8; CREDENTIAL_ID_LEN],

    pub algorithm: CredentialAlgorithm,

    pub key_material: [u8; KEY_MATERIAL_LEN],

    pub user_id: [u8; USER_ID_MAX_LEN],

    pub user_id_len: u8,

    pub user_name: [u8; USER_NAME_MAX_LEN],

    pub user_name_len: u8,

    pub user_display_name: [u8; USER_DISPLAY_NAME_MAX_LEN],

    pub user_display_name_len: u8,

    pub is_resident: bool,

    pub protection: CredentialProtection,

    pub cred_blob: [u8; CRED_BLOB_MAX_LEN],

    pub cred_blob_len: u8,

    pub sign_count: u32,
}

#[derive(Clone, Copy)]
/// Plaintext record codec; storage adapters supply confidentiality, integrity and rollback policy.
pub struct CredentialRecord {
    pub rp_id_hash: [u8; RP_ID_HASH_LEN],

    pub rp_id: [u8; RP_ID_MAX_LEN],

    pub rp_id_len: u8,

    pub credential: Credential,
}

#[derive(Clone, Copy)]
pub struct ResidentRp {
    pub rp_id_hash: [u8; RP_ID_HASH_LEN],

    pub rp_id: [u8; RP_ID_MAX_LEN],

    pub rp_id_len: u8,
}

impl ResidentRp {
    pub const fn empty() -> Self {
        Self {
            rp_id_hash: [0; RP_ID_HASH_LEN],
            rp_id: [0; RP_ID_MAX_LEN],
            rp_id_len: 0,
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum CredentialError {
    KeyGenerationFailed,

    InvalidInput,

    StorageFull,

    StorageFailed,
}

fn generate_credential<K: PrivateKeyStore, E: EntropySource>(
    key_store: &mut K,
    entropy: &mut E,
    algorithm: CredentialAlgorithm,
    user_id: &[u8],
    user_name: &[u8],
    user_display_name: &[u8],
    is_resident: bool,
    protection: CredentialProtection,
    cred_blob: Option<&[u8]>,
) -> Option<Credential> {
    if user_id.len() > USER_ID_MAX_LEN
        || user_name.len() > USER_NAME_MAX_LEN
        || user_display_name.len() > USER_DISPLAY_NAME_MAX_LEN
        || cred_blob.is_some_and(|value| value.len() > CRED_BLOB_MAX_LEN)
    {
        return None;
    }
    let id = crypto::generate_random_bytes(entropy)?;
    let key_material = key_store.create_key_material_for_algorithm(algorithm, &id, entropy)?;

    Some(Credential {
        id,
        algorithm,
        key_material,
        user_id: {
            let mut value = [0; USER_ID_MAX_LEN];
            value[..user_id.len()].copy_from_slice(user_id);
            value
        },
        user_id_len: user_id.len() as u8,
        user_name: {
            let mut value = [0; USER_NAME_MAX_LEN];
            value[..user_name.len()].copy_from_slice(user_name);
            value
        },
        user_name_len: user_name.len() as u8,
        user_display_name: {
            let mut value = [0; USER_DISPLAY_NAME_MAX_LEN];
            value[..user_display_name.len()].copy_from_slice(user_display_name);
            value
        },
        user_display_name_len: user_display_name.len() as u8,
        is_resident,
        protection,
        cred_blob: {
            let mut value = [0; CRED_BLOB_MAX_LEN];
            if let Some(blob) = cred_blob {
                value[..blob.len()].copy_from_slice(blob);
            }
            value
        },
        cred_blob_len: cred_blob.map_or(0, |value| value.len() as u8),
        sign_count: 0,
    })
}

fn credential_id_is_in_use<B: StorageBackend>(
    storage: &mut Storage<B>,
    credential_id: &[u8; CREDENTIAL_ID_LEN],
) -> bool {
    for index in 0..MAX_RECORDS {
        let Some(record) = storage.load_record(index) else {
            continue;
        };

        if &record.credential.id == credential_id {
            return true;
        }
    }

    false
}

pub fn find_record_by_id<B: StorageBackend>(
    storage: &mut Storage<B>,
    credential_id: &[u8; CREDENTIAL_ID_LEN],
) -> Option<(usize, CredentialRecord)> {
    for index in 0..MAX_RECORDS {
        let Some(record) = storage.load_record(index) else {
            continue;
        };

        if &record.credential.id == credential_id {
            return Some((index, record));
        }
    }

    None
}

/// Deletes the journal record only; resource-owning key stores require separate key release.
pub fn delete_by_id<B: StorageBackend>(
    storage: &mut Storage<B>,
    credential_id: &[u8; CREDENTIAL_ID_LEN],
) -> Result<bool, CredentialError> {
    let Some((index, _)) = find_record_by_id(storage, credential_id) else {
        return Ok(false);
    };

    storage
        .delete_record(index)
        .map_err(|_| CredentialError::StorageFailed)
}

pub fn update_user_by_id<B: StorageBackend>(
    storage: &mut Storage<B>,
    credential_id: &[u8; CREDENTIAL_ID_LEN],
    user_id: &[u8],
    user_name: &[u8],
    user_display_name: &[u8],
) -> Result<bool, CredentialError> {
    if user_id.len() > USER_ID_MAX_LEN
        || user_name.len() > USER_NAME_MAX_LEN
        || user_display_name.len() > USER_DISPLAY_NAME_MAX_LEN
    {
        return Err(CredentialError::InvalidInput);
    }

    let Some((index, mut record)) = find_record_by_id(storage, credential_id) else {
        return Ok(false);
    };

    record.credential.user_id = [0; USER_ID_MAX_LEN];
    record.credential.user_id[..user_id.len()].copy_from_slice(user_id);
    record.credential.user_id_len = user_id.len() as u8;
    record.credential.user_name = [0; USER_NAME_MAX_LEN];
    record.credential.user_name[..user_name.len()].copy_from_slice(user_name);
    record.credential.user_name_len = user_name.len() as u8;
    record.credential.user_display_name = [0; USER_DISPLAY_NAME_MAX_LEN];
    record.credential.user_display_name[..user_display_name.len()]
        .copy_from_slice(user_display_name);
    record.credential.user_display_name_len = user_display_name.len() as u8;

    storage
        .save_record(index, &record)
        .map_err(|_| CredentialError::StorageFailed)?;

    Ok(true)
}

pub fn create_with_key_store<B: StorageBackend, K: PrivateKeyStore, E: EntropySource>(
    storage: &mut Storage<B>,
    key_store: &mut K,
    entropy: &mut E,
    rp_id: &[u8],
    user_id: &[u8],
    user_name: &[u8],
    user_display_name: &[u8],
    is_resident: bool,
    protection: CredentialProtection,
    rp_id_hash: [u8; RP_ID_HASH_LEN],
) -> Result<Credential, CredentialError> {
    create_with_key_store_and_cred_blob(
        storage,
        key_store,
        entropy,
        rp_id,
        user_id,
        user_name,
        user_display_name,
        is_resident,
        protection,
        rp_id_hash,
        None,
    )
}

pub fn create_with_key_store_and_cred_blob<
    B: StorageBackend,
    K: PrivateKeyStore,
    E: EntropySource,
>(
    storage: &mut Storage<B>,
    key_store: &mut K,
    entropy: &mut E,
    rp_id: &[u8],
    user_id: &[u8],
    user_name: &[u8],
    user_display_name: &[u8],
    is_resident: bool,
    protection: CredentialProtection,
    rp_id_hash: [u8; RP_ID_HASH_LEN],
    cred_blob: Option<&[u8]>,
) -> Result<Credential, CredentialError> {
    create_with_key_store_algorithm_and_cred_blob(
        storage,
        key_store,
        entropy,
        CredentialAlgorithm::Es256,
        rp_id,
        user_id,
        user_name,
        user_display_name,
        is_resident,
        protection,
        rp_id_hash,
        cred_blob,
    )
}

/// Creates bounded credential material; failed persistence must be reconciled by the backend.
/// Do not keep using generated key material after a failed create.
pub fn create_with_key_store_algorithm_and_cred_blob<
    B: StorageBackend,
    K: PrivateKeyStore,
    E: EntropySource,
>(
    storage: &mut Storage<B>,
    key_store: &mut K,
    entropy: &mut E,
    algorithm: CredentialAlgorithm,
    rp_id: &[u8],
    user_id: &[u8],
    user_name: &[u8],
    user_display_name: &[u8],
    is_resident: bool,
    protection: CredentialProtection,
    rp_id_hash: [u8; RP_ID_HASH_LEN],
    cred_blob: Option<&[u8]>,
) -> Result<Credential, CredentialError> {
    if !key_store.supports_algorithm(algorithm) {
        return Err(CredentialError::KeyGenerationFailed);
    }
    if rp_id.len() > RP_ID_MAX_LEN {
        return Err(CredentialError::KeyGenerationFailed);
    }

    let index = storage
        .first_empty_record_index()
        .ok_or(CredentialError::StorageFull)?;

    let mut generated = None;
    for _ in 0..16 {
        if let Some(credential) = generate_credential(
            key_store,
            entropy,
            algorithm,
            user_id,
            user_name,
            user_display_name,
            is_resident,
            protection,
            cred_blob,
        ) {
            if credential_id_is_in_use(storage, &credential.id) {
                key_store
                    .release_key_material(algorithm, &credential.key_material)
                    .map_err(|_| CredentialError::KeyGenerationFailed)?;
            } else {
                generated = Some(credential);
                break;
            }
        }
    }
    let credential = generated.ok_or(CredentialError::KeyGenerationFailed)?;
    let record = CredentialRecord::from_credential_with_rp_id(rp_id_hash, rp_id, credential)
        .ok_or(CredentialError::KeyGenerationFailed)?;

    if storage.save_record(index, &record).is_err() {
        let _ = key_store.release_key_material(algorithm, &credential.key_material);
        return Err(CredentialError::StorageFailed);
    }

    Ok(record.credential)
}

#[allow(dead_code)]
pub fn find_by_rp<B: StorageBackend>(
    storage: &mut Storage<B>,
    rp_id_hash: [u8; RP_ID_HASH_LEN],
) -> Option<Credential> {
    find_record_index_by_rp(storage, rp_id_hash)
        .and_then(|index| storage.load_record(index))
        .map(|record| record.credential)
}

#[allow(dead_code)]
pub fn find_by_rp_and_id<B: StorageBackend>(
    storage: &mut Storage<B>,
    rp_id_hash: [u8; RP_ID_HASH_LEN],
    credential_id: &[u8],
) -> Option<Credential> {
    find_record_index_by_rp_and_id(storage, rp_id_hash, credential_id)
        .and_then(|index| storage.load_record(index))
        .map(|record| record.credential)
}

pub fn any_id_matches_rp<B: StorageBackend>(
    storage: &mut Storage<B>,
    rp_id_hash: [u8; RP_ID_HASH_LEN],
    mut matches_id: impl FnMut(&[u8]) -> Option<bool>,
) -> Option<bool> {
    for index in 0..MAX_RECORDS {
        let Some(record) = storage.load_record(index) else {
            continue;
        };

        if record.rp_id_hash == rp_id_hash && matches_id(&record.credential.id)? {
            return Some(true);
        }
    }

    Some(false)
}

pub fn try_any_id_matches_rp<B: StorageBackend, E>(
    storage: &mut Storage<B>,
    rp_id_hash: [u8; RP_ID_HASH_LEN],
    mut matches_id: impl FnMut(&[u8]) -> Result<bool, E>,
) -> Result<bool, E> {
    for index in 0..MAX_RECORDS {
        let Some(record) = storage.load_record(index) else {
            continue;
        };

        if record.rp_id_hash == rp_id_hash && matches_id(&record.credential.id)? {
            return Ok(true);
        }
    }

    Ok(false)
}

pub fn count_by_rp<B: StorageBackend>(
    storage: &mut Storage<B>,
    rp_id_hash: [u8; RP_ID_HASH_LEN],
) -> usize {
    let mut count = 0;

    for index in 0..MAX_RECORDS {
        let Some(record) = storage.load_record(index) else {
            continue;
        };

        if record.rp_id_hash == rp_id_hash {
            count += 1;
        }
    }

    count
}

pub fn count_resident<B: StorageBackend>(storage: &mut Storage<B>) -> usize {
    let mut count = 0;

    for index in 0..MAX_RECORDS {
        let Some(record) = storage.load_record(index) else {
            continue;
        };

        if record.credential.is_resident {
            count += 1;
        }
    }

    count
}

pub fn remaining_record_capacity<B: StorageBackend>(storage: &mut Storage<B>) -> usize {
    let mut count = 0;

    for index in 0..MAX_RECORDS {
        if storage.load_record(index).is_none() {
            count += 1;
        }
    }

    count
}

pub fn collect_unique_resident_rps<B: StorageBackend>(
    storage: &mut Storage<B>,
    out: &mut [ResidentRp; MAX_RECORDS],
) -> usize {
    let mut count = 0;

    for index in 0..MAX_RECORDS {
        let Some(record) = storage.load_record(index) else {
            continue;
        };
        if !record.credential.is_resident || record.rp_id_len == 0 {
            continue;
        }
        if out[..count]
            .iter()
            .any(|rp| rp.rp_id_hash == record.rp_id_hash)
        {
            continue;
        }
        if count >= MAX_RECORDS {
            break;
        }

        out[count] = ResidentRp {
            rp_id_hash: record.rp_id_hash,
            rp_id: record.rp_id,
            rp_id_len: record.rp_id_len,
        };
        count += 1;
    }

    count
}

pub fn collect_resident_credential_indices_by_rp<B: StorageBackend>(
    storage: &mut Storage<B>,
    rp_id_hash: [u8; RP_ID_HASH_LEN],
    indices: &mut [u8; MAX_RECORDS],
) -> usize {
    let mut count = 0;

    for index in 0..MAX_RECORDS {
        let Some(record) = storage.load_record(index) else {
            continue;
        };
        if record.rp_id_hash == rp_id_hash && record.credential.is_resident {
            indices[count] = index as u8;
            count += 1;
        }
    }

    count
}

pub fn find_and_increment_sign_count<B: StorageBackend>(
    storage: &mut Storage<B>,
    rp_id_hash: [u8; RP_ID_HASH_LEN],
    credential_id: Option<&[u8]>,
) -> Option<(Credential, u32)> {
    let index = if let Some(credential_id) = credential_id {
        find_record_index_by_rp_and_id(storage, rp_id_hash, credential_id)?
    } else {
        find_record_index_by_rp(storage, rp_id_hash)?
    };

    increment_sign_count_at(storage, index)
}

/// Persists the increment before returning; missing records, write failure and overflow return None.
pub fn increment_sign_count_at<B: StorageBackend>(
    storage: &mut Storage<B>,
    index: usize,
) -> Option<(Credential, u32)> {
    let mut record = storage.load_record(index)?;
    record.credential.sign_count = record.credential.sign_count.checked_add(1)?;
    let sign_count = record.credential.sign_count;
    storage.save_record(index, &record).ok()?;

    Some((record.credential, sign_count))
}

fn find_record_index_by_rp<B: StorageBackend>(
    storage: &mut Storage<B>,
    rp_id_hash: [u8; RP_ID_HASH_LEN],
) -> Option<usize> {
    for index in 0..MAX_RECORDS {
        let Some(record) = storage.load_record(index) else {
            continue;
        };

        if record.rp_id_hash == rp_id_hash
            && record.credential.algorithm == CredentialAlgorithm::Es256
        {
            return Some(index);
        }
    }

    None
}

fn find_record_index_by_rp_and_id<B: StorageBackend>(
    storage: &mut Storage<B>,
    rp_id_hash: [u8; RP_ID_HASH_LEN],
    credential_id: &[u8],
) -> Option<usize> {
    for index in 0..MAX_RECORDS {
        let Some(record) = storage.load_record(index) else {
            continue;
        };

        if record.rp_id_hash == rp_id_hash
            && record.credential.id == credential_id
            && record.credential.algorithm == CredentialAlgorithm::Es256
        {
            return Some(index);
        }
    }

    None
}

impl CredentialRecord {
    pub fn from_credential(rp_id_hash: [u8; RP_ID_HASH_LEN], credential: Credential) -> Self {
        Self::from_credential_with_rp_id(rp_id_hash, &[], credential)
            .expect("empty RP ID always fits")
    }

    pub fn from_credential_with_rp_id(
        rp_id_hash: [u8; RP_ID_HASH_LEN],
        rp_id: &[u8],
        credential: Credential,
    ) -> Option<Self> {
        if rp_id.len() > RP_ID_MAX_LEN {
            return None;
        }

        let mut rp_id_buf = [0; RP_ID_MAX_LEN];
        rp_id_buf[..rp_id.len()].copy_from_slice(rp_id);

        Some(Self {
            rp_id_hash,
            rp_id: rp_id_buf,
            rp_id_len: rp_id.len() as u8,
            credential,
        })
    }

    pub fn encode(&self, buf: &mut [u8; RECORD_LEN]) {
        buf[0..4].copy_from_slice(&MAGIC);

        let rp_start = 4;
        buf[rp_start..rp_start + RP_ID_HASH_LEN].copy_from_slice(&self.rp_id_hash);

        let rp_id_len_start = rp_start + RP_ID_HASH_LEN;
        buf[rp_id_len_start] = self.rp_id_len;
        buf[rp_id_len_start + 1..rp_id_len_start + 1 + RP_ID_MAX_LEN].copy_from_slice(&self.rp_id);

        let id_start = rp_id_len_start + 1 + RP_ID_MAX_LEN;
        buf[id_start..id_start + CREDENTIAL_ID_LEN].copy_from_slice(&self.credential.id);

        let key_start = id_start + CREDENTIAL_ID_LEN;
        buf[key_start..key_start + KEY_MATERIAL_LEN].copy_from_slice(&self.credential.key_material);

        let sign_count_start = key_start + KEY_MATERIAL_LEN;
        buf[sign_count_start..sign_count_start + SIGN_COUNT_LEN]
            .copy_from_slice(&self.credential.sign_count.to_be_bytes());
        let user_len_start = sign_count_start + SIGN_COUNT_LEN;
        buf[user_len_start] = self.credential.user_id_len;
        buf[user_len_start + 1..user_len_start + 1 + USER_ID_MAX_LEN]
            .copy_from_slice(&self.credential.user_id);
        let user_name_len_start = user_len_start + 1 + USER_ID_MAX_LEN;
        buf[user_name_len_start] = self.credential.user_name_len;
        buf[user_name_len_start + 1..user_name_len_start + 1 + USER_NAME_MAX_LEN]
            .copy_from_slice(&self.credential.user_name);
        let user_display_name_len_start = user_name_len_start + 1 + USER_NAME_MAX_LEN;
        buf[user_display_name_len_start] = self.credential.user_display_name_len;
        buf[user_display_name_len_start + 1
            ..user_display_name_len_start + 1 + USER_DISPLAY_NAME_MAX_LEN]
            .copy_from_slice(&self.credential.user_display_name);
        buf[user_display_name_len_start + 1 + USER_DISPLAY_NAME_MAX_LEN] =
            self.credential.is_resident as u8;
        let protection_start = user_display_name_len_start + 2 + USER_DISPLAY_NAME_MAX_LEN;
        buf[protection_start] = self.credential.protection.ctap_value();
        buf[protection_start + 1] = self.credential.cred_blob_len;
        buf[protection_start + 2..protection_start + 2 + CRED_BLOB_MAX_LEN]
            .copy_from_slice(&self.credential.cred_blob);
        buf[protection_start + 2 + CRED_BLOB_MAX_LEN] = self.credential.algorithm.storage_id();
    }

    pub fn decode(buf: &[u8; RECORD_LEN]) -> Option<Self> {
        Self::decode_bytes(buf, MAGIC, true, true)
    }

    pub(crate) fn decode_v6(buf: &[u8; V6_RECORD_LEN]) -> Option<Self> {
        Self::decode_bytes(buf, V6_MAGIC, true, false)
    }

    pub(crate) fn decode_v5(buf: &[u8; V5_RECORD_LEN]) -> Option<Self> {
        Self::decode_bytes(buf, V5_MAGIC, false, false)
    }

    fn decode_bytes(
        buf: &[u8],
        magic: [u8; 4],
        has_cred_blob: bool,
        has_algorithm: bool,
    ) -> Option<Self> {
        if buf[0..4] != magic {
            return None;
        }

        let mut rp = [0u8; RP_ID_HASH_LEN];
        let rp_start = 4;
        rp.copy_from_slice(&buf[rp_start..rp_start + RP_ID_HASH_LEN]);

        let rp_id_len_start = rp_start + RP_ID_HASH_LEN;
        let rp_id_len = buf[rp_id_len_start];
        if rp_id_len as usize > RP_ID_MAX_LEN {
            return None;
        }
        let mut rp_id = [0u8; RP_ID_MAX_LEN];
        rp_id.copy_from_slice(&buf[rp_id_len_start + 1..rp_id_len_start + 1 + RP_ID_MAX_LEN]);

        let id_start = rp_id_len_start + 1 + RP_ID_MAX_LEN;
        let mut id = [0u8; CREDENTIAL_ID_LEN];
        id.copy_from_slice(&buf[id_start..id_start + CREDENTIAL_ID_LEN]);

        let key_start = id_start + CREDENTIAL_ID_LEN;
        let mut key_material = [0u8; KEY_MATERIAL_LEN];
        key_material.copy_from_slice(&buf[key_start..key_start + KEY_MATERIAL_LEN]);

        let sign_count_start = key_start + KEY_MATERIAL_LEN;
        let sign_count = u32::from_be_bytes([
            buf[sign_count_start],
            buf[sign_count_start + 1],
            buf[sign_count_start + 2],
            buf[sign_count_start + 3],
        ]);
        let user_len_start = sign_count_start + SIGN_COUNT_LEN;
        let user_id_len = buf[user_len_start];
        if user_id_len as usize > USER_ID_MAX_LEN {
            return None;
        }
        let mut user_id = [0u8; USER_ID_MAX_LEN];
        user_id.copy_from_slice(&buf[user_len_start + 1..user_len_start + 1 + USER_ID_MAX_LEN]);
        let user_name_len_start = user_len_start + 1 + USER_ID_MAX_LEN;
        let user_name_len = buf[user_name_len_start];
        if user_name_len as usize > USER_NAME_MAX_LEN {
            return None;
        }
        let mut user_name = [0u8; USER_NAME_MAX_LEN];
        user_name.copy_from_slice(
            &buf[user_name_len_start + 1..user_name_len_start + 1 + USER_NAME_MAX_LEN],
        );
        let user_display_name_len_start = user_name_len_start + 1 + USER_NAME_MAX_LEN;
        let user_display_name_len = buf[user_display_name_len_start];
        if user_display_name_len as usize > USER_DISPLAY_NAME_MAX_LEN {
            return None;
        }
        let mut user_display_name = [0u8; USER_DISPLAY_NAME_MAX_LEN];
        user_display_name.copy_from_slice(
            &buf[user_display_name_len_start + 1
                ..user_display_name_len_start + 1 + USER_DISPLAY_NAME_MAX_LEN],
        );
        let is_resident = match buf[user_display_name_len_start + 1 + USER_DISPLAY_NAME_MAX_LEN] {
            0 => false,
            1 => true,
            _ => return None,
        };
        let protection_start = user_display_name_len_start + 2 + USER_DISPLAY_NAME_MAX_LEN;
        let protection = CredentialProtection::from_ctap_value(buf[protection_start] as u64)?;
        let (cred_blob, cred_blob_len) = if has_cred_blob {
            let cred_blob_len = buf[protection_start + 1];
            if cred_blob_len as usize > CRED_BLOB_MAX_LEN {
                return None;
            }
            let mut cred_blob = [0u8; CRED_BLOB_MAX_LEN];
            cred_blob.copy_from_slice(
                &buf[protection_start + 2..protection_start + 2 + CRED_BLOB_MAX_LEN],
            );
            (cred_blob, cred_blob_len)
        } else {
            ([0; CRED_BLOB_MAX_LEN], 0)
        };
        let algorithm = if has_algorithm {
            CredentialAlgorithm::from_storage_id(buf[protection_start + 2 + CRED_BLOB_MAX_LEN])?
        } else {
            CredentialAlgorithm::Es256
        };

        Some(Self {
            rp_id_hash: rp,
            rp_id,
            rp_id_len,
            credential: Credential {
                id,
                algorithm,
                key_material,
                user_id,
                user_id_len,
                user_name,
                user_name_len,
                user_display_name,
                user_display_name_len,
                is_resident,
                protection,
                cred_blob,
                cred_blob_len,
                sign_count,
            },
        })
    }
}
