#[cfg(all(target_arch = "arm", target_os = "none", feature = "defmt-log"))]
use defmt::debug;
#[cfg(not(all(target_arch = "arm", target_os = "none", feature = "defmt-log")))]
macro_rules! debug {
    ($($arg:tt)*) => {};
}

use crate::ctaphid::entropy::EntropySource;
use crate::ctaphid::key_store::PrivateKeyStore;
use crate::ctaphid::pin_uv_auth::{PERMISSION_GET_ASSERTION, PinUvAuthProvider};
use crate::ctaphid::storage::{MAX_RECORDS, Storage, StorageBackend};
use crate::ctaphid::user_verification::UserVerification;
use crate::ctaphid::{cbor, credential};
use crate::presence::UserPresence;
#[cfg(feature = "hmac-secret")]
use zeroize::Zeroize;

#[cfg(feature = "hmac-secret")]
use super::client_pin::{
    HmacSecretState, PlatformKeyAgreement, establish_hmac_secret, evaluate_hmac_secret,
    read_platform_key_agreement,
};
use super::credential_descriptor::{CredentialDescriptor, read_credential_descriptor};
#[cfg(not(any(feature = "hmac-secret", feature = "cred-blob")))]
use super::request::read_extensions;
#[cfg(any(feature = "hmac-secret", feature = "cred-blob"))]
use super::request::read_typed_bool;
use super::request::{
    PinUvAuth, error_status, expect_array, expect_map, has_unsupported_options, read_options,
    read_typed_array_len, read_typed_bytes, read_typed_map_len, read_typed_text, read_typed_uint,
    rp_id_hash, verify_pin_uv_auth_param,
};
use super::{AssertionState, Options, RequestError, status};

/// Requires configured response capacity; undersized buffers may panic.
/// Counters may advance even if signing or response construction fails.
pub(super) fn get_assertion<
    'a,
    B: StorageBackend,
    P: UserPresence,
    V: UserVerification,
    A: PinUvAuthProvider,
    K: PrivateKeyStore,
>(
    request: &[u8],
    _storage: &mut Storage<B>,
    presence: &mut P,
    verification: &mut V,
    pin_uv_auth: &mut A,
    key_store: &mut K,
    entropy: &mut impl EntropySource,
    assertion_state: &mut AssertionState,
    buf: &'a mut [u8],
) -> &'a [u8] {
    assertion_state.clear();

    let _req = match parse_get_assertion_request(request) {
        Ok(req) => req,
        Err(err) => {
            buf[0] = error_status(err);
            return &buf[..1];
        }
    };

    if has_unsupported_options(&_req.options) {
        debug!("unsupported get_assertion options");
        buf[0] = status::UNSUPPORTED_OPTION;
        return &buf[..1];
    }

    let rp_id_hash = rp_id_hash(_req.rp_id);
    let pin_uv_verified = match verify_pin_uv_auth_param(
        &_req.pin_uv_auth,
        pin_uv_auth,
        &_req.client_data_hash,
        PERMISSION_GET_ASSERTION,
        Some(rp_id_hash),
    ) {
        Ok(value) => value,
        Err(status) => {
            debug!("PIN/UV authentication failed");
            buf[0] = status;
            return &buf[..1];
        }
    };

    #[cfg(feature = "hmac-secret")]
    let mut hmac_secret = match _req.hmac_secret.as_ref() {
        Some(input) => match establish_hmac_secret(
            pin_uv_auth,
            input.protocol,
            &input.key_agreement,
            input.salt_enc,
            input.salt_auth,
        ) {
            Ok(state) => Some(state),
            Err(error) => {
                buf[0] = error;
                return &buf[..1];
            }
        },
        None => None,
    };

    if !presence.wait_for_presence() {
        debug!("user presence not confirmed");
        buf[0] = status::OPERATION_DENIED;
        return &buf[..1];
    }

    let user_verified = pin_uv_verified || verification.verify().is_verified();
    if _req.options.uv == Some(true) && !user_verified {
        debug!("user verification not confirmed");
        buf[0] = status::OPERATION_DENIED;
        return &buf[..1];
    }

    let include_user = _req.allow_list.is_none();

    let mut matching_indices = [0u8; MAX_RECORDS];
    let credential_count = match collect_assertion_indices(
        _storage,
        key_store,
        rp_id_hash,
        _req.allow_list,
        user_verified,
        &mut matching_indices,
    ) {
        Ok(count) => count,
        Err(err) => {
            buf[0] = error_status(err);
            return &buf[..1];
        }
    };

    if credential_count == 0 {
        debug!("getAssertion no matching credentials");
        buf[0] = status::NO_CREDENTIALS;
        return &buf[..1];
    }

    debug!("getAssertion matching credentials: {}", credential_count);

    let response = write_assertion_for_index(
        buf,
        _storage,
        key_store,
        pin_uv_auth,
        entropy,
        rp_id_hash,
        &_req.client_data_hash,
        matching_indices[0] as usize,
        credential_count,
        include_user,
        user_verified,
        #[cfg(feature = "hmac-secret")]
        hmac_secret.as_ref(),
        _req.get_cred_blob,
    );
    if response.first() == Some(&status::OK) {
        assertion_state.set(
            rp_id_hash,
            _req.client_data_hash,
            &matching_indices,
            credential_count,
            include_user,
            user_verified,
            #[cfg(feature = "hmac-secret")]
            hmac_secret.take(),
            _req.get_cred_blob,
        );
        if pin_uv_verified {
            pin_uv_auth.clear_pin_uv_auth_token_after_user_presence(
                _req.pin_uv_auth.protocol.expect("verified PIN/UV protocol") as u8,
            );
        }
    } else {
        assertion_state.clear();
    }
    #[cfg(feature = "hmac-secret")]
    if let Some(mut state) = hmac_secret {
        state.clear();
    }
    response
}

/// Uses a previously validated exchange; callers isolate assertion state to the current session.
pub(super) fn get_next_assertion<
    'a,
    B: StorageBackend,
    A: PinUvAuthProvider,
    K: PrivateKeyStore,
    E: EntropySource,
>(
    storage: &mut Storage<B>,
    pin_uv_auth: &mut A,
    key_store: &mut K,
    entropy: &mut E,
    assertion_state: &mut AssertionState,
    buf: &'a mut [u8],
) -> &'a [u8] {
    if !assertion_state.active || assertion_state.next >= assertion_state.count {
        assertion_state.clear();
        buf[0] = status::NOT_ALLOWED;
        return &buf[..1];
    }

    let rp_id_hash = assertion_state.rp_id_hash;
    let client_data_hash = assertion_state.client_data_hash;
    let index = assertion_state.indices[assertion_state.next] as usize;
    let include_user = assertion_state.include_user;
    let user_verified = assertion_state.user_verified;
    let get_cred_blob = assertion_state.get_cred_blob;
    debug!("getNextAssertion index: {}", index);
    let response = write_assertion_for_index(
        buf,
        storage,
        key_store,
        pin_uv_auth,
        entropy,
        rp_id_hash,
        &client_data_hash,
        index,
        0,
        include_user,
        user_verified,
        #[cfg(feature = "hmac-secret")]
        assertion_state.hmac_secret.as_ref(),
        get_cred_blob,
    );
    if response.first() == Some(&status::OK) {
        assertion_state.next += 1;
        if assertion_state.next >= assertion_state.count {
            assertion_state.clear();
        }
    } else {
        assertion_state.clear();
    }
    response
}

struct GetAssertionRequest<'a> {
    rp_id: &'a [u8],
    client_data_hash: [u8; 32],
    allow_list: Option<&'a [u8]>,
    options: Options,
    pin_uv_auth: PinUvAuth<'a>,
    #[cfg(feature = "hmac-secret")]
    hmac_secret: Option<HmacSecretInput<'a>>,
    get_cred_blob: bool,
}

#[cfg(feature = "hmac-secret")]
struct HmacSecretInput<'a> {
    key_agreement: PlatformKeyAgreement,
    salt_enc: &'a [u8],
    salt_auth: &'a [u8],
    protocol: u8,
}

fn collect_assertion_indices<B: StorageBackend, K: PrivateKeyStore>(
    storage: &mut Storage<B>,
    key_store: &K,
    rp_id_hash: [u8; 32],
    allow_list: Option<&[u8]>,
    user_verified: bool,
    indices: &mut [u8; MAX_RECORDS],
) -> Result<usize, RequestError> {
    if let Some(allow_list) = allow_list {
        collect_allowed_assertion_indices(
            storage,
            key_store,
            rp_id_hash,
            allow_list,
            user_verified,
            indices,
        )
    } else {
        Ok(collect_rp_assertion_indices(
            storage,
            key_store,
            rp_id_hash,
            user_verified,
            indices,
        ))
    }
}

fn collect_rp_assertion_indices<B: StorageBackend, K: PrivateKeyStore>(
    storage: &mut Storage<B>,
    key_store: &K,
    rp_id_hash: [u8; 32],
    user_verified: bool,
    indices: &mut [u8; MAX_RECORDS],
) -> usize {
    let mut count = 0;

    for index in 0..MAX_RECORDS {
        let Some(record) = storage.load_record(index) else {
            continue;
        };

        if record.rp_id_hash == rp_id_hash
            && record.credential.is_resident
            && key_store.supports_algorithm(record.credential.algorithm)
            && (user_verified
                || record.credential.protection
                    == credential::CredentialProtection::UserVerificationOptional)
        {
            indices[count] = index as u8;
            count += 1;
        }
    }

    count
}

fn collect_allowed_assertion_indices<B: StorageBackend, K: PrivateKeyStore>(
    storage: &mut Storage<B>,
    key_store: &K,
    rp_id_hash: [u8; 32],
    allow_list: &[u8],
    user_verified: bool,
    indices: &mut [u8; MAX_RECORDS],
) -> Result<usize, RequestError> {
    let mut r = cbor::Reader::new(allow_list);
    let len = read_typed_array_len(&mut r)?;
    let mut count = 0;

    for _ in 0..len {
        let item = r.remaining();
        expect_map(item)?;
        r.skip_value().ok_or(RequestError::InvalidCbor)?;

        let CredentialDescriptor::PublicKey { id } = read_credential_descriptor(item)? else {
            continue;
        };

        if id.len() != credential::CREDENTIAL_ID_LEN {
            continue;
        }

        for index in 0..MAX_RECORDS {
            let Some(record) = storage.load_record(index) else {
                continue;
            };

            if record.rp_id_hash == rp_id_hash
                && record.credential.id == id
                && key_store.supports_algorithm(record.credential.algorithm)
                && (user_verified
                    || record.credential.protection
                        != credential::CredentialProtection::UserVerificationRequired)
            {
                if indices[..count].contains(&(index as u8)) {
                    break;
                }

                if count >= MAX_RECORDS {
                    break;
                }

                indices[count] = index as u8;
                count += 1;
                break;
            }
        }
    }

    Ok(count)
}

fn parse_get_assertion_request<'a>(
    request: &'a [u8],
) -> Result<GetAssertionRequest<'a>, RequestError> {
    let mut r = cbor::Reader::new(request);

    let map_len = read_typed_map_len(&mut r)?;
    let mut rp_id = None;
    let mut client_data_hash = None;
    let mut allow_list = None;
    let mut options = None;
    let mut pin_uv_auth_param = None;
    let mut pin_uv_auth_protocol = None;
    #[cfg(feature = "hmac-secret")]
    let mut hmac_secret = None;
    #[allow(unused_mut)]
    let mut get_cred_blob = false;
    let mut extensions_present = false;

    for _ in 0..map_len {
        let key = read_typed_uint(&mut r)?;

        match key {
            1 => {
                if rp_id.is_some() {
                    return Err(RequestError::InvalidCbor);
                }
                rp_id = Some(read_typed_text(&mut r)?);
            }

            2 => {
                if client_data_hash.is_some() {
                    return Err(RequestError::InvalidCbor);
                }
                let bytes = read_typed_bytes(&mut r)?;
                if bytes.len() != 32 {
                    return Err(RequestError::InvalidCbor);
                }

                let mut hash = [0u8; 32];
                hash.copy_from_slice(bytes);
                client_data_hash = Some(hash);
            }

            3 => {
                if allow_list.is_some() {
                    return Err(RequestError::InvalidCbor);
                }
                expect_array(r.remaining())?;
                allow_list = Some(r.remaining());
                r.skip_value().ok_or(RequestError::InvalidCbor)?;
            }

            4 => {
                if extensions_present {
                    return Err(RequestError::InvalidCbor);
                }
                expect_map(r.remaining())?;
                #[cfg(feature = "hmac-secret")]
                {
                    let extensions = read_get_assertion_extensions(r.remaining())?;
                    hmac_secret = extensions.hmac_secret;
                    get_cred_blob = extensions.get_cred_blob;
                }
                #[cfg(all(not(feature = "hmac-secret"), feature = "cred-blob"))]
                {
                    get_cred_blob = read_get_assertion_extensions(r.remaining())?.get_cred_blob;
                }
                #[cfg(not(any(feature = "hmac-secret", feature = "cred-blob")))]
                read_extensions(r.remaining())?;
                extensions_present = true;
                r.skip_value().ok_or(RequestError::InvalidCbor)?;
            }

            5 => {
                if options.is_some() {
                    return Err(RequestError::InvalidCbor);
                }
                expect_map(r.remaining())?;
                options = Some(read_options(r.remaining())?);
                r.skip_value().ok_or(RequestError::InvalidCbor)?;
            }

            6 => {
                if pin_uv_auth_param.is_some() {
                    return Err(RequestError::InvalidCbor);
                }
                pin_uv_auth_param = Some(read_typed_bytes(&mut r)?);
            }

            7 => {
                if pin_uv_auth_protocol.is_some() {
                    return Err(RequestError::InvalidCbor);
                }
                pin_uv_auth_protocol = Some(read_typed_uint(&mut r)?);
            }

            _ => {
                r.skip_value().ok_or(RequestError::InvalidCbor)?;
            }
        }
    }

    if !r.remaining().is_empty() {
        return Err(RequestError::InvalidCbor);
    }

    Ok(GetAssertionRequest {
        rp_id: rp_id.ok_or(RequestError::MissingParameter)?,
        client_data_hash: client_data_hash.ok_or(RequestError::MissingParameter)?,
        allow_list,
        options: options.unwrap_or_default(),
        pin_uv_auth: PinUvAuth {
            param: pin_uv_auth_param,
            protocol: pin_uv_auth_protocol,
        },
        #[cfg(feature = "hmac-secret")]
        hmac_secret,
        get_cred_blob,
    })
}

#[cfg(any(feature = "hmac-secret", feature = "cred-blob"))]
struct GetAssertionExtensions<'a> {
    #[cfg(feature = "hmac-secret")]
    hmac_secret: Option<HmacSecretInput<'a>>,
    get_cred_blob: bool,
    #[cfg(not(feature = "hmac-secret"))]
    _lifetime: core::marker::PhantomData<&'a ()>,
}

#[cfg(any(feature = "hmac-secret", feature = "cred-blob"))]
fn read_get_assertion_extensions(data: &[u8]) -> Result<GetAssertionExtensions<'_>, RequestError> {
    let mut r = cbor::Reader::new(data);
    let map_len = read_typed_map_len(&mut r)?;
    #[cfg(feature = "hmac-secret")]
    let mut hmac_secret = None;
    let mut get_cred_blob = None;

    for _ in 0..map_len {
        let key = read_typed_text(&mut r)?;
        if key == b"hmac-secret" {
            #[cfg(feature = "hmac-secret")]
            {
                if hmac_secret.is_some() {
                    return Err(RequestError::InvalidCbor);
                }
                hmac_secret = Some(read_hmac_secret_input(&mut r)?);
            }
            #[cfg(not(feature = "hmac-secret"))]
            r.skip_value().ok_or(RequestError::InvalidCbor)?;
        } else if key == b"credBlob" {
            #[cfg(feature = "cred-blob")]
            {
                if get_cred_blob.is_some() {
                    return Err(RequestError::InvalidCbor);
                }
                get_cred_blob = Some(read_typed_bool(&mut r)?);
            }
            #[cfg(not(feature = "cred-blob"))]
            r.skip_value().ok_or(RequestError::InvalidCbor)?;
        } else {
            r.skip_value().ok_or(RequestError::InvalidCbor)?;
        }
    }
    if !r.remaining().is_empty() {
        return Err(RequestError::InvalidCbor);
    }
    Ok(GetAssertionExtensions {
        #[cfg(feature = "hmac-secret")]
        hmac_secret,
        get_cred_blob: get_cred_blob == Some(true),
        #[cfg(not(feature = "hmac-secret"))]
        _lifetime: core::marker::PhantomData,
    })
}

#[cfg(feature = "hmac-secret")]
fn read_hmac_secret_input<'a>(
    r: &mut cbor::Reader<'a>,
) -> Result<HmacSecretInput<'a>, RequestError> {
    let map_len = read_typed_map_len(r)?;
    let mut key_agreement = None;
    let mut salt_enc = None;
    let mut salt_auth = None;
    let mut protocol = None;
    for _ in 0..map_len {
        match read_typed_uint(r)? {
            1 if key_agreement.is_none() => {
                key_agreement = Some(read_platform_key_agreement(r).map_err(|error| {
                    if error == status::CBOR_UNEXPECTED_TYPE {
                        RequestError::UnexpectedType
                    } else {
                        RequestError::InvalidCbor
                    }
                })?);
            }
            2 if salt_enc.is_none() => {
                salt_enc = Some(read_typed_bytes(r)?);
            }
            3 if salt_auth.is_none() => {
                salt_auth = Some(read_typed_bytes(r)?);
            }
            4 if protocol.is_none() => {
                let value = read_typed_uint(r)?;
                protocol = Some(u8::try_from(value).map_err(|_| RequestError::InvalidCbor)?);
            }
            1 | 2 | 3 | 4 => return Err(RequestError::InvalidCbor),
            _ => r.skip_value().ok_or(RequestError::InvalidCbor)?,
        }
    }
    Ok(HmacSecretInput {
        key_agreement: key_agreement.ok_or(RequestError::MissingParameter)?,
        salt_enc: salt_enc.ok_or(RequestError::MissingParameter)?,
        salt_auth: salt_auth.ok_or(RequestError::MissingParameter)?,
        protocol: protocol.unwrap_or(1),
    })
}

fn write_assertion_for_index<
    'a,
    B: StorageBackend,
    A: PinUvAuthProvider,
    K: PrivateKeyStore,
    E: EntropySource,
>(
    buf: &'a mut [u8],
    storage: &mut Storage<B>,
    key_store: &mut K,
    _pin_uv_auth: &mut A,
    _entropy: &mut E,
    rp_id_hash: [u8; 32],
    client_data_hash: &[u8; 32],
    index: usize,
    credential_count: usize,
    include_user: bool,
    user_verified: bool,
    #[cfg(feature = "hmac-secret")] hmac_secret: Option<&HmacSecretState>,
    get_cred_blob: bool,
) -> &'a [u8] {
    let Some((_credential, sign_count)) = credential::increment_sign_count_at(storage, index)
    else {
        buf[0] = status::NO_CREDENTIALS;
        return &buf[..1];
    };

    #[cfg(feature = "hmac-secret")]
    let mut hmac_secret_buf = [0u8; 80];
    #[cfg(feature = "hmac-secret")]
    let hmac_secret_output = if let Some(state) = hmac_secret {
        match (_credential.algorithm == credential::CredentialAlgorithm::Es256)
            .then(|| key_store.hmac_secret_cred_random(&_credential.key_material, user_verified))
            .flatten()
        {
            Some(mut cred_random) => {
                let result = evaluate_hmac_secret(
                    _pin_uv_auth,
                    state,
                    &cred_random,
                    _entropy,
                    &mut hmac_secret_buf,
                );
                cred_random.zeroize();
                match result {
                    Some(output) => Some(output),
                    None => {
                        buf[0] = status::OPERATION_DENIED;
                        return &buf[..1];
                    }
                }
            }
            None => None,
        }
    } else {
        None
    };

    let mut _auth_data_buf = [0u8; 256];
    let cred_blob_output =
        get_cred_blob.then_some(&_credential.cred_blob[.._credential.cred_blob_len as usize]);
    let Some(_auth_data) =
        crate::ctaphid::auth_data::write_assertion_authenticator_data_with_hmac_secret(
            &mut _auth_data_buf,
            &rp_id_hash,
            sign_count,
            user_verified,
            #[cfg(feature = "hmac-secret")]
            hmac_secret_output,
            #[cfg(not(feature = "hmac-secret"))]
            None,
            cred_blob_output,
        )
    else {
        buf[0] = status::OPERATION_DENIED;
        return &buf[..1];
    };

    let mut sig_buf = [0u8; super::buffers::CREDENTIAL_SIGNATURE_LEN];
    let Some(_signature) = key_store.sign_for_algorithm(
        _credential.algorithm,
        &_credential.key_material,
        _auth_data,
        client_data_hash,
        &mut sig_buf,
    ) else {
        buf[0] = status::OPERATION_DENIED;
        return &buf[..1];
    };

    write_get_assertion_response(
        buf,
        &_credential.id,
        &_credential.user_id[.._credential.user_id_len as usize],
        &_credential.user_name[.._credential.user_name_len as usize],
        &_credential.user_display_name[.._credential.user_display_name_len as usize],
        _auth_data,
        _signature,
        credential_count,
        include_user,
    )
}

fn write_get_assertion_response<'a>(
    buf: &'a mut [u8],
    credential_id: &[u8],
    user_id: &[u8],
    user_name: &[u8],
    user_display_name: &[u8],
    auth_data: &[u8],
    signature: &[u8],
    credential_count: usize,
    include_user: bool,
) -> &'a [u8] {
    let mut w = cbor::Writer::new(buf);

    w.write_raw_u8(status::OK).unwrap();

    let map_len = 3 + u8::from(include_user) + u8::from(credential_count > 1);
    w.write_map_len(map_len).unwrap();

    w.write_uint(1).unwrap();
    w.write_map_len(2).unwrap();
    w.write_text(b"id").unwrap();
    w.write_bytes(credential_id).unwrap();
    w.write_text(b"type").unwrap();
    w.write_text(b"public-key").unwrap();

    w.write_uint(2).unwrap();
    w.write_bytes(auth_data).unwrap();

    w.write_uint(3).unwrap();
    w.write_bytes(signature).unwrap();

    if include_user {
        w.write_uint(4).unwrap();
        let user_map_len =
            1 + u8::from(!user_name.is_empty()) + u8::from(!user_display_name.is_empty());
        w.write_map_len(user_map_len).unwrap();
        w.write_text(b"id").unwrap();
        w.write_bytes(user_id).unwrap();
        if !user_name.is_empty() {
            w.write_text(b"name").unwrap();
            w.write_text(user_name).unwrap();
        }
        if !user_display_name.is_empty() {
            w.write_text(b"displayName").unwrap();
            w.write_text(user_display_name).unwrap();
        }
    }

    if credential_count > 1 {
        w.write_uint(5).unwrap();
        w.write_uint(credential_count as u64).unwrap();
    }

    w.finish()
}
