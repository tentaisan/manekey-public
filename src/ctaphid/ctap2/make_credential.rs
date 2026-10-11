#[cfg(all(target_arch = "arm", target_os = "none", feature = "defmt-log"))]
use defmt::debug;
#[cfg(not(all(target_arch = "arm", target_os = "none", feature = "defmt-log")))]
macro_rules! debug {
    ($($arg:tt)*) => {};
}

use crate::ctaphid::credential::{
    CredentialProtection, USER_DISPLAY_NAME_MAX_LEN, USER_ID_MAX_LEN, USER_NAME_MAX_LEN,
};
use crate::ctaphid::entropy::EntropySource;
use crate::ctaphid::key_store::PrivateKeyStore;
use crate::ctaphid::pin_uv_auth::{PERMISSION_MAKE_CREDENTIAL, PinUvAuthProvider};
use crate::ctaphid::storage::{Storage, StorageBackend};
use crate::ctaphid::user_verification::UserVerification;
use crate::ctaphid::{attestation, cbor, credential};
use crate::presence::UserPresence;
use zeroize::Zeroize;

use super::credential_descriptor::{
    allow_list_contains_credential_id, validate_credential_descriptor_list,
};
use super::request::{
    CborInteger, PinUvAuth, RequestError, error_status, expect_array, expect_map, read_options,
    read_typed_array_len, read_typed_bool, read_typed_bytes, read_typed_integer,
    read_typed_map_len, read_typed_text, read_typed_uint, rp_id_hash, verify_pin_uv_auth_param,
};
use super::{MakeCredentialRequest, status};

/// Requires configured response capacity; undersized buffers may panic.
/// Persistence/cleanup failure requires backend reconciliation, not blind command replay.
pub(super) fn make_credential<
    'a,
    B: StorageBackend,
    P: UserPresence,
    V: UserVerification,
    A: PinUvAuthProvider,
    K: PrivateKeyStore,
    E: EntropySource,
>(
    request: &[u8],
    storage: &mut Storage<B>,
    presence: &mut P,
    verification: &mut V,
    pin_uv_auth: &mut A,
    key_store: &mut K,
    entropy: &mut E,
    buf: &'a mut [u8],
) -> &'a [u8] {
    debug!("make_credential request len: {}", request.len());

    let req = match parse_make_credential_request(request) {
        Ok(req) => req,
        Err(err) => {
            debug!("parse_make_credential_request failed");
            buf[0] = error_status(err);
            return &buf[..1];
        }
    };
    debug!("request parsed successfully");

    if super::request::has_unsupported_options(&req.options) {
        debug!("unsupported make_credential options");
        buf[0] = status::UNSUPPORTED_OPTION;
        return &buf[..1];
    }

    let rp_id_hash = rp_id_hash(req.rp_id);
    let pin_uv_verified = match verify_pin_uv_auth_param(
        &req.pin_uv_auth,
        pin_uv_auth,
        &req.client_data_hash,
        PERMISSION_MAKE_CREDENTIAL,
        Some(rp_id_hash),
    ) {
        Ok(value) => value,
        Err(status) => {
            debug!("PIN/UV authentication failed");
            buf[0] = status;
            return &buf[..1];
        }
    };

    if !presence.wait_for_presence() {
        debug!("user presence not confirmed");
        buf[0] = status::OPERATION_DENIED;
        return &buf[..1];
    }

    let user_verified = pin_uv_verified || verification.verify().is_verified();
    if req.options.uv == Some(true) && !user_verified {
        debug!("user verification not confirmed");
        buf[0] = status::OPERATION_DENIED;
        return &buf[..1];
    }

    let algorithm = match select_pub_key_cred_param(req.pub_key_cred_params, key_store) {
        Ok(Some(algorithm)) => algorithm,
        Ok(None) => {
            debug!("supported algorithm not found in pub_key_cred_params");
            buf[0] = status::UNSUPPORTED_ALGORITHM;
            return &buf[..1];
        }
        Err(err) => {
            buf[0] = error_status(err);
            return &buf[..1];
        }
    };

    if let Some(exclude_list) = req.exclude_list {
        if let Err(err) = validate_credential_descriptor_list(exclude_list) {
            buf[0] = error_status(err);
            return &buf[..1];
        }
        match credential::try_any_id_matches_rp(storage, rp_id_hash, |credential_id| {
            allow_list_contains_credential_id(exclude_list, credential_id)
        }) {
            Ok(true) => {
                buf[0] = status::CREDENTIAL_EXCLUDED;
                return &buf[..1];
            }
            Ok(false) => {}
            Err(err) => {
                buf[0] = error_status(err);
                return &buf[..1];
            }
        }
    }

    let response = make_credential_success(
        buf,
        storage,
        key_store,
        entropy,
        algorithm,
        req.rp_id,
        &rp_id_hash,
        &req.client_data_hash,
        req.user_id,
        req.user_name,
        req.user_display_name,
        req.options.rk == Some(true),
        req.protection,
        req.cred_protect_output,
        req.hmac_secret_requested,
        req.cred_blob,
        user_verified,
    );
    if response.first() == Some(&status::OK) && pin_uv_verified {
        pin_uv_auth.clear_pin_uv_auth_token_after_user_presence(
            req.pin_uv_auth.protocol.expect("verified PIN/UV protocol") as u8,
        );
    }
    response
}

pub(super) fn parse_make_credential_request<'a>(
    request: &'a [u8],
) -> Result<MakeCredentialRequest<'a>, RequestError> {
    let mut r = cbor::Reader::new(request);

    let map_len = read_typed_map_len(&mut r)?;
    let mut client_data_hash = None;
    let mut rp_id = None;
    let mut user = None;
    let mut pub_key_cred_params = None;
    let mut exclude_list = None;
    let mut options = None;
    let mut cred_protect_output = None;
    let mut hmac_secret_requested = false;
    let mut cred_blob = None;
    let mut extensions_present = false;
    let mut pin_uv_auth_param = None;
    let mut pin_uv_auth_protocol = None;

    for _ in 0..map_len {
        let key = read_typed_uint(&mut r)?;

        match key {
            1 => {
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

            2 => {
                if rp_id.is_some() {
                    return Err(RequestError::InvalidCbor);
                }
                let rp = r.remaining();
                expect_map(rp)?;
                rp_id = Some(read_rp_id(rp)?);
                r.skip_value().ok_or(RequestError::InvalidCbor)?;
            }

            3 => {
                if user.is_some() {
                    return Err(RequestError::InvalidCbor);
                }
                expect_map(r.remaining())?;
                user = Some(read_user_entity(r.remaining())?);
                r.skip_value().ok_or(RequestError::InvalidCbor)?;
            }

            4 => {
                if pub_key_cred_params.is_some() {
                    return Err(RequestError::InvalidCbor);
                }
                expect_array(r.remaining())?;
                pub_key_cred_params = Some(r.remaining());
                r.skip_value().ok_or(RequestError::InvalidCbor)?;
            }

            5 => {
                if exclude_list.is_some() {
                    return Err(RequestError::InvalidCbor);
                }
                expect_array(r.remaining())?;
                exclude_list = Some(r.remaining());
                r.skip_value().ok_or(RequestError::InvalidCbor)?;
            }

            6 => {
                if extensions_present {
                    return Err(RequestError::InvalidCbor);
                }
                expect_map(r.remaining())?;
                let extensions = read_make_credential_extensions(r.remaining())?;
                cred_protect_output = extensions.cred_protect;
                hmac_secret_requested = extensions.hmac_secret;
                cred_blob = extensions.cred_blob;
                extensions_present = true;
                r.skip_value().ok_or(RequestError::InvalidCbor)?;
            }

            7 => {
                if options.is_some() {
                    return Err(RequestError::InvalidCbor);
                }
                expect_map(r.remaining())?;
                options = Some(read_options(r.remaining())?);
                r.skip_value().ok_or(RequestError::InvalidCbor)?;
            }

            8 => {
                if pin_uv_auth_param.is_some() {
                    return Err(RequestError::InvalidCbor);
                }
                pin_uv_auth_param = Some(read_typed_bytes(&mut r)?);
            }

            9 => {
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

    let user = user.ok_or(RequestError::MissingParameter)?;

    Ok(MakeCredentialRequest {
        client_data_hash: client_data_hash.ok_or(RequestError::MissingParameter)?,
        rp_id: rp_id.ok_or(RequestError::MissingParameter)?,
        user_id: user.id,
        user_name: user.name,
        user_display_name: user.display_name,
        protection: cred_protect_output.unwrap_or(CredentialProtection::UserVerificationOptional),
        cred_protect_output,
        hmac_secret_requested,
        cred_blob,
        pub_key_cred_params: pub_key_cred_params.ok_or(RequestError::MissingParameter)?,
        exclude_list,
        pin_uv_auth: PinUvAuth {
            param: pin_uv_auth_param,
            protocol: pin_uv_auth_protocol,
        },
        options: options.unwrap_or_default(),
    })
}

fn select_pub_key_cred_param<K: PrivateKeyStore>(
    data: &[u8],
    key_store: &K,
) -> Result<Option<credential::CredentialAlgorithm>, RequestError> {
    let mut r = cbor::Reader::new(data);

    let array_len = read_typed_array_len(&mut r)?;
    let mut selected = None;

    for _ in 0..array_len {
        expect_map(r.remaining())?;
        let item = read_pub_key_cred_param_algorithm(r.remaining())?;

        r.skip_value().ok_or(RequestError::InvalidCbor)?;

        if selected.is_none()
            && item.is_some_and(|algorithm| key_store.supports_algorithm(algorithm))
        {
            selected = item;
        }
    }

    Ok(selected)
}

fn read_pub_key_cred_param_algorithm(
    data: &[u8],
) -> Result<Option<credential::CredentialAlgorithm>, RequestError> {
    let mut r = cbor::Reader::new(data);

    let map_len = read_typed_map_len(&mut r)?;
    let mut algorithm = None;

    for _ in 0..map_len {
        let key = read_typed_text(&mut r)?;

        if key == b"alg" {
            if algorithm.is_some() {
                return Err(RequestError::InvalidCbor);
            }
            algorithm = Some(read_typed_integer(&mut r)?);
        } else {
            r.skip_value().ok_or(RequestError::InvalidCbor)?;
        }
    }

    Ok(match algorithm {
        Some(CborInteger::Negative(value)) => {
            credential::CredentialAlgorithm::from_cose_algorithm(value)
        }
        _ => None,
    })
}

fn make_credential_success<'a, B: StorageBackend, K: PrivateKeyStore, E: EntropySource>(
    buf: &'a mut [u8],
    storage: &mut Storage<B>,
    key_store: &mut K,
    entropy: &mut E,
    algorithm: credential::CredentialAlgorithm,
    rp_id: &[u8],
    rp_id_hash: &[u8; 32],
    client_data_hash: &[u8; 32],
    user_id: &[u8],
    user_name: &[u8],
    user_display_name: &[u8],
    is_resident: bool,
    protection: CredentialProtection,
    cred_protect_output: Option<CredentialProtection>,
    hmac_secret_requested: bool,
    cred_blob: Option<&[u8]>,
    user_verified: bool,
) -> &'a [u8] {
    let stored_cred_blob = cred_blob.is_some_and(|blob| {
        cfg!(feature = "cred-blob") && is_resident && blob.len() <= credential::CRED_BLOB_MAX_LEN
    });
    let credential = match credential::create_with_key_store_algorithm_and_cred_blob(
        storage,
        key_store,
        entropy,
        algorithm,
        rp_id,
        user_id,
        user_name,
        user_display_name,
        is_resident,
        protection,
        *rp_id_hash,
        if stored_cred_blob { cred_blob } else { None },
    ) {
        Ok(credential) => credential,
        Err(credential::CredentialError::StorageFull) => {
            debug!("credential store full");
            buf[0] = status::KEY_STORE_FULL;
            return &buf[..1];
        }
        Err(_) => {
            debug!("credential::create failed");
            buf[0] = status::OPERATION_DENIED;
            return &buf[..1];
        }
    };
    debug!("credential created");

    let mut auth_data_buf = [0u8; super::buffers::ATTESTED_AUTH_DATA_LEN];
    let mut cose_key_buf = [0u8; super::buffers::CREDENTIAL_COSE_KEY_LEN];
    let Some(credential_public_key) = key_store.write_public_key_cose(
        credential.algorithm,
        &credential.key_material,
        &mut cose_key_buf,
    ) else {
        abort_created_key(storage, key_store, &credential);
        buf[0] = status::OPERATION_DENIED;
        return &buf[..1];
    };
    let hmac_secret_output = hmac_secret_requested.then(|| {
        if credential.algorithm != credential::CredentialAlgorithm::Es256 {
            return false;
        }
        let mut without_uv = key_store.hmac_secret_cred_random(&credential.key_material, false);
        let mut with_uv = if without_uv.is_some() {
            key_store.hmac_secret_cred_random(&credential.key_material, true)
        } else {
            None
        };
        let available = without_uv.is_some() && with_uv.is_some();
        without_uv.zeroize();
        with_uv.zeroize();
        available
    });
    let auth_data = crate::ctaphid::auth_data::write_attested_authenticator_data_with_cose_key(
        &mut auth_data_buf,
        rp_id_hash,
        &credential.id,
        credential_public_key,
        cred_protect_output,
        hmac_secret_output,
        cred_blob.map(|_| stored_cred_blob),
        user_verified,
    )
    .unwrap();
    debug!("auth_data len: {}", auth_data.len());

    let mut sig_buf = [0u8; super::buffers::CREDENTIAL_SIGNATURE_LEN];
    let Some(signature) = key_store.sign_for_algorithm(
        credential.algorithm,
        &credential.key_material,
        auth_data,
        client_data_hash,
        &mut sig_buf,
    ) else {
        abort_created_key(storage, key_store, &credential);
        buf[0] = status::OPERATION_DENIED;
        return &buf[..1];
    };
    debug!("signature len: {}", signature.len());

    let mut w = cbor::Writer::new(buf);
    w.write_raw_u8(status::OK).unwrap();

    attestation::write_packed_attestation_object_with_algorithm(
        &mut w,
        auth_data,
        signature,
        credential.algorithm.cose_algorithm(),
    )
    .unwrap();
    debug!("attestation object written");

    let result = w.finish();
    debug!("response len: {}", result.len());
    result
}

fn abort_created_key<B: StorageBackend, K: PrivateKeyStore>(
    storage: &mut Storage<B>,
    key_store: &mut K,
    credential: &credential::Credential,
) {
    if credential::delete_by_id(storage, &credential.id).is_ok() {
        let _ = key_store.release_key_material(credential.algorithm, &credential.key_material);
    }
}

fn read_rp_id(rp: &[u8]) -> Result<&[u8], RequestError> {
    let mut r = cbor::Reader::new(rp);

    let map_len = read_typed_map_len(&mut r)?;
    let mut id = None;

    for _ in 0..map_len {
        let key = read_typed_text(&mut r)?;

        if key == b"id" {
            if id.is_some() {
                return Err(RequestError::InvalidCbor);
            }
            id = Some(read_typed_text(&mut r)?);
        } else {
            r.skip_value().ok_or(RequestError::InvalidCbor)?;
        }
    }

    id.ok_or(RequestError::MissingParameter)
}

struct MakeCredentialExtensions<'a> {
    cred_protect: Option<CredentialProtection>,
    hmac_secret: bool,
    cred_blob: Option<&'a [u8]>,
}

fn read_make_credential_extensions(
    data: &[u8],
) -> Result<MakeCredentialExtensions<'_>, RequestError> {
    let mut r = cbor::Reader::new(data);
    let map_len = read_typed_map_len(&mut r)?;
    let mut protection = None;
    let mut hmac_secret = None;
    let mut cred_blob = None;

    for _ in 0..map_len {
        let key = read_typed_text(&mut r)?;
        if key == b"credProtect" {
            if protection.is_some() {
                return Err(RequestError::InvalidCbor);
            }
            protection = Some(
                CredentialProtection::from_ctap_value(read_typed_uint(&mut r)?)
                    .ok_or(RequestError::InvalidCbor)?,
            );
        } else if key == b"hmac-secret" && cfg!(feature = "hmac-secret") {
            if hmac_secret.is_some() {
                return Err(RequestError::InvalidCbor);
            }
            hmac_secret = Some(read_typed_bool(&mut r)?);
        } else if key == b"credBlob" && cfg!(feature = "cred-blob") {
            if cred_blob.is_some() {
                return Err(RequestError::InvalidCbor);
            }
            cred_blob = Some(read_typed_bytes(&mut r)?);
        } else {
            r.skip_value().ok_or(RequestError::InvalidCbor)?;
        }
    }

    Ok(MakeCredentialExtensions {
        cred_protect: protection,
        hmac_secret: hmac_secret == Some(true),
        cred_blob,
    })
}

struct UserEntity<'a> {
    id: &'a [u8],
    name: &'a [u8],
    display_name: &'a [u8],
}

fn read_user_entity(user: &[u8]) -> Result<UserEntity<'_>, RequestError> {
    let mut r = cbor::Reader::new(user);
    let map_len = read_typed_map_len(&mut r)?;
    let mut id = None;
    let mut name = None;
    let mut display_name = None;

    for _ in 0..map_len {
        let key = read_typed_text(&mut r)?;
        match key {
            b"id" if id.is_none() => {
                let value = read_typed_bytes(&mut r)?;
                if value.len() > USER_ID_MAX_LEN {
                    return Err(RequestError::InvalidCbor);
                }
                id = Some(value);
            }
            b"name" if name.is_none() => {
                let value = read_typed_text(&mut r)?;
                if value.len() > USER_NAME_MAX_LEN {
                    return Err(RequestError::InvalidCbor);
                }
                name = Some(value);
            }
            b"displayName" if display_name.is_none() => {
                let value = read_typed_text(&mut r)?;
                if value.len() > USER_DISPLAY_NAME_MAX_LEN {
                    return Err(RequestError::InvalidCbor);
                }
                display_name = Some(value);
            }
            b"id" | b"name" | b"displayName" => return Err(RequestError::InvalidCbor),
            _ => r.skip_value().ok_or(RequestError::InvalidCbor)?,
        }
    }

    Ok(UserEntity {
        id: id.ok_or(RequestError::MissingParameter)?,
        name: name.unwrap_or_default(),
        display_name: display_name.unwrap_or_default(),
    })
}
