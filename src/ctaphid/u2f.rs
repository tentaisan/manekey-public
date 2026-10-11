use super::{
    credential, entropy::EntropySource, key_store::PrivateKeyStore, storage, u2f_attestation,
};

const CLA: u8 = 0x00;
const INS_VERSION: u8 = 0x03;
const INS_REGISTER: u8 = 0x01;
const INS_AUTHENTICATE: u8 = 0x02;
const U2F_VERSION: &[u8] = b"U2F_V2";

const STATUS_NO_ERROR: [u8; 2] = [0x90, 0x00];
const STATUS_WRONG_LENGTH: [u8; 2] = [0x67, 0x00];
const STATUS_WRONG_DATA: [u8; 2] = [0x6a, 0x80];
const STATUS_INS_NOT_SUPPORTED: [u8; 2] = [0x6d, 0x00];
const STATUS_CLA_NOT_SUPPORTED: [u8; 2] = [0x6e, 0x00];
const STATUS_CONDITIONS_NOT_SATISFIED: [u8; 2] = [0x69, 0x85];

pub(crate) const PARAMETER_LEN: usize = 32;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Request<'a> {
    Version,
    Register {
        challenge: &'a [u8; PARAMETER_LEN],
        application: &'a [u8; PARAMETER_LEN],
    },
    Authenticate {
        challenge: &'a [u8; PARAMETER_LEN],
        application: &'a [u8; PARAMETER_LEN],
        key_handle: &'a [u8],
        check_only: bool,
    },
}

/// Version-only APDU entry; response capacity must be at least eight bytes.
pub fn handle(request: &[u8], response: &mut [u8]) -> usize {
    let status = match parse(request) {
        Ok(Request::Version) => return version_response(response),
        Ok(Request::Register { .. } | Request::Authenticate { .. }) => STATUS_INS_NOT_SUPPORTED,
        Err(status) => {
            if request.len() >= 2
                && request[0] == CLA
                && matches!(request[1], INS_REGISTER | INS_AUTHENTICATE)
            {
                STATUS_INS_NOT_SUPPORTED
            } else {
                status
            }
        }
    };

    status_response(status, response)
}

/// Caller establishes required UP; registration uses a public development attestation identity.
/// Response capacity must cover status/version bytes; counters may advance before signing fails.
pub(crate) fn handle_with_trusted_state<
    B: storage::StorageBackend,
    K: PrivateKeyStore,
    E: EntropySource,
>(
    request: &[u8],
    storage: &mut storage::Storage<B>,
    key_store: &mut K,
    entropy: &mut E,
    response: &mut [u8],
) -> usize {
    match parse(request) {
        Ok(Request::Version) => version_response(response),
        Ok(Request::Authenticate {
            application,
            key_handle,
            check_only: true,
            ..
        }) => authenticate_check_only(application, key_handle, storage, response),
        Ok(Request::Register {
            challenge,
            application,
        }) => register(
            challenge,
            application,
            storage,
            key_store,
            entropy,
            response,
        ),
        Ok(Request::Authenticate {
            challenge,
            application,
            key_handle,
            check_only: false,
        }) => authenticate(
            challenge,
            application,
            key_handle,
            storage,
            key_store,
            response,
        ),
        Err(status) if request.len() >= 2 && request[0] == CLA => match request[1] {
            INS_REGISTER | INS_AUTHENTICATE => status_response(STATUS_INS_NOT_SUPPORTED, response),
            _ => status_response(status, response),
        },
        Err(status) => status_response(status, response),
    }
}

pub(crate) fn register_needs_user_presence(request: &[u8]) -> bool {
    matches!(parse(request), Ok(Request::Register { .. }))
}

pub(crate) fn authenticate_needs_user_presence<B: storage::StorageBackend>(
    request: &[u8],
    storage: &mut storage::Storage<B>,
) -> bool {
    let Ok(Request::Authenticate {
        application,
        key_handle,
        check_only: false,
        ..
    }) = parse(request)
    else {
        return false;
    };
    key_handle_exists(application, key_handle, storage)
}

fn authenticate_check_only<B: storage::StorageBackend>(
    application: &[u8; PARAMETER_LEN],
    key_handle: &[u8],
    storage: &mut storage::Storage<B>,
    response: &mut [u8],
) -> usize {
    if key_handle_exists(application, key_handle, storage) {
        status_response(STATUS_CONDITIONS_NOT_SATISFIED, response)
    } else {
        status_response(STATUS_WRONG_DATA, response)
    }
}

fn register<B: storage::StorageBackend, K: PrivateKeyStore, E: EntropySource>(
    challenge: &[u8; PARAMETER_LEN],
    application: &[u8; PARAMETER_LEN],
    storage: &mut storage::Storage<B>,
    key_store: &mut K,
    entropy: &mut E,
    response: &mut [u8],
) -> usize {
    const PUBLIC_KEY_LEN: usize = 65;
    const ATTESTATION_SIGNATURE_MAX_LEN: usize = 72;
    let fixed_len = 1
        + PUBLIC_KEY_LEN
        + 1
        + credential::CREDENTIAL_ID_LEN
        + u2f_attestation::CERTIFICATE_DER.len()
        + STATUS_NO_ERROR.len();
    if response.len() < fixed_len + ATTESTATION_SIGNATURE_MAX_LEN {
        return status_response(STATUS_WRONG_LENGTH, response);
    }

    let Ok(credential) = credential::create_with_key_store(
        storage,
        key_store,
        entropy,
        &[],
        &[],
        &[],
        &[],
        false,
        credential::CredentialProtection::UserVerificationOptional,
        *application,
    ) else {
        return status_response(STATUS_WRONG_DATA, response);
    };
    let Some((x, y)) = key_store.public_key_xy(&credential.key_material) else {
        return status_response(STATUS_WRONG_DATA, response);
    };

    response[0] = 0x05;
    response[1] = 0x04;
    response[2..34].copy_from_slice(&x);
    response[34..66].copy_from_slice(&y);
    response[66] = credential.id.len() as u8;
    response[67..67 + credential.id.len()].copy_from_slice(&credential.id);
    let certificate_start = 67 + credential.id.len();
    let certificate_end = certificate_start + u2f_attestation::CERTIFICATE_DER.len();
    response[certificate_start..certificate_end].copy_from_slice(u2f_attestation::CERTIFICATE_DER);

    let mut signed_data =
        [0u8; 1 + PARAMETER_LEN * 2 + credential::CREDENTIAL_ID_LEN + PUBLIC_KEY_LEN];
    signed_data[1..1 + PARAMETER_LEN].copy_from_slice(application);
    signed_data[1 + PARAMETER_LEN..1 + PARAMETER_LEN * 2].copy_from_slice(challenge);
    let key_handle_start = 1 + PARAMETER_LEN * 2;
    signed_data[key_handle_start..key_handle_start + credential.id.len()]
        .copy_from_slice(&credential.id);
    let public_key_start = key_handle_start + credential.id.len();
    signed_data[public_key_start] = 0x04;
    signed_data[public_key_start + 1..public_key_start + 33].copy_from_slice(&x);
    signed_data[public_key_start + 33..public_key_start + PUBLIC_KEY_LEN].copy_from_slice(&y);
    let signature_end = response.len() - STATUS_NO_ERROR.len();
    let Some(signature) =
        u2f_attestation::sign(&signed_data, &mut response[certificate_end..signature_end])
    else {
        return status_response(STATUS_WRONG_DATA, response);
    };
    let signature_len = signature.len();
    response
        [certificate_end + signature_len..certificate_end + signature_len + STATUS_NO_ERROR.len()]
        .copy_from_slice(&STATUS_NO_ERROR);
    certificate_end + signature_len + STATUS_NO_ERROR.len()
}

fn authenticate<B: storage::StorageBackend, K: PrivateKeyStore>(
    challenge: &[u8; PARAMETER_LEN],
    application: &[u8; PARAMETER_LEN],
    key_handle: &[u8],
    storage: &mut storage::Storage<B>,
    key_store: &mut K,
    response: &mut [u8],
) -> usize {
    if response.len() < 5 + STATUS_NO_ERROR.len() {
        return 0;
    }
    if key_handle.len() != credential::CREDENTIAL_ID_LEN {
        return status_response(STATUS_WRONG_DATA, response);
    }
    let Some((credential, sign_count)) =
        credential::find_and_increment_sign_count(storage, *application, Some(key_handle))
    else {
        return status_response(STATUS_WRONG_DATA, response);
    };

    let mut signed_data = [0u8; PARAMETER_LEN + 1 + 4];
    signed_data[..PARAMETER_LEN].copy_from_slice(application);
    signed_data[PARAMETER_LEN] = 0x01;
    signed_data[PARAMETER_LEN + 1..].copy_from_slice(&sign_count.to_be_bytes());
    let signature_end = response.len() - STATUS_NO_ERROR.len();
    let Some(signature) = key_store.sign(
        &credential.key_material,
        &signed_data,
        challenge,
        &mut response[5..signature_end],
    ) else {
        return status_response(STATUS_WRONG_DATA, response);
    };
    let signature_len = signature.len();
    response[0] = 0x01;
    response[1..5].copy_from_slice(&sign_count.to_be_bytes());
    response[5 + signature_len..5 + signature_len + STATUS_NO_ERROR.len()]
        .copy_from_slice(&STATUS_NO_ERROR);
    5 + signature_len + STATUS_NO_ERROR.len()
}

fn key_handle_exists<B: storage::StorageBackend>(
    application: &[u8; PARAMETER_LEN],
    key_handle: &[u8],
    storage: &mut storage::Storage<B>,
) -> bool {
    key_handle.len() == credential::CREDENTIAL_ID_LEN
        && credential::find_by_rp_and_id(storage, *application, key_handle).is_some_and(
            |credential| credential.algorithm == credential::CredentialAlgorithm::Es256,
        )
}

fn version_response(response: &mut [u8]) -> usize {
    response[..U2F_VERSION.len()].copy_from_slice(U2F_VERSION);
    response[U2F_VERSION.len()..U2F_VERSION.len() + STATUS_NO_ERROR.len()]
        .copy_from_slice(&STATUS_NO_ERROR);
    U2F_VERSION.len() + STATUS_NO_ERROR.len()
}

fn status_response(status: [u8; 2], response: &mut [u8]) -> usize {
    response[..status.len()].copy_from_slice(&status);
    status.len()
}

pub(crate) fn operation_denied_response(response: &mut [u8]) -> usize {
    response[..STATUS_CONDITIONS_NOT_SATISFIED.len()]
        .copy_from_slice(&STATUS_CONDITIONS_NOT_SATISFIED);
    STATUS_CONDITIONS_NOT_SATISFIED.len()
}

pub(crate) fn parse(request: &[u8]) -> Result<Request<'_>, [u8; 2]> {
    if request.len() < 4 {
        return Err(STATUS_WRONG_LENGTH);
    }
    if request[0] != CLA {
        return Err(STATUS_CLA_NOT_SUPPORTED);
    }
    if request[3] != 0 {
        return Err(STATUS_WRONG_DATA);
    }

    match request[1] {
        INS_VERSION if request[2] == 0 => {
            parse_version_request(&request[4..]).map(|()| Request::Version)
        }
        INS_REGISTER if request[2] == 0 => parse_register_request(&request[4..]),
        INS_AUTHENTICATE => parse_authenticate_request(request[2], &request[4..]),
        INS_VERSION | INS_REGISTER => Err(STATUS_WRONG_DATA),
        _ => Err(STATUS_INS_NOT_SUPPORTED),
    }
}

fn parse_version_request(tail: &[u8]) -> Result<(), [u8; 2]> {
    match tail {
        [] | [0] | [0, 0, 0] | [0, 0, 0, 0, 0] => Ok(()),
        _ => Err(STATUS_WRONG_LENGTH),
    }
}

fn parse_register_request(tail: &[u8]) -> Result<Request<'_>, [u8; 2]> {
    if tail.len() != 1 + PARAMETER_LEN * 2 + 1 || tail[0] != (PARAMETER_LEN * 2) as u8 {
        return Err(STATUS_WRONG_LENGTH);
    }
    let challenge = tail[1..1 + PARAMETER_LEN]
        .try_into()
        .expect("fixed register challenge length");
    let application = tail[1 + PARAMETER_LEN..1 + PARAMETER_LEN * 2]
        .try_into()
        .expect("fixed register application length");
    if tail[1 + PARAMETER_LEN * 2] != 0 {
        return Err(STATUS_WRONG_LENGTH);
    }
    Ok(Request::Register {
        challenge,
        application,
    })
}

fn parse_authenticate_request(p1: u8, tail: &[u8]) -> Result<Request<'_>, [u8; 2]> {
    let check_only = match p1 {
        0x07 => true,
        0x03 => false,
        _ => return Err(STATUS_WRONG_DATA),
    };
    let minimum_len = 1 + PARAMETER_LEN * 2 + 1 + 1;
    if tail.len() < minimum_len {
        return Err(STATUS_WRONG_LENGTH);
    }
    let challenge = tail[1..1 + PARAMETER_LEN]
        .try_into()
        .expect("fixed authenticate challenge length");
    let application = tail[1 + PARAMETER_LEN..1 + PARAMETER_LEN * 2]
        .try_into()
        .expect("fixed authenticate application length");
    let key_handle_len = tail[1 + PARAMETER_LEN * 2] as usize;
    let key_handle_start = 1 + PARAMETER_LEN * 2 + 1;
    let key_handle_end = key_handle_start + key_handle_len;
    if key_handle_len == 0
        || tail[0] as usize != PARAMETER_LEN * 2 + 1 + key_handle_len
        || tail.len() != key_handle_end + 1
        || tail[key_handle_end] != 0
    {
        return Err(STATUS_WRONG_LENGTH);
    }
    Ok(Request::Authenticate {
        challenge,
        application,
        key_handle: &tail[key_handle_start..key_handle_end],
        check_only,
    })
}
