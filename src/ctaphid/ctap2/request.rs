use crate::ctaphid::{
    cbor,
    hash::{Sha256Backend, sha256_digest},
    pin_uv_auth::{PinUvAuthProvider, with_client_pin_crypto},
};

use super::{capabilities::CURRENT, status};

#[derive(Debug, PartialEq, Eq)]
pub(super) enum RequestError {
    UnexpectedType,
    InvalidCbor,
    MissingParameter,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum CborInteger {
    Unsigned(u64),
    Negative(i64),
}

#[derive(Clone, Copy)]
enum CborType {
    Unsigned,
    Bytes,
    Text,
    Array,
    Map,
    Bool,
}

impl CborType {
    fn matches(self, first: u8) -> bool {
        let major = first & 0xe0;
        match self {
            Self::Unsigned => major == 0x00,
            Self::Bytes => major == 0x40,
            Self::Text => major == 0x60,
            Self::Array => major == 0x80,
            Self::Map => major == 0xa0,
            Self::Bool => matches!(first, 0xf4 | 0xf5),
        }
    }
}

fn read_error(data: &[u8], expected: CborType) -> RequestError {
    match data.first() {
        Some(first) if !expected.matches(*first) => RequestError::UnexpectedType,
        _ => RequestError::InvalidCbor,
    }
}

pub(super) fn read_typed_map_len(r: &mut cbor::Reader<'_>) -> Result<usize, RequestError> {
    let error = read_error(r.remaining(), CborType::Map);
    r.read_map_len().ok_or(error)
}

pub(super) fn read_typed_array_len(r: &mut cbor::Reader<'_>) -> Result<usize, RequestError> {
    let error = read_error(r.remaining(), CborType::Array);
    r.read_array_len().ok_or(error)
}

pub(super) fn read_typed_uint(r: &mut cbor::Reader<'_>) -> Result<u64, RequestError> {
    let error = read_error(r.remaining(), CborType::Unsigned);
    r.read_uint().ok_or(error)
}

pub(super) fn read_typed_integer(r: &mut cbor::Reader<'_>) -> Result<CborInteger, RequestError> {
    match r.remaining().first().map(|first| first & 0xe0) {
        Some(0x00) => read_typed_uint(r).map(CborInteger::Unsigned),
        Some(0x20) => r
            .read_negint()
            .map(CborInteger::Negative)
            .ok_or(RequestError::InvalidCbor),
        Some(_) => Err(RequestError::UnexpectedType),
        None => Err(RequestError::InvalidCbor),
    }
}

pub(super) fn read_typed_bytes<'a>(r: &mut cbor::Reader<'a>) -> Result<&'a [u8], RequestError> {
    let error = read_error(r.remaining(), CborType::Bytes);
    r.read_bytes().ok_or(error)
}

pub(super) fn read_typed_text<'a>(r: &mut cbor::Reader<'a>) -> Result<&'a [u8], RequestError> {
    let error = read_error(r.remaining(), CborType::Text);
    r.read_text().ok_or(error)
}

pub(super) fn read_typed_bool(r: &mut cbor::Reader<'_>) -> Result<bool, RequestError> {
    let error = read_error(r.remaining(), CborType::Bool);
    r.read_bool().ok_or(error)
}

pub(super) fn expect_map(data: &[u8]) -> Result<(), RequestError> {
    if data
        .first()
        .is_some_and(|first| CborType::Map.matches(*first))
    {
        Ok(())
    } else {
        Err(read_error(data, CborType::Map))
    }
}

pub(super) fn expect_array(data: &[u8]) -> Result<(), RequestError> {
    if data
        .first()
        .is_some_and(|first| CborType::Array.matches(*first))
    {
        Ok(())
    } else {
        Err(read_error(data, CborType::Array))
    }
}

#[derive(Debug, Default, PartialEq, Eq)]
pub(super) struct Options {
    pub(super) rk: Option<bool>,
    pub(super) uv: Option<bool>,
    pub(super) up: Option<bool>,
}

pub(super) struct PinUvAuth<'a> {
    pub(super) param: Option<&'a [u8]>,
    pub(super) protocol: Option<u64>,
}

pub(super) fn read_options(data: &[u8]) -> Result<Options, RequestError> {
    let mut r = cbor::Reader::new(data);
    let map_len = read_typed_map_len(&mut r)?;
    let mut options = Options::default();

    for _ in 0..map_len {
        let key = read_typed_text(&mut r)?;

        match key {
            b"rk" if options.rk.is_none() => options.rk = Some(read_typed_bool(&mut r)?),
            b"uv" if options.uv.is_none() => options.uv = Some(read_typed_bool(&mut r)?),
            b"up" if options.up.is_none() => options.up = Some(read_typed_bool(&mut r)?),
            b"rk" | b"uv" | b"up" => return Err(RequestError::InvalidCbor),
            _ => r.skip_value().ok_or(RequestError::InvalidCbor)?,
        }
    }

    Ok(options)
}

#[cfg(any(not(any(feature = "hmac-secret", feature = "cred-blob")), test))]
pub(super) fn read_extensions(data: &[u8]) -> Result<(), RequestError> {
    let mut r = cbor::Reader::new(data);
    let map_len = read_typed_map_len(&mut r)?;

    for _ in 0..map_len {
        read_typed_text(&mut r)?;
        r.skip_value().ok_or(RequestError::InvalidCbor)?;
    }

    Ok(())
}

pub(super) fn has_unsupported_options(options: &Options) -> bool {
    CURRENT.has_unsupported_options(options)
}

pub(super) fn verify_pin_uv_auth_param<A: PinUvAuthProvider>(
    pin_uv_auth: &PinUvAuth<'_>,
    provider: &mut A,
    client_data_hash: &[u8; 32],
    required_permission: u8,
    rp_id_hash: Option<[u8; 32]>,
) -> Result<bool, u8> {
    verify_pin_uv_auth_message(
        pin_uv_auth,
        provider,
        client_data_hash,
        required_permission,
        rp_id_hash,
        false,
    )
}

pub(super) fn verify_pin_uv_auth_message<A: PinUvAuthProvider>(
    pin_uv_auth: &PinUvAuth<'_>,
    provider: &mut A,
    message: &[u8],
    required_permission: u8,
    rp_id_hash: Option<[u8; 32]>,
    require_param: bool,
) -> Result<bool, u8> {
    match (pin_uv_auth.param, pin_uv_auth.protocol) {
        (None, None) if require_param => Err(status::PUAT_REQUIRED),
        (None, None) => Ok(false),
        (Some(_), None) => Err(status::MISSING_PARAMETER),
        (None, Some(_)) => Err(status::PIN_AUTH_INVALID),
        (Some(param), Some(protocol @ (1 | 2))) => {
            if !provider.pin_is_set() {
                return Err(status::PIN_NOT_SET);
            }
            if provider.pin_uv_auth_token_expired(protocol as u8) {
                return Err(status::PIN_TOKEN_EXPIRED);
            }
            let Some(token_state) = provider.pin_uv_auth_token_state_for_protocol(protocol as u8)
            else {
                return Err(status::PIN_AUTH_INVALID);
            };
            if token_state.protocol() != protocol as u8
                || !token_state.allows(required_permission, rp_id_hash)
            {
                return Err(status::PIN_AUTH_INVALID);
            }

            if with_client_pin_crypto(provider, |backend| {
                backend.verify_token_auth_param(
                    protocol as u8,
                    &token_state.token(),
                    message,
                    param,
                )
            }) {
                if provider.mark_pin_uv_auth_token_used(protocol as u8) {
                    Ok(true)
                } else {
                    Err(status::PIN_TOKEN_EXPIRED)
                }
            } else {
                Err(status::PIN_AUTH_INVALID)
            }
        }
        (Some(_), Some(_)) => Err(status::INVALID_PARAMETER),
    }
}

pub(super) fn error_status(err: RequestError) -> u8 {
    match err {
        RequestError::UnexpectedType => status::CBOR_UNEXPECTED_TYPE,
        RequestError::InvalidCbor => status::INVALID_CBOR,
        RequestError::MissingParameter => status::MISSING_PARAMETER,
    }
}

pub(super) fn rp_id_hash(rp_id: &[u8]) -> [u8; 32] {
    sha256_digest(rp_id)
}

#[allow(dead_code)]
pub(super) fn rp_id_hash_with_hash<H: Sha256Backend>(
    rp_id: &[u8],
    hash: &mut H,
) -> Option<[u8; 32]> {
    hash.digest(rp_id).ok()
}
