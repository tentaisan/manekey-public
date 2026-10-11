use crate::ctaphid::cbor;

use super::request::{
    RequestError, expect_map, read_typed_array_len, read_typed_bytes, read_typed_map_len,
    read_typed_text,
};

pub(super) fn allow_list_contains_credential_id(
    allow_list: &[u8],
    credential_id: &[u8],
) -> Result<bool, RequestError> {
    let mut r = cbor::Reader::new(allow_list);

    let len = read_typed_array_len(&mut r)?;
    let mut found = false;

    for _ in 0..len {
        let item = r.remaining();
        expect_map(item)?;
        r.skip_value().ok_or(RequestError::InvalidCbor)?;

        if let CredentialDescriptor::PublicKey { id } = read_credential_descriptor(item)? {
            if id == credential_id {
                found = true;
            }
        }
    }

    Ok(found)
}

pub(super) fn validate_credential_descriptor_list(data: &[u8]) -> Result<(), RequestError> {
    let mut r = cbor::Reader::new(data);
    let len = read_typed_array_len(&mut r)?;

    for _ in 0..len {
        let item = r.remaining();
        expect_map(item)?;
        r.skip_value().ok_or(RequestError::InvalidCbor)?;
        read_credential_descriptor(item)?;
    }

    Ok(())
}

pub(super) enum CredentialDescriptor<'a> {
    PublicKey { id: &'a [u8] },
    UnsupportedType,
}

pub(super) fn read_credential_descriptor(
    data: &[u8],
) -> Result<CredentialDescriptor<'_>, RequestError> {
    let mut r = cbor::Reader::new(data);

    let map_len = read_typed_map_len(&mut r)?;
    let mut id = None;
    let mut type_is_public_key = None;

    for _ in 0..map_len {
        let key = read_typed_text(&mut r)?;

        match key {
            b"id" if id.is_none() => id = Some(read_typed_bytes(&mut r)?),
            b"type" if type_is_public_key.is_none() => {
                type_is_public_key = Some(read_typed_text(&mut r)? == b"public-key")
            }
            b"id" | b"type" => return Err(RequestError::InvalidCbor),
            _ => r.skip_value().ok_or(RequestError::InvalidCbor)?,
        }
    }

    let id = id.ok_or(RequestError::MissingParameter)?;

    if type_is_public_key.ok_or(RequestError::MissingParameter)? {
        Ok(CredentialDescriptor::PublicKey { id })
    } else {
        Ok(CredentialDescriptor::UnsupportedType)
    }
}
