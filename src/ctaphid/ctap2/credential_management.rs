use crate::ctaphid::{
    cbor,
    credential::{self, CREDENTIAL_ID_LEN, ResidentRp},
    key_store::PrivateKeyStore,
    pin_uv_auth::{PERMISSION_CREDENTIAL_MANAGEMENT, PinUvAuthProvider},
    storage::{MAX_RECORDS, Storage, StorageBackend},
};

use super::{
    credential_descriptor::{CredentialDescriptor, read_credential_descriptor},
    request::{
        self, PinUvAuth, RequestError, expect_map, read_typed_bytes, read_typed_map_len,
        read_typed_text, read_typed_uint,
    },
    status,
};

const SUB_COMMAND: u64 = 0x01;
const SUB_COMMAND_PARAMS: u64 = 0x02;
const PIN_UV_AUTH_PROTOCOL: u64 = 0x03;
const PIN_UV_AUTH_PARAM: u64 = 0x04;

const GET_CREDS_METADATA: u64 = 0x01;
const ENUMERATE_RPS_BEGIN: u64 = 0x02;
const ENUMERATE_RPS_GET_NEXT_RP: u64 = 0x03;
const ENUMERATE_CREDENTIALS_BEGIN: u64 = 0x04;
const ENUMERATE_CREDENTIALS_GET_NEXT_CREDENTIAL: u64 = 0x05;
const DELETE_CREDENTIAL: u64 = 0x06;
const UPDATE_USER_INFORMATION: u64 = 0x07;

const PARAM_RP_ID_HASH: u64 = 0x01;
const PARAM_CREDENTIAL_ID: u64 = 0x02;
const PARAM_USER: u64 = 0x03;

const RESPONSE_EXISTING_RESIDENT_CREDENTIALS_COUNT: u64 = 0x01;
const RESPONSE_MAX_POSSIBLE_REMAINING_RESIDENT_CREDENTIALS_COUNT: u64 = 0x02;
const RESPONSE_RP: u64 = 0x01;
const RESPONSE_RP_ID_HASH: u64 = 0x02;
const RESPONSE_TOTAL_RPS: u64 = 0x03;
const RESPONSE_USER: u64 = 0x04;
const RESPONSE_CREDENTIAL_ID: u64 = 0x05;
const RESPONSE_PUBLIC_KEY: u64 = 0x06;
const RESPONSE_TOTAL_CREDENTIALS: u64 = 0x07;

/// Enumeration state belongs to the current authorized session; clear does not erase stored RP bytes.
pub struct CredentialManagementState {
    rps: [ResidentRp; MAX_RECORDS],
    credential_indices: [u8; MAX_RECORDS],
    count: usize,
    next: usize,
    kind: EnumerationKind,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum EnumerationKind {
    None,
    Rps,
    Credentials,
}

impl CredentialManagementState {
    pub const fn new() -> Self {
        Self {
            rps: [ResidentRp::empty(); MAX_RECORDS],
            credential_indices: [0; MAX_RECORDS],
            count: 0,
            next: 0,
            kind: EnumerationKind::None,
        }
    }

    pub(super) fn clear(&mut self) {
        self.count = 0;
        self.next = 0;
        self.kind = EnumerationKind::None;
    }

    fn set_rps(&mut self, rps: [ResidentRp; MAX_RECORDS], count: usize) {
        self.rps = rps;
        self.count = count;
        self.next = 0;
        self.kind = if count > 0 {
            EnumerationKind::Rps
        } else {
            EnumerationKind::None
        };
    }

    fn set_credentials(&mut self, indices: [u8; MAX_RECORDS], count: usize) {
        self.credential_indices = indices;
        self.count = count;
        self.next = 0;
        self.kind = if count > 0 {
            EnumerationKind::Credentials
        } else {
            EnumerationKind::None
        };
    }

    fn next_rp(&mut self) -> Option<(ResidentRp, bool)> {
        if self.kind != EnumerationKind::Rps || self.next >= self.count {
            self.clear();
            return None;
        }

        let rp = self.rps[self.next];
        self.next += 1;
        if self.next >= self.count {
            self.clear();
            Some((rp, false))
        } else {
            Some((rp, true))
        }
    }

    fn next_credential_index(&mut self) -> Option<(usize, bool)> {
        if self.kind != EnumerationKind::Credentials || self.next >= self.count {
            self.clear();
            return None;
        }

        let index = self.credential_indices[self.next] as usize;
        self.next += 1;
        if self.next >= self.count {
            self.clear();
            Some((index, false))
        } else {
            Some((index, true))
        }
    }
}

struct CredentialManagementRequest<'a> {
    subcommand: u64,
    subcommand_params: Option<&'a [u8]>,
    pin_uv_auth: PinUvAuth<'a>,
}

struct UserUpdate<'a> {
    id: &'a [u8],
    name: &'a [u8],
    display_name: &'a [u8],
}

fn parse_request(data: &[u8]) -> Result<CredentialManagementRequest<'_>, RequestError> {
    let mut r = cbor::Reader::new(data);
    let map_len = read_typed_map_len(&mut r)?;
    let mut subcommand = None;
    let mut subcommand_params = None;
    let mut pin_uv_auth_protocol = None;
    let mut pin_uv_auth_param = None;

    for _ in 0..map_len {
        let key = read_typed_uint(&mut r)?;

        match key {
            SUB_COMMAND if subcommand.is_none() => {
                subcommand = Some(read_typed_uint(&mut r)?);
            }
            SUB_COMMAND_PARAMS if subcommand_params.is_none() => {
                let params = r.remaining();
                expect_map(params)?;
                r.skip_value().ok_or(RequestError::InvalidCbor)?;
                let consumed = params.len() - r.remaining().len();
                subcommand_params = Some(&params[..consumed]);
            }
            PIN_UV_AUTH_PROTOCOL if pin_uv_auth_protocol.is_none() => {
                pin_uv_auth_protocol = Some(read_typed_uint(&mut r)?);
            }
            PIN_UV_AUTH_PARAM if pin_uv_auth_param.is_none() => {
                pin_uv_auth_param = Some(read_typed_bytes(&mut r)?);
            }
            SUB_COMMAND | SUB_COMMAND_PARAMS | PIN_UV_AUTH_PROTOCOL | PIN_UV_AUTH_PARAM => {
                return Err(RequestError::InvalidCbor);
            }
            _ => r.skip_value().ok_or(RequestError::InvalidCbor)?,
        }
    }

    if !r.remaining().is_empty() {
        return Err(RequestError::InvalidCbor);
    }

    Ok(CredentialManagementRequest {
        subcommand: subcommand.ok_or(RequestError::MissingParameter)?,
        subcommand_params,
        pin_uv_auth: PinUvAuth {
            param: pin_uv_auth_param,
            protocol: pin_uv_auth_protocol,
        },
    })
}

fn parse_delete_credential_params(params: &[u8]) -> Result<[u8; CREDENTIAL_ID_LEN], RequestError> {
    let mut r = cbor::Reader::new(params);
    let map_len = read_typed_map_len(&mut r)?;
    let mut credential_id = None;

    for _ in 0..map_len {
        let key = read_typed_uint(&mut r)?;

        match key {
            PARAM_CREDENTIAL_ID if credential_id.is_none() => {
                let descriptor = r.remaining();
                expect_map(descriptor)?;
                r.skip_value().ok_or(RequestError::InvalidCbor)?;
                let consumed = descriptor.len() - r.remaining().len();
                let descriptor = &descriptor[..consumed];

                match read_credential_descriptor(descriptor)? {
                    CredentialDescriptor::PublicKey { id } if id.len() == CREDENTIAL_ID_LEN => {
                        let mut value = [0; CREDENTIAL_ID_LEN];
                        value.copy_from_slice(id);
                        credential_id = Some(value);
                    }
                    CredentialDescriptor::PublicKey { .. }
                    | CredentialDescriptor::UnsupportedType => {
                        return Err(RequestError::InvalidCbor);
                    }
                }
            }
            PARAM_CREDENTIAL_ID => return Err(RequestError::InvalidCbor),
            _ => r.skip_value().ok_or(RequestError::InvalidCbor)?,
        }
    }

    if !r.remaining().is_empty() {
        return Err(RequestError::InvalidCbor);
    }

    credential_id.ok_or(RequestError::MissingParameter)
}

fn parse_rp_id_hash_params(params: &[u8]) -> Result<[u8; 32], RequestError> {
    let mut r = cbor::Reader::new(params);
    let map_len = read_typed_map_len(&mut r)?;
    let mut rp_id_hash = None;

    for _ in 0..map_len {
        let key = read_typed_uint(&mut r)?;

        match key {
            PARAM_RP_ID_HASH if rp_id_hash.is_none() => {
                let bytes = read_typed_bytes(&mut r)?;
                if bytes.len() != 32 {
                    return Err(RequestError::InvalidCbor);
                }
                let mut value = [0; 32];
                value.copy_from_slice(bytes);
                rp_id_hash = Some(value);
            }
            PARAM_RP_ID_HASH => return Err(RequestError::InvalidCbor),
            _ => r.skip_value().ok_or(RequestError::InvalidCbor)?,
        }
    }

    if !r.remaining().is_empty() {
        return Err(RequestError::InvalidCbor);
    }

    rp_id_hash.ok_or(RequestError::MissingParameter)
}

fn parse_user_update_entity(user: &[u8]) -> Result<UserUpdate<'_>, RequestError> {
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
                if value.len() > credential::USER_ID_MAX_LEN {
                    return Err(RequestError::InvalidCbor);
                }
                id = Some(value);
            }
            b"name" if name.is_none() => {
                let value = read_typed_text(&mut r)?;
                if value.len() > credential::USER_NAME_MAX_LEN {
                    return Err(RequestError::InvalidCbor);
                }
                name = Some(value);
            }
            b"displayName" if display_name.is_none() => {
                let value = read_typed_text(&mut r)?;
                if value.len() > credential::USER_DISPLAY_NAME_MAX_LEN {
                    return Err(RequestError::InvalidCbor);
                }
                display_name = Some(value);
            }
            b"id" | b"name" | b"displayName" => return Err(RequestError::InvalidCbor),
            _ => r.skip_value().ok_or(RequestError::InvalidCbor)?,
        }
    }

    if !r.remaining().is_empty() {
        return Err(RequestError::InvalidCbor);
    }

    Ok(UserUpdate {
        id: id.ok_or(RequestError::MissingParameter)?,
        name: name.unwrap_or(&[]),
        display_name: display_name.unwrap_or(&[]),
    })
}

fn parse_update_user_information_params(
    params: &[u8],
) -> Result<([u8; CREDENTIAL_ID_LEN], UserUpdate<'_>), RequestError> {
    let mut r = cbor::Reader::new(params);
    let map_len = read_typed_map_len(&mut r)?;
    let mut credential_id = None;
    let mut user = None;

    for _ in 0..map_len {
        let key = read_typed_uint(&mut r)?;

        match key {
            PARAM_CREDENTIAL_ID if credential_id.is_none() => {
                let descriptor = r.remaining();
                expect_map(descriptor)?;
                r.skip_value().ok_or(RequestError::InvalidCbor)?;
                let consumed = descriptor.len() - r.remaining().len();
                let descriptor = &descriptor[..consumed];

                match read_credential_descriptor(descriptor)? {
                    CredentialDescriptor::PublicKey { id } if id.len() == CREDENTIAL_ID_LEN => {
                        let mut value = [0; CREDENTIAL_ID_LEN];
                        value.copy_from_slice(id);
                        credential_id = Some(value);
                    }
                    CredentialDescriptor::PublicKey { .. }
                    | CredentialDescriptor::UnsupportedType => {
                        return Err(RequestError::InvalidCbor);
                    }
                }
            }
            PARAM_USER if user.is_none() => {
                let item = r.remaining();
                expect_map(item)?;
                r.skip_value().ok_or(RequestError::InvalidCbor)?;
                let consumed = item.len() - r.remaining().len();
                user = Some(parse_user_update_entity(&item[..consumed])?);
            }
            PARAM_CREDENTIAL_ID | PARAM_USER => return Err(RequestError::InvalidCbor),
            _ => r.skip_value().ok_or(RequestError::InvalidCbor)?,
        }
    }

    if !r.remaining().is_empty() {
        return Err(RequestError::InvalidCbor);
    }

    Ok((
        credential_id.ok_or(RequestError::MissingParameter)?,
        user.ok_or(RequestError::MissingParameter)?,
    ))
}

fn delete_credential<'a, B: StorageBackend, A: PinUvAuthProvider, K: PrivateKeyStore>(
    request: &CredentialManagementRequest<'_>,
    storage: &mut Storage<B>,
    pin_uv_auth: &mut A,
    key_store: &mut K,
    buf: &'a mut [u8],
) -> &'a [u8] {
    let Some(params) = request.subcommand_params else {
        buf[0] = status::MISSING_PARAMETER;
        return &buf[..1];
    };
    let credential_id = match parse_delete_credential_params(params) {
        Ok(credential_id) => credential_id,
        Err(err) => {
            buf[0] = request::error_status(err);
            return &buf[..1];
        }
    };
    let Some((_, record)) = credential::find_record_by_id(storage, &credential_id) else {
        buf[0] = status::NO_CREDENTIALS;
        return &buf[..1];
    };

    let message_len = 1 + params.len();
    if buf.len() < message_len {
        buf[0] = status::OTHER;
        return &buf[..1];
    }
    buf[0] = DELETE_CREDENTIAL as u8;
    buf[1..message_len].copy_from_slice(params);

    match request::verify_pin_uv_auth_message(
        &request.pin_uv_auth,
        pin_uv_auth,
        &buf[..message_len],
        PERMISSION_CREDENTIAL_MANAGEMENT,
        Some(record.rp_id_hash),
        true,
    ) {
        Ok(true) => {}
        Ok(false) => {
            buf[0] = status::PUAT_REQUIRED;
            return &buf[..1];
        }
        Err(status) => {
            buf[0] = status;
            return &buf[..1];
        }
    }

    match credential::delete_by_id(storage, &credential_id) {
        Ok(true) => {
            if key_store
                .release_key_material(record.credential.algorithm, &record.credential.key_material)
                .is_err()
            {
                buf[0] = status::OPERATION_DENIED;
                return &buf[..1];
            }
            buf[0] = status::OK;
            &buf[..1]
        }
        Ok(false) => {
            buf[0] = status::NO_CREDENTIALS;
            &buf[..1]
        }
        Err(_) => {
            buf[0] = status::OTHER;
            &buf[..1]
        }
    }
}

fn update_user_information<'a, B: StorageBackend, A: PinUvAuthProvider>(
    request: &CredentialManagementRequest<'_>,
    storage: &mut Storage<B>,
    pin_uv_auth: &mut A,
    buf: &'a mut [u8],
) -> &'a [u8] {
    let Some(params) = request.subcommand_params else {
        buf[0] = status::MISSING_PARAMETER;
        return &buf[..1];
    };
    let (credential_id, user) = match parse_update_user_information_params(params) {
        Ok(params) => params,
        Err(err) => {
            buf[0] = request::error_status(err);
            return &buf[..1];
        }
    };
    let Some((_, record)) = credential::find_record_by_id(storage, &credential_id) else {
        buf[0] = status::NO_CREDENTIALS;
        return &buf[..1];
    };

    let message_len = 1 + params.len();
    if buf.len() < message_len {
        buf[0] = status::OTHER;
        return &buf[..1];
    }
    buf[0] = UPDATE_USER_INFORMATION as u8;
    buf[1..message_len].copy_from_slice(params);

    match request::verify_pin_uv_auth_message(
        &request.pin_uv_auth,
        pin_uv_auth,
        &buf[..message_len],
        PERMISSION_CREDENTIAL_MANAGEMENT,
        Some(record.rp_id_hash),
        true,
    ) {
        Ok(true) => {}
        Ok(false) => {
            buf[0] = status::PUAT_REQUIRED;
            return &buf[..1];
        }
        Err(status) => {
            buf[0] = status;
            return &buf[..1];
        }
    }

    match credential::update_user_by_id(
        storage,
        &credential_id,
        user.id,
        user.name,
        user.display_name,
    ) {
        Ok(true) => {
            buf[0] = status::OK;
            &buf[..1]
        }
        Ok(false) => {
            buf[0] = status::NO_CREDENTIALS;
            &buf[..1]
        }
        Err(credential::CredentialError::InvalidInput) => {
            buf[0] = status::INVALID_PARAMETER;
            &buf[..1]
        }
        Err(_) => {
            buf[0] = status::OTHER;
            &buf[..1]
        }
    }
}

fn get_creds_metadata<'a, B: StorageBackend, A: PinUvAuthProvider>(
    request: &CredentialManagementRequest<'_>,
    storage: &mut Storage<B>,
    pin_uv_auth: &mut A,
    buf: &'a mut [u8],
) -> &'a [u8] {
    if request.subcommand_params.is_some() {
        buf[0] = status::INVALID_PARAMETER;
        return &buf[..1];
    }

    match request::verify_pin_uv_auth_message(
        &request.pin_uv_auth,
        pin_uv_auth,
        &[GET_CREDS_METADATA as u8],
        PERMISSION_CREDENTIAL_MANAGEMENT,
        None,
        true,
    ) {
        Ok(true) => {}
        Ok(false) => {
            buf[0] = status::PUAT_REQUIRED;
            return &buf[..1];
        }
        Err(status) => {
            buf[0] = status;
            return &buf[..1];
        }
    }

    let existing = credential::count_resident(storage) as u64;
    let remaining = credential::remaining_record_capacity(storage) as u64;
    let mut w = cbor::Writer::new(buf);

    w.write_raw_u8(status::OK).unwrap();
    w.write_map_len(2).unwrap();
    w.write_uint(RESPONSE_EXISTING_RESIDENT_CREDENTIALS_COUNT)
        .unwrap();
    w.write_uint(existing).unwrap();
    w.write_uint(RESPONSE_MAX_POSSIBLE_REMAINING_RESIDENT_CREDENTIALS_COUNT)
        .unwrap();
    w.write_uint(remaining).unwrap();

    w.finish()
}

fn write_rp_response<'a>(rp: &ResidentRp, total_rps: Option<usize>, buf: &'a mut [u8]) -> &'a [u8] {
    let mut w = cbor::Writer::new(buf);
    let rp_id = &rp.rp_id[..rp.rp_id_len as usize];

    w.write_raw_u8(status::OK).unwrap();
    w.write_map_len(if total_rps.is_some() { 3 } else { 2 })
        .unwrap();
    w.write_uint(RESPONSE_RP).unwrap();
    w.write_map_len(2).unwrap();
    w.write_text(b"id").unwrap();
    w.write_text(rp_id).unwrap();
    w.write_text(b"name").unwrap();
    w.write_text(rp_id).unwrap();
    w.write_uint(RESPONSE_RP_ID_HASH).unwrap();
    w.write_bytes(&rp.rp_id_hash).unwrap();
    if let Some(total_rps) = total_rps {
        w.write_uint(RESPONSE_TOTAL_RPS).unwrap();
        w.write_uint(total_rps as u64).unwrap();
    }

    w.finish()
}

fn write_user_entity(w: &mut cbor::Writer<'_>, credential: &credential::Credential) -> Option<()> {
    let mut fields = 1;
    if credential.user_name_len > 0 {
        fields += 1;
    }
    if credential.user_display_name_len > 0 {
        fields += 1;
    }

    w.write_map_len(fields)?;
    w.write_text(b"id")?;
    w.write_bytes(&credential.user_id[..credential.user_id_len as usize])?;
    if credential.user_name_len > 0 {
        w.write_text(b"name")?;
        w.write_text(&credential.user_name[..credential.user_name_len as usize])?;
    }
    if credential.user_display_name_len > 0 {
        w.write_text(b"displayName")?;
        w.write_text(&credential.user_display_name[..credential.user_display_name_len as usize])?;
    }

    Some(())
}

fn write_credential_descriptor(
    w: &mut cbor::Writer<'_>,
    credential: &credential::Credential,
) -> Option<()> {
    w.write_map_len(2)?;
    w.write_text(b"id")?;
    w.write_bytes(&credential.id)?;
    w.write_text(b"type")?;
    w.write_text(b"public-key")?;

    Some(())
}

fn write_credential_response<'a, B: StorageBackend, K: PrivateKeyStore>(
    storage: &mut Storage<B>,
    key_store: &mut K,
    index: usize,
    total_credentials: Option<usize>,
    buf: &'a mut [u8],
) -> &'a [u8] {
    let Some(record) = storage.load_record(index) else {
        buf[0] = status::NO_CREDENTIALS;
        return &buf[..1];
    };
    let mut cose_key_buf = [0u8; super::buffers::CREDENTIAL_COSE_KEY_LEN];
    let Some(cose_key) = key_store.write_public_key_cose(
        record.credential.algorithm,
        &record.credential.key_material,
        &mut cose_key_buf,
    ) else {
        buf[0] = status::OTHER;
        return &buf[..1];
    };

    let mut w = cbor::Writer::new(buf);
    w.write_raw_u8(status::OK).unwrap();
    w.write_map_len(if total_credentials.is_some() { 4 } else { 3 })
        .unwrap();
    w.write_uint(RESPONSE_USER).unwrap();
    write_user_entity(&mut w, &record.credential).unwrap();
    w.write_uint(RESPONSE_CREDENTIAL_ID).unwrap();
    write_credential_descriptor(&mut w, &record.credential).unwrap();
    w.write_uint(RESPONSE_PUBLIC_KEY).unwrap();
    w.write_raw_bytes(cose_key).unwrap();
    if let Some(total_credentials) = total_credentials {
        w.write_uint(RESPONSE_TOTAL_CREDENTIALS).unwrap();
        w.write_uint(total_credentials as u64).unwrap();
    }

    w.finish()
}

fn enumerate_rps_begin<'a, B: StorageBackend, A: PinUvAuthProvider>(
    request: &CredentialManagementRequest<'_>,
    storage: &mut Storage<B>,
    pin_uv_auth: &mut A,
    state: &mut CredentialManagementState,
    buf: &'a mut [u8],
) -> &'a [u8] {
    if request.subcommand_params.is_some() {
        buf[0] = status::INVALID_PARAMETER;
        return &buf[..1];
    }

    match request::verify_pin_uv_auth_message(
        &request.pin_uv_auth,
        pin_uv_auth,
        &[ENUMERATE_RPS_BEGIN as u8],
        PERMISSION_CREDENTIAL_MANAGEMENT,
        None,
        true,
    ) {
        Ok(true) => {}
        Ok(false) => {
            buf[0] = status::PUAT_REQUIRED;
            return &buf[..1];
        }
        Err(status) => {
            buf[0] = status;
            return &buf[..1];
        }
    }

    let mut rps = [ResidentRp::empty(); MAX_RECORDS];
    let count = credential::collect_unique_resident_rps(storage, &mut rps);
    if count == 0 {
        state.clear();
        buf[0] = status::NO_CREDENTIALS;
        return &buf[..1];
    }
    state.set_rps(rps, count);

    let Some((rp, more)) = state.next_rp() else {
        buf[0] = status::NO_CREDENTIALS;
        return &buf[..1];
    };
    if !more {
        state.clear();
    }
    write_rp_response(&rp, Some(count), buf)
}

fn enumerate_rps_get_next_rp<'a>(
    request: &CredentialManagementRequest<'_>,
    state: &mut CredentialManagementState,
    buf: &'a mut [u8],
) -> &'a [u8] {
    if request.subcommand_params.is_some()
        || request.pin_uv_auth.param.is_some()
        || request.pin_uv_auth.protocol.is_some()
    {
        buf[0] = status::INVALID_PARAMETER;
        return &buf[..1];
    }

    let Some((rp, _)) = state.next_rp() else {
        buf[0] = status::NOT_ALLOWED;
        return &buf[..1];
    };

    write_rp_response(&rp, None, buf)
}

fn enumerate_credentials_begin<'a, B: StorageBackend, A: PinUvAuthProvider, K: PrivateKeyStore>(
    request: &CredentialManagementRequest<'_>,
    storage: &mut Storage<B>,
    pin_uv_auth: &mut A,
    key_store: &mut K,
    state: &mut CredentialManagementState,
    buf: &'a mut [u8],
) -> &'a [u8] {
    let Some(params) = request.subcommand_params else {
        buf[0] = status::MISSING_PARAMETER;
        return &buf[..1];
    };
    let rp_id_hash = match parse_rp_id_hash_params(params) {
        Ok(rp_id_hash) => rp_id_hash,
        Err(err) => {
            buf[0] = request::error_status(err);
            return &buf[..1];
        }
    };
    let message_len = 1 + params.len();
    if buf.len() < message_len {
        buf[0] = status::OTHER;
        return &buf[..1];
    }
    buf[0] = ENUMERATE_CREDENTIALS_BEGIN as u8;
    buf[1..message_len].copy_from_slice(params);

    match request::verify_pin_uv_auth_message(
        &request.pin_uv_auth,
        pin_uv_auth,
        &buf[..message_len],
        PERMISSION_CREDENTIAL_MANAGEMENT,
        Some(rp_id_hash),
        true,
    ) {
        Ok(true) => {}
        Ok(false) => {
            buf[0] = status::PUAT_REQUIRED;
            return &buf[..1];
        }
        Err(status) => {
            buf[0] = status;
            return &buf[..1];
        }
    }

    let mut indices = [0; MAX_RECORDS];
    let count =
        credential::collect_resident_credential_indices_by_rp(storage, rp_id_hash, &mut indices);
    if count == 0 {
        state.clear();
        buf[0] = status::NO_CREDENTIALS;
        return &buf[..1];
    }
    state.set_credentials(indices, count);

    let Some((index, _)) = state.next_credential_index() else {
        buf[0] = status::NO_CREDENTIALS;
        return &buf[..1];
    };
    write_credential_response(storage, key_store, index, Some(count), buf)
}

fn enumerate_credentials_get_next_credential<'a, B: StorageBackend, K: PrivateKeyStore>(
    request: &CredentialManagementRequest<'_>,
    storage: &mut Storage<B>,
    key_store: &mut K,
    state: &mut CredentialManagementState,
    buf: &'a mut [u8],
) -> &'a [u8] {
    if request.subcommand_params.is_some()
        || request.pin_uv_auth.param.is_some()
        || request.pin_uv_auth.protocol.is_some()
    {
        buf[0] = status::INVALID_PARAMETER;
        return &buf[..1];
    }

    let Some((index, _)) = state.next_credential_index() else {
        buf[0] = status::NOT_ALLOWED;
        return &buf[..1];
    };

    write_credential_response(storage, key_store, index, None, buf)
}

/// Requires configured response capacity; undersized buffers may panic.
/// Mutation errors do not guarantee rollback of record deletion or key release.
pub(super) fn credential_management<
    'a,
    B: StorageBackend,
    A: PinUvAuthProvider,
    K: PrivateKeyStore,
>(
    data: &[u8],
    storage: &mut Storage<B>,
    pin_uv_auth: &mut A,
    key_store: &mut K,
    state: &mut CredentialManagementState,
    buf: &'a mut [u8],
) -> &'a [u8] {
    let request = match parse_request(data) {
        Ok(request) => request,
        Err(err) => {
            buf[0] = request::error_status(err);
            return &buf[..1];
        }
    };

    match request.subcommand {
        ENUMERATE_RPS_BEGIN => enumerate_rps_begin(&request, storage, pin_uv_auth, state, buf),
        ENUMERATE_RPS_GET_NEXT_RP => enumerate_rps_get_next_rp(&request, state, buf),
        ENUMERATE_CREDENTIALS_BEGIN => {
            enumerate_credentials_begin(&request, storage, pin_uv_auth, key_store, state, buf)
        }
        ENUMERATE_CREDENTIALS_GET_NEXT_CREDENTIAL => {
            enumerate_credentials_get_next_credential(&request, storage, key_store, state, buf)
        }
        GET_CREDS_METADATA => get_creds_metadata(&request, storage, pin_uv_auth, buf),
        DELETE_CREDENTIAL => delete_credential(&request, storage, pin_uv_auth, key_store, buf),
        UPDATE_USER_INFORMATION => update_user_information(&request, storage, pin_uv_auth, buf),
        _ => {
            buf[0] = status::INVALID_SUBCOMMAND;
            &buf[..1]
        }
    }
}
