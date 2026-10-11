use crate::ctaphid::{
    cbor::{self, Writer},
    crypto,
    entropy::EntropySource,
    pin_uv_auth::{
        DEFAULT_PIN_UV_AUTH_TOKEN_PERMISSIONS, PERMISSION_CREDENTIAL_MANAGEMENT,
        PERMISSION_GET_ASSERTION, PERMISSION_MAKE_CREDENTIAL, PinUvAuthProvider, PinVerification,
        with_client_pin_crypto,
    },
};

use super::{
    request::{
        self, CborInteger, read_typed_bytes, read_typed_integer, read_typed_map_len,
        read_typed_text, read_typed_uint,
    },
    status,
};
#[cfg(feature = "hmac-secret")]
use zeroize::Zeroize;

const GET_RETRIES: u64 = 0x01;
const GET_KEY_AGREEMENT: u64 = 0x02;
const SET_PIN: u64 = 0x03;
const CHANGE_PIN: u64 = 0x04;
const GET_PIN_TOKEN: u64 = 0x05;
const GET_PIN_UV_AUTH_TOKEN_USING_PIN_WITH_PERMISSIONS: u64 = 0x09;

const SUPPORTED_TOKEN_PERMISSIONS: u8 =
    PERMISSION_MAKE_CREDENTIAL | PERMISSION_GET_ASSERTION | PERMISSION_CREDENTIAL_MANAGEMENT;

fn encrypted_len(protocol: u64, plaintext_len: usize) -> usize {
    plaintext_len + if protocol == 2 { 16 } else { 0 }
}

pub(super) enum SharedSecret {
    One([u8; 32]),
    Two([u8; 64]),
}

fn take_key_agreement_secret<A: PinUvAuthProvider>(
    pin_uv_auth: &mut A,
    peer_x: &[u8; 32],
    peer_y: &[u8; 32],
) -> Option<[u8; 32]> {
    if let Some(private_key) = pin_uv_auth.take_key_agreement_private_key() {
        return with_client_pin_crypto(pin_uv_auth, |backend| {
            backend.ecdh(&private_key, peer_x, peer_y)
        });
    }
    if pin_uv_auth.take_backend_owned_key_agreement() {
        return with_client_pin_crypto(pin_uv_auth, |backend| backend.ecdh_current(peer_x, peer_y));
    }
    None
}

impl SharedSecret {
    #[cfg(feature = "hmac-secret")]
    fn clear(&mut self) {
        match self {
            Self::One(key) => key.zeroize(),
            Self::Two(key) => key.zeroize(),
        }
    }

    fn new<A: PinUvAuthProvider>(provider: &mut A, protocol: u8, ecdh: &[u8; 32]) -> Option<Self> {
        with_client_pin_crypto(provider, |backend| {
            if protocol == 2 {
                backend.protocol_two_shared_secret(ecdh).map(Self::Two)
            } else {
                backend.protocol_one_shared_secret(ecdh).map(Self::One)
            }
        })
    }

    fn verify<A: PinUvAuthProvider>(
        &self,
        provider: &mut A,
        parts: &[&[u8]],
        param: &[u8],
    ) -> bool {
        with_client_pin_crypto(provider, |backend| match self {
            Self::One(key) => backend.verify_protocol_one_auth_param(key, parts, param),
            Self::Two(key) => backend.verify_protocol_two_auth_param(key, parts, param),
        })
    }

    fn decrypt<'a, A: PinUvAuthProvider>(
        &self,
        provider: &mut A,
        encrypted: &'a mut [u8],
    ) -> Option<&'a [u8]> {
        with_client_pin_crypto(provider, |backend| match self {
            Self::One(key) => backend.decrypt_protocol_one(key, encrypted),
            Self::Two(key) => backend.decrypt_protocol_two(key, encrypted),
        })
    }

    fn encrypt_token<'a, A: PinUvAuthProvider, E: EntropySource>(
        &self,
        provider: &mut A,
        token: &[u8; 32],
        entropy: &mut E,
        output: &'a mut [u8; 48],
    ) -> Option<&'a [u8]> {
        match self {
            Self::One(key) => {
                output[..32].copy_from_slice(token);
                with_client_pin_crypto(provider, |backend| {
                    backend.encrypt_protocol_one(key, &mut output[..32])
                })
            }
            Self::Two(key) => {
                let iv = crypto::generate_random_bytes::<_, 16>(entropy)?;
                with_client_pin_crypto(provider, |backend| {
                    backend.encrypt_protocol_two(key, &iv, token, output)
                })
            }
        }
    }

    #[cfg(feature = "hmac-secret")]
    fn hmac<A: PinUvAuthProvider>(
        &self,
        provider: &mut A,
        key: &[u8],
        parts: &[&[u8]],
    ) -> Option<[u8; 32]> {
        with_client_pin_crypto(provider, |backend| backend.hmac_sha256(key, parts))
    }

    #[cfg(feature = "hmac-secret")]
    fn encrypt<'a, A: PinUvAuthProvider, E: EntropySource>(
        &self,
        provider: &mut A,
        plaintext: &[u8],
        entropy: &mut E,
        output: &'a mut [u8; 80],
    ) -> Option<&'a [u8]> {
        match self {
            Self::One(key) => {
                output[..plaintext.len()].copy_from_slice(plaintext);
                with_client_pin_crypto(provider, |backend| {
                    backend.encrypt_protocol_one(key, &mut output[..plaintext.len()])
                })
            }
            Self::Two(key) => {
                let iv = crypto::generate_random_bytes::<_, 16>(entropy)?;
                with_client_pin_crypto(provider, |backend| {
                    backend.encrypt_protocol_two(key, &iv, plaintext, output)
                })
            }
        }
    }
}

pub(super) struct PlatformKeyAgreement {
    pub(super) x: [u8; 32],
    pub(super) y: [u8; 32],
}

struct ClientPinRequest<'a> {
    protocol: Option<u64>,
    subcommand: u64,
    key_agreement: Option<PlatformKeyAgreement>,
    pin_uv_auth_param: Option<&'a [u8]>,
    new_pin_enc: Option<&'a [u8]>,
    pin_hash_enc: Option<&'a [u8]>,
    permissions: Option<u64>,
    rp_id: Option<&'a [u8]>,
}

fn read_request(data: &[u8]) -> Result<ClientPinRequest<'_>, u8> {
    let mut r = cbor::Reader::new(data);
    let map_len = read_typed_map_len(&mut r).map_err(request::error_status)?;
    let mut protocol = None;
    let mut subcommand = None;
    let mut key_agreement = None;
    let mut pin_uv_auth_param = None;
    let mut new_pin_enc = None;
    let mut pin_hash_enc = None;
    let mut permissions = None;
    let mut rp_id = None;

    for _ in 0..map_len {
        match read_typed_uint(&mut r).map_err(request::error_status)? {
            1 if protocol.is_none() => {
                protocol = Some(read_typed_uint(&mut r).map_err(request::error_status)?)
            }
            2 if subcommand.is_none() => {
                subcommand = Some(read_typed_uint(&mut r).map_err(request::error_status)?)
            }
            3 if key_agreement.is_none() => {
                key_agreement = Some(read_platform_key_agreement(&mut r)?)
            }
            4 if pin_uv_auth_param.is_none() => {
                pin_uv_auth_param = Some(read_typed_bytes(&mut r).map_err(request::error_status)?)
            }
            5 if new_pin_enc.is_none() => {
                new_pin_enc = Some(read_typed_bytes(&mut r).map_err(request::error_status)?)
            }
            6 if pin_hash_enc.is_none() => {
                pin_hash_enc = Some(read_typed_bytes(&mut r).map_err(request::error_status)?)
            }
            9 if permissions.is_none() => {
                permissions = Some(read_typed_uint(&mut r).map_err(request::error_status)?)
            }
            10 if rp_id.is_none() => {
                rp_id = Some(read_typed_text(&mut r).map_err(request::error_status)?)
            }
            1 | 2 | 3 | 4 | 5 | 6 | 9 | 10 => return Err(status::INVALID_CBOR),
            _ => r.skip_value().ok_or(status::INVALID_CBOR)?,
        }
    }

    if !r.remaining().is_empty() {
        return Err(status::INVALID_CBOR);
    }

    Ok(ClientPinRequest {
        protocol,
        subcommand: subcommand.ok_or(status::MISSING_PARAMETER)?,
        key_agreement,
        pin_uv_auth_param,
        new_pin_enc,
        pin_hash_enc,
        permissions,
        rp_id,
    })
}

pub(super) fn read_platform_key_agreement(
    r: &mut cbor::Reader<'_>,
) -> Result<PlatformKeyAgreement, u8> {
    let map_len = read_typed_map_len(r).map_err(request::error_status)?;
    let mut kty = None;
    let mut alg = None;
    let mut crv = None;
    let mut x = None;
    let mut y = None;

    for _ in 0..map_len {
        let label = read_typed_integer(r).map_err(request::error_status)?;
        match label {
            CborInteger::Unsigned(1) if kty.is_none() => {
                kty = Some(read_typed_uint(r).map_err(request::error_status)?)
            }
            CborInteger::Unsigned(3) if alg.is_none() => {
                alg = Some(read_typed_integer(r).map_err(request::error_status)?)
            }
            CborInteger::Negative(-1) if crv.is_none() => {
                crv = Some(read_typed_uint(r).map_err(request::error_status)?)
            }
            CborInteger::Negative(-2) if x.is_none() => x = Some(read_coordinate(r)?),
            CborInteger::Negative(-3) if y.is_none() => y = Some(read_coordinate(r)?),
            CborInteger::Unsigned(1 | 3) | CborInteger::Negative(-1 | -2 | -3) => {
                return Err(status::INVALID_CBOR);
            }
            _ => r.skip_value().ok_or(status::INVALID_CBOR)?,
        }
    }

    if kty != Some(2) || alg != Some(CborInteger::Negative(-25)) || crv != Some(1) {
        return Err(status::INVALID_PARAMETER);
    }

    Ok(PlatformKeyAgreement {
        x: x.ok_or(status::INVALID_PARAMETER)?,
        y: y.ok_or(status::INVALID_PARAMETER)?,
    })
}

#[cfg(feature = "hmac-secret")]
/// Secret session state; drop clears owned fields, not all temporary or backend copies.
pub(super) struct HmacSecretState {
    shared_secret: SharedSecret,
    salts: [u8; 64],
    salts_len: u8,
}

#[cfg(feature = "hmac-secret")]
impl HmacSecretState {
    pub(super) fn clear(&mut self) {
        self.shared_secret.clear();
        self.salts.zeroize();
        self.salts_len = 0;
    }
}

#[cfg(feature = "hmac-secret")]
impl Drop for HmacSecretState {
    fn drop(&mut self) {
        self.clear();
    }
}

#[cfg(feature = "hmac-secret")]
/// Consumes current key-agreement state; failure does not restore it.
pub(super) fn establish_hmac_secret<A: PinUvAuthProvider>(
    provider: &mut A,
    protocol: u8,
    peer: &PlatformKeyAgreement,
    salt_enc: &[u8],
    salt_auth: &[u8],
) -> Result<HmacSecretState, u8> {
    if !matches!(protocol, 1 | 2) || !provider.supported_pin_protocols().contains(&protocol) {
        return Err(status::INVALID_PARAMETER);
    }
    let valid_encrypted_len = match protocol {
        1 => matches!(salt_enc.len(), 32 | 64),
        2 => matches!(salt_enc.len(), 48 | 80),
        _ => false,
    };
    if !valid_encrypted_len || salt_enc.len() > 80 {
        return Err(status::INVALID_PARAMETER);
    }

    let mut ecdh =
        take_key_agreement_secret(provider, &peer.x, &peer.y).ok_or(status::PIN_AUTH_INVALID)?;
    let mut shared_secret = match SharedSecret::new(provider, protocol, &ecdh) {
        Some(value) => value,
        None => {
            ecdh.zeroize();
            return Err(status::PIN_AUTH_INVALID);
        }
    };
    ecdh.zeroize();
    if !shared_secret.verify(provider, &[salt_enc], salt_auth) {
        shared_secret.clear();
        return Err(status::PIN_AUTH_INVALID);
    }

    let mut encrypted = [0u8; 80];
    encrypted[..salt_enc.len()].copy_from_slice(salt_enc);
    let mut state_salts = [0u8; 64];
    let salts_len = match shared_secret.decrypt(provider, &mut encrypted[..salt_enc.len()]) {
        Some(salts) if matches!(salts.len(), 32 | 64) => {
            state_salts[..salts.len()].copy_from_slice(salts);
            salts.len()
        }
        _ => {
            encrypted.zeroize();
            shared_secret.clear();
            return Err(status::INVALID_PARAMETER);
        }
    };
    encrypted.zeroize();
    Ok(HmacSecretState {
        shared_secret,
        salts: state_salts,
        salts_len: salts_len as u8,
    })
}

#[cfg(feature = "hmac-secret")]
/// Callers discard output after failure; cleanup does not guarantee erasure of backend copies.
pub(super) fn evaluate_hmac_secret<'a, A: PinUvAuthProvider, E: EntropySource>(
    provider: &mut A,
    state: &HmacSecretState,
    cred_random: &[u8; 32],
    entropy: &mut E,
    output: &'a mut [u8; 80],
) -> Option<&'a [u8]> {
    let salts_len = state.salts_len as usize;
    if !matches!(salts_len, 32 | 64) {
        return None;
    }
    let mut plaintext = [0u8; 64];
    let mut first = state
        .shared_secret
        .hmac(provider, cred_random, &[&state.salts[..32]])?;
    plaintext[..32].copy_from_slice(&first);
    first.zeroize();
    if salts_len == 64 {
        let Some(mut second) =
            state
                .shared_secret
                .hmac(provider, cred_random, &[&state.salts[32..64]])
        else {
            plaintext.zeroize();
            return None;
        };
        plaintext[32..64].copy_from_slice(&second);
        second.zeroize();
    }
    let output_len =
        match state
            .shared_secret
            .encrypt(provider, &plaintext[..salts_len], entropy, output)
        {
            Some(encrypted) => encrypted.len(),
            None => {
                plaintext.zeroize();
                return None;
            }
        };
    plaintext.zeroize();
    Some(&output[..output_len])
}

fn read_coordinate(r: &mut cbor::Reader<'_>) -> Result<[u8; 32], u8> {
    read_typed_bytes(r)
        .map_err(request::error_status)?
        .try_into()
        .map_err(|_| status::INVALID_PARAMETER)
}

/// Requires configured response capacity; undersized buffers may panic after state changes.
/// Providers own persistence, retry/token state and crypto exclusion; transient secrets are not erased on every path.
pub(super) fn client_pin<'a, A: PinUvAuthProvider, E: EntropySource>(
    data: &[u8],
    pin_uv_auth: &mut A,
    entropy: &mut E,
    buf: &'a mut [u8],
) -> &'a [u8] {
    let request = match read_request(data) {
        Ok(value) => value,
        Err(error) => {
            buf[0] = error;
            return &buf[..1];
        }
    };

    if request.protocol == Some(2) && !pin_uv_auth.supported_pin_protocols().contains(&2) {
        buf[0] = status::INVALID_PARAMETER;
        return &buf[..1];
    }

    match request.subcommand {
        GET_RETRIES => write_retries(pin_uv_auth, buf),
        GET_KEY_AGREEMENT => {
            if !matches!(request.protocol, Some(1 | 2)) {
                buf[0] = if request.protocol.is_some() {
                    status::INVALID_PARAMETER
                } else {
                    status::MISSING_PARAMETER
                };
                return &buf[..1];
            }
            write_key_agreement(pin_uv_auth, entropy, buf)
        }
        SET_PIN => set_pin(request, pin_uv_auth, buf),
        CHANGE_PIN => change_pin(request, pin_uv_auth, buf),
        GET_PIN_TOKEN => get_pin_token(
            request,
            pin_uv_auth,
            entropy,
            DEFAULT_PIN_UV_AUTH_TOKEN_PERMISSIONS,
            None,
            buf,
        ),
        GET_PIN_UV_AUTH_TOKEN_USING_PIN_WITH_PERMISSIONS => {
            let (Some(permissions), rp_id) = (request.permissions, request.rp_id) else {
                buf[0] = status::MISSING_PARAMETER;
                return &buf[..1];
            };
            if permissions == 0 || permissions > u8::MAX as u64 {
                buf[0] = status::INVALID_PARAMETER;
                return &buf[..1];
            }

            let permissions = (permissions as u8) & SUPPORTED_TOKEN_PERMISSIONS;
            if permissions == 0 {
                buf[0] = status::UNAUTHORIZED_PERMISSION;
                return &buf[..1];
            }

            let rp_id_hash = rp_id.map(super::request::rp_id_hash);
            get_pin_token(request, pin_uv_auth, entropy, permissions, rp_id_hash, buf)
        }
        _ => {
            buf[0] = status::INVALID_SUBCOMMAND;
            &buf[..1]
        }
    }
}

fn change_pin<'a, A: PinUvAuthProvider>(
    request: ClientPinRequest<'_>,
    pin_uv_auth: &mut A,
    buf: &'a mut [u8],
) -> &'a [u8] {
    if !pin_uv_auth.pin_is_set() {
        buf[0] = status::PIN_NOT_SET;
        return &buf[..1];
    }
    if !matches!(request.protocol, Some(1 | 2)) {
        buf[0] = if request.protocol.is_some() {
            status::INVALID_PARAMETER
        } else {
            status::MISSING_PARAMETER
        };
        return &buf[..1];
    }

    let (Some(platform_key), Some(pin_uv_auth_param), Some(new_pin_enc), Some(pin_hash_enc)) = (
        request.key_agreement,
        request.pin_uv_auth_param,
        request.new_pin_enc,
        request.pin_hash_enc,
    ) else {
        buf[0] = status::MISSING_PARAMETER;
        return &buf[..1];
    };
    if new_pin_enc.len() != encrypted_len(request.protocol.unwrap(), 64)
        || pin_hash_enc.len() != encrypted_len(request.protocol.unwrap(), 16)
    {
        buf[0] = status::INVALID_PARAMETER;
        return &buf[..1];
    }

    let Some(ecdh_secret) =
        take_key_agreement_secret(pin_uv_auth, &platform_key.x, &platform_key.y)
    else {
        buf[0] = status::INVALID_PARAMETER;
        return &buf[..1];
    };
    let Some(shared_secret) =
        SharedSecret::new(pin_uv_auth, request.protocol.unwrap() as u8, &ecdh_secret)
    else {
        buf[0] = status::OTHER;
        return &buf[..1];
    };
    if !shared_secret.verify(pin_uv_auth, &[new_pin_enc, pin_hash_enc], pin_uv_auth_param) {
        buf[0] = status::PIN_AUTH_INVALID;
        return &buf[..1];
    }

    let mut encrypted_pin_hash = [0u8; 32];
    encrypted_pin_hash[..pin_hash_enc.len()].copy_from_slice(pin_hash_enc);
    let Some(decrypted_pin_hash) =
        shared_secret.decrypt(pin_uv_auth, &mut encrypted_pin_hash[..pin_hash_enc.len()])
    else {
        buf[0] = status::PIN_AUTH_INVALID;
        return &buf[..1];
    };
    let pin_hash: [u8; 16] = decrypted_pin_hash
        .try_into()
        .expect("pinHashEnc length was checked");
    match pin_uv_auth.verify_pin_hash(&pin_hash) {
        Ok(PinVerification::Matched) => {}
        Ok(PinVerification::Mismatched) => {
            buf[0] = status::PIN_INVALID;
            return &buf[..1];
        }
        Ok(PinVerification::AuthBlocked) => {
            buf[0] = status::PIN_AUTH_BLOCKED;
            return &buf[..1];
        }
        Ok(PinVerification::Blocked) => {
            buf[0] = status::PIN_BLOCKED;
            return &buf[..1];
        }
        Err(_) => {
            buf[0] = status::OTHER;
            return &buf[..1];
        }
    }

    let new_pin_hash = match decrypt_new_pin_hash(pin_uv_auth, &shared_secret, new_pin_enc) {
        Ok(pin_hash) => pin_hash,
        Err(NewPinError::Decrypt) => {
            buf[0] = status::PIN_AUTH_INVALID;
            return &buf[..1];
        }
        Err(NewPinError::Backend) => {
            buf[0] = status::OTHER;
            return &buf[..1];
        }
        Err(NewPinError::Policy) => {
            buf[0] = status::PIN_POLICY_VIOLATION;
            return &buf[..1];
        }
    };
    if pin_uv_auth.store_pin_hash(new_pin_hash).is_err() {
        buf[0] = status::OTHER;
        return &buf[..1];
    }

    buf[0] = status::OK;
    &buf[..1]
}

fn set_pin<'a, A: PinUvAuthProvider>(
    request: ClientPinRequest<'_>,
    pin_uv_auth: &mut A,
    buf: &'a mut [u8],
) -> &'a [u8] {
    if !pin_uv_auth.supports_pin_setting() {
        buf[0] = status::PIN_NOT_SET;
        return &buf[..1];
    }
    if pin_uv_auth.pin_is_set() {
        buf[0] = status::PIN_AUTH_INVALID;
        return &buf[..1];
    }
    if !matches!(request.protocol, Some(1 | 2)) {
        buf[0] = if request.protocol.is_some() {
            status::INVALID_PARAMETER
        } else {
            status::MISSING_PARAMETER
        };
        return &buf[..1];
    }

    let (Some(platform_key), Some(pin_uv_auth_param), Some(new_pin_enc)) = (
        request.key_agreement,
        request.pin_uv_auth_param,
        request.new_pin_enc,
    ) else {
        buf[0] = status::MISSING_PARAMETER;
        return &buf[..1];
    };

    let Some(ecdh_secret) =
        take_key_agreement_secret(pin_uv_auth, &platform_key.x, &platform_key.y)
    else {
        buf[0] = status::INVALID_PARAMETER;
        return &buf[..1];
    };
    let Some(shared_secret) =
        SharedSecret::new(pin_uv_auth, request.protocol.unwrap() as u8, &ecdh_secret)
    else {
        buf[0] = status::OTHER;
        return &buf[..1];
    };

    if !shared_secret.verify(pin_uv_auth, &[new_pin_enc], pin_uv_auth_param) {
        buf[0] = status::PIN_AUTH_INVALID;
        return &buf[..1];
    }
    if new_pin_enc.len() != encrypted_len(request.protocol.unwrap(), 64) {
        buf[0] = status::INVALID_PARAMETER;
        return &buf[..1];
    }

    let pin_hash = match decrypt_new_pin_hash(pin_uv_auth, &shared_secret, new_pin_enc) {
        Ok(pin_hash) => pin_hash,
        Err(NewPinError::Decrypt) => {
            buf[0] = status::PIN_AUTH_INVALID;
            return &buf[..1];
        }
        Err(NewPinError::Backend) => {
            buf[0] = status::OTHER;
            return &buf[..1];
        }
        Err(NewPinError::Policy) => {
            buf[0] = status::PIN_POLICY_VIOLATION;
            return &buf[..1];
        }
    };
    if pin_uv_auth.store_pin_hash(pin_hash).is_err() {
        buf[0] = status::OTHER;
        return &buf[..1];
    }

    buf[0] = status::OK;
    &buf[..1]
}

enum NewPinError {
    Backend,
    Decrypt,
    Policy,
}

fn decrypt_new_pin_hash<A: PinUvAuthProvider>(
    pin_uv_auth: &mut A,
    shared_secret: &SharedSecret,
    new_pin_enc: &[u8],
) -> Result<[u8; 16], NewPinError> {
    if !matches!(new_pin_enc.len(), 64 | 80) {
        return Err(NewPinError::Decrypt);
    }
    let mut encrypted_pin = [0u8; 80];
    encrypted_pin[..new_pin_enc.len()].copy_from_slice(new_pin_enc);
    let padded_pin = shared_secret
        .decrypt(pin_uv_auth, &mut encrypted_pin[..new_pin_enc.len()])
        .ok_or(NewPinError::Decrypt)?;
    let pin_len = padded_pin
        .iter()
        .rposition(|byte| *byte != 0)
        .map_or(0, |index| index + 1);
    let pin = &padded_pin[..pin_len];
    if pin.len() > 63 || core::str::from_utf8(pin).map_or(true, |value| value.chars().count() < 4) {
        return Err(NewPinError::Policy);
    }
    with_client_pin_crypto(pin_uv_auth, |backend| backend.pin_hash(pin)).ok_or(NewPinError::Backend)
}

fn get_pin_token<'a, A: PinUvAuthProvider, E: EntropySource>(
    request: ClientPinRequest<'_>,
    pin_uv_auth: &mut A,
    entropy: &mut E,
    permissions: u8,
    rp_id_hash: Option<[u8; 32]>,
    buf: &'a mut [u8],
) -> &'a [u8] {
    if !pin_uv_auth.pin_is_set() {
        buf[0] = status::PIN_NOT_SET;
        return &buf[..1];
    }
    if !matches!(request.protocol, Some(1 | 2)) {
        buf[0] = if request.protocol.is_some() {
            status::INVALID_PARAMETER
        } else {
            status::MISSING_PARAMETER
        };
        return &buf[..1];
    }

    let (Some(platform_key), Some(pin_hash_enc)) = (request.key_agreement, request.pin_hash_enc)
    else {
        buf[0] = status::MISSING_PARAMETER;
        return &buf[..1];
    };
    if pin_hash_enc.len() != encrypted_len(request.protocol.unwrap(), 16) {
        buf[0] = status::INVALID_PARAMETER;
        return &buf[..1];
    }

    let Some(ecdh_secret) =
        take_key_agreement_secret(pin_uv_auth, &platform_key.x, &platform_key.y)
    else {
        buf[0] = status::INVALID_PARAMETER;
        return &buf[..1];
    };
    let Some(shared_secret) =
        SharedSecret::new(pin_uv_auth, request.protocol.unwrap() as u8, &ecdh_secret)
    else {
        buf[0] = status::OTHER;
        return &buf[..1];
    };

    let mut encrypted_pin_hash = [0u8; 32];
    encrypted_pin_hash[..pin_hash_enc.len()].copy_from_slice(pin_hash_enc);
    let Some(decrypted_pin_hash) =
        shared_secret.decrypt(pin_uv_auth, &mut encrypted_pin_hash[..pin_hash_enc.len()])
    else {
        buf[0] = status::PIN_AUTH_INVALID;
        return &buf[..1];
    };
    let pin_hash: [u8; 16] = decrypted_pin_hash
        .try_into()
        .expect("pinHashEnc length was checked");

    match pin_uv_auth.verify_pin_hash(&pin_hash) {
        Ok(PinVerification::Matched) => {}
        Ok(PinVerification::Mismatched) => {
            buf[0] = status::PIN_INVALID;
            return &buf[..1];
        }
        Ok(PinVerification::AuthBlocked) => {
            buf[0] = status::PIN_AUTH_BLOCKED;
            return &buf[..1];
        }
        Ok(PinVerification::Blocked) => {
            buf[0] = status::PIN_BLOCKED;
            return &buf[..1];
        }
        Err(_) => {
            buf[0] = status::OTHER;
            return &buf[..1];
        }
    }

    let Some(token) = crypto::generate_random_bytes::<_, 32>(entropy) else {
        buf[0] = status::OTHER;
        return &buf[..1];
    };
    let mut token_buffer = [0u8; 48];
    let Some(token_enc) =
        shared_secret.encrypt_token(pin_uv_auth, &token, entropy, &mut token_buffer)
    else {
        buf[0] = status::OTHER;
        return &buf[..1];
    };

    if pin_uv_auth
        .store_pin_uv_auth_token_for_protocol(
            request.protocol.unwrap() as u8,
            token,
            permissions,
            rp_id_hash,
        )
        .is_err()
    {
        buf[0] = status::OTHER;
        return &buf[..1];
    }
    let mut writer = Writer::new(buf);
    writer.write_raw_u8(status::OK).unwrap();
    writer.write_map_len(1).unwrap();
    writer.write_uint(2).unwrap();
    writer.write_bytes(token_enc).unwrap();
    writer.finish()
}

fn write_retries<'a, A: PinUvAuthProvider>(pin_uv_auth: &mut A, buf: &'a mut [u8]) -> &'a [u8] {
    let mut writer = Writer::new(buf);
    writer.write_raw_u8(status::OK).unwrap();
    writer.write_map_len(1).unwrap();
    writer.write_uint(3).unwrap();
    writer.write_uint(pin_uv_auth.pin_retries() as u64).unwrap();
    writer.finish()
}

fn write_key_agreement<'a, A: PinUvAuthProvider, E: EntropySource>(
    pin_uv_auth: &mut A,
    entropy: &mut E,
    buf: &'a mut [u8],
) -> &'a [u8] {
    let Some(key_agreement) = with_client_pin_crypto(pin_uv_auth, |backend| {
        backend.generate_key_agreement(entropy)
    }) else {
        buf[0] = status::OTHER;
        return &buf[..1];
    };
    let (public_x, public_y) = key_agreement.public_xy();
    let (public_x, public_y) = (*public_x, *public_y);
    match key_agreement {
        crypto::P256KeyAgreement::Exported(key_pair) => {
            pin_uv_auth.store_key_agreement_private_key(key_pair.private_key);
        }
        crypto::P256KeyAgreement::BackendOwned { .. } => {
            pin_uv_auth.store_backend_owned_key_agreement();
        }
    }

    let mut writer = Writer::new(buf);
    writer.write_raw_u8(status::OK).unwrap();
    writer.write_map_len(1).unwrap();
    writer.write_uint(1).unwrap();
    writer.write_map_len(5).unwrap();
    writer.write_uint(1).unwrap();
    writer.write_uint(2).unwrap();
    writer.write_uint(3).unwrap();
    writer.write_negint(-25).unwrap();
    writer.write_negint(-1).unwrap();
    writer.write_uint(1).unwrap();
    writer.write_negint(-2).unwrap();
    writer.write_bytes(&public_x).unwrap();
    writer.write_negint(-3).unwrap();
    writer.write_bytes(&public_y).unwrap();
    writer.finish()
}
