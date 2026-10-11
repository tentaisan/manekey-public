use crate::ctaphid::entropy::EntropySource;
use crate::ctaphid::key_store::PrivateKeyStore;
use crate::ctaphid::pin_uv_auth::PinUvAuthProvider;
use crate::ctaphid::storage::{MAX_RECORDS, Storage, StorageBackend};
use crate::ctaphid::user_verification::UserVerification;

use crate::presence::UserPresence;

pub(crate) mod buffers;
mod capabilities;
#[cfg(any(not(feature = "ctap2-no-client-pin"), feature = "hmac-secret"))]
mod client_pin;
mod credential_descriptor;
mod credential_management;
mod get_assertion;
mod get_info;
mod make_credential;
mod request;
mod reset;

#[cfg(not(feature = "ctap2-no-client-pin"))]
use self::client_pin::client_pin;
pub use self::credential_management::CredentialManagementState;
use self::credential_management::credential_management;
use self::get_assertion::{get_assertion, get_next_assertion};
use self::get_info::{get_info, get_info_with_transports, get_info_with_transports_and_algorithms};
use self::make_credential::make_credential;
use self::request::{Options, PinUvAuth, RequestError};

/// Writes GetInfo using configured response capacity; undersized buffers may panic.
pub fn get_info_response<'a, A: PinUvAuthProvider>(
    pin_uv_auth: &mut A,
    buf: &'a mut [u8],
) -> &'a [u8] {
    get_info(pin_uv_auth, buf)
}

/// Overrides advertised transports only; it does not create or authorize a transport.
/// Requires configured response capacity.
pub fn get_info_response_with_transports<'a, A: PinUvAuthProvider>(
    pin_uv_auth: &mut A,
    buf: &'a mut [u8],
    transports: &[&[u8]],
) -> &'a [u8] {
    get_info_with_transports(pin_uv_auth, buf, transports)
}

use crate::presence::PresenceReason;

#[allow(dead_code)]
mod status {

    pub const OK: u8 = 0x00;

    pub const INVALID_COMMAND: u8 = 0x01;

    pub const INVALID_PARAMETER: u8 = 0x02;

    pub const INVALID_LENGTH: u8 = 0x03;

    pub const CBOR_UNEXPECTED_TYPE: u8 = 0x11;

    pub const INVALID_CBOR: u8 = 0x12;

    pub const MISSING_PARAMETER: u8 = 0x14;

    pub const CREDENTIAL_EXCLUDED: u8 = 0x19;

    pub const UNSUPPORTED_ALGORITHM: u8 = 0x26;

    pub const OPERATION_DENIED: u8 = 0x27;

    pub const KEEPALIVE_CANCEL: u8 = 0x2d;

    pub const KEY_STORE_FULL: u8 = 0x28;

    pub const UNSUPPORTED_OPTION: u8 = 0x2b;

    pub const INVALID_OPTION: u8 = 0x2c;

    pub const NOT_ALLOWED: u8 = 0x30;

    pub const PIN_INVALID: u8 = 0x31;

    pub const PIN_BLOCKED: u8 = 0x32;

    pub const PIN_AUTH_INVALID: u8 = 0x33;

    pub const PIN_AUTH_BLOCKED: u8 = 0x34;

    pub const PIN_NOT_SET: u8 = 0x35;

    pub const PUAT_REQUIRED: u8 = 0x36;

    pub const PIN_POLICY_VIOLATION: u8 = 0x37;

    pub const PIN_TOKEN_EXPIRED: u8 = 0x38;

    pub const OTHER: u8 = 0x7f;

    pub const INVALID_SUBCOMMAND: u8 = 0x3e;

    pub const UNAUTHORIZED_PERMISSION: u8 = 0x40;

    pub const NO_CREDENTIALS: u8 = 0x2e;
}

mod cmd {

    pub const AUTHENTICATOR_MAKE_CREDENTIAL: u8 = 0x01;

    pub const AUTHENTICATOR_GET_ASSERTION: u8 = 0x02;

    pub const AUTHENTICATOR_GET_NEXT_ASSERTION: u8 = 0x08;

    pub const AUTHENTICATOR_GET_INFO: u8 = 0x04;

    pub const AUTHENTICATOR_CLIENT_PIN: u8 = 0x06;

    pub const AUTHENTICATOR_RESET: u8 = 0x07;

    pub const AUTHENTICATOR_CREDENTIAL_MANAGEMENT: u8 = 0x0a;
}

pub(crate) fn user_presence_reason(data: &[u8]) -> Option<PresenceReason> {
    match data.first().copied() {
        Some(cmd::AUTHENTICATOR_MAKE_CREDENTIAL) => Some(PresenceReason::MakeCredential),
        Some(cmd::AUTHENTICATOR_GET_ASSERTION) => Some(PresenceReason::GetAssertion),
        Some(cmd::AUTHENTICATOR_RESET) => Some(PresenceReason::Reset),
        _ => None,
    }
}

pub(crate) const KEEPALIVE_CANCEL_STATUS: u8 = status::KEEPALIVE_CANCEL;

pub(crate) const OPERATION_DENIED_STATUS: u8 = status::OPERATION_DENIED;

struct MakeCredentialRequest<'a> {
    client_data_hash: [u8; 32],
    rp_id: &'a [u8],
    user_id: &'a [u8],
    user_name: &'a [u8],
    user_display_name: &'a [u8],
    protection: crate::ctaphid::credential::CredentialProtection,
    cred_protect_output: Option<crate::ctaphid::credential::CredentialProtection>,
    hmac_secret_requested: bool,
    cred_blob: Option<&'a [u8]>,
    pub_key_cred_params: &'a [u8],
    exclude_list: Option<&'a [u8]>,
    pin_uv_auth: PinUvAuth<'a>,
    options: Options,
}

/// Enumeration state belongs to the current validated session; clearing is not full-byte erasure.
pub struct AssertionState {
    rp_id_hash: [u8; 32],
    client_data_hash: [u8; 32],
    indices: [u8; MAX_RECORDS],
    count: usize,
    next: usize,
    active: bool,
    include_user: bool,
    user_verified: bool,
    #[cfg(feature = "hmac-secret")]
    hmac_secret: Option<client_pin::HmacSecretState>,
    get_cred_blob: bool,
}

impl AssertionState {
    pub const fn new() -> Self {
        Self {
            rp_id_hash: [0; 32],
            client_data_hash: [0; 32],
            indices: [0; MAX_RECORDS],
            count: 0,
            next: 0,
            active: false,
            include_user: false,
            user_verified: false,
            #[cfg(feature = "hmac-secret")]
            hmac_secret: None,
            get_cred_blob: false,
        }
    }

    fn clear(&mut self) {
        #[cfg(feature = "hmac-secret")]
        if let Some(mut state) = self.hmac_secret.take() {
            state.clear();
        }
        self.count = 0;
        self.next = 0;
        self.active = false;
        self.include_user = false;
        self.user_verified = false;
        self.get_cred_blob = false;
    }

    fn set(
        &mut self,
        rp_id_hash: [u8; 32],
        client_data_hash: [u8; 32],
        indices: &[u8; MAX_RECORDS],
        count: usize,
        include_user: bool,
        user_verified: bool,
        #[cfg(feature = "hmac-secret")] hmac_secret: Option<client_pin::HmacSecretState>,
        get_cred_blob: bool,
    ) {
        self.rp_id_hash = rp_id_hash;
        self.client_data_hash = client_data_hash;
        self.indices.copy_from_slice(indices);
        self.count = count;
        self.next = 1;
        self.active = count > 1;
        self.include_user = include_user;
        self.user_verified = user_verified;
        self.get_cred_blob = count > 1 && get_cred_blob;
        #[cfg(feature = "hmac-secret")]
        {
            if count > 1 {
                self.hmac_secret = hmac_secret;
            } else if let Some(mut state) = hmac_secret {
                state.clear();
                self.hmac_secret = None;
            }
        }
    }
}

/// Dispatches with configured response capacity; undersized buffers may panic.
/// Callers isolate enumeration state to the current session and provide trusted UP/UV adapters.
pub fn handle<
    'a,
    B: StorageBackend,
    P: UserPresence,
    V: UserVerification,
    A: PinUvAuthProvider,
    K: PrivateKeyStore,
    E: EntropySource,
>(
    data: &[u8],
    storage: &mut Storage<B>,
    presence: &mut P,
    verification: &mut V,
    pin_uv_auth: &mut A,
    key_store: &mut K,
    entropy: &mut E,
    assertion_state: &mut AssertionState,
    credential_management_state: &mut CredentialManagementState,
    buf: &'a mut [u8],
) -> &'a [u8] {
    handle_with_transports(
        data,
        storage,
        presence,
        verification,
        pin_uv_auth,
        key_store,
        entropy,
        assertion_state,
        credential_management_state,
        buf,
        capabilities::CURRENT.transports,
    )
}

/// Dispatches with caller-supplied advertised transports, not transport authentication.
/// Requires configured response capacity and session-local enumeration state.
pub fn handle_with_transports<
    'a,
    B: StorageBackend,
    P: UserPresence,
    V: UserVerification,
    A: PinUvAuthProvider,
    K: PrivateKeyStore,
    E: EntropySource,
>(
    data: &[u8],
    storage: &mut Storage<B>,
    presence: &mut P,
    verification: &mut V,
    pin_uv_auth: &mut A,
    key_store: &mut K,
    entropy: &mut E,
    assertion_state: &mut AssertionState,
    credential_management_state: &mut CredentialManagementState,
    buf: &'a mut [u8],
    transports: &[&[u8]],
) -> &'a [u8] {
    if data.is_empty() {
        buf[0] = status::INVALID_COMMAND;
        return &buf[..1];
    }

    match data[0] {
        cmd::AUTHENTICATOR_GET_INFO => {
            assertion_state.clear();
            credential_management_state.clear();
            if data.len() != 1 {
                buf[0] = status::INVALID_LENGTH;
                &buf[..1]
            } else {
                get_info_with_transports_and_algorithms(
                    pin_uv_auth,
                    buf,
                    transports,
                    key_store.supports_algorithm(
                        crate::ctaphid::credential::CredentialAlgorithm::MlDsa44,
                    ),
                )
            }
        }
        cmd::AUTHENTICATOR_MAKE_CREDENTIAL => {
            assertion_state.clear();
            credential_management_state.clear();
            make_credential(
                &data[1..],
                storage,
                presence,
                verification,
                pin_uv_auth,
                key_store,
                entropy,
                buf,
            )
        }
        cmd::AUTHENTICATOR_GET_ASSERTION => {
            credential_management_state.clear();
            get_assertion(
                &data[1..],
                storage,
                presence,
                verification,
                pin_uv_auth,
                key_store,
                entropy,
                assertion_state,
                buf,
            )
        }
        cmd::AUTHENTICATOR_GET_NEXT_ASSERTION => {
            credential_management_state.clear();
            if data.len() != 1 {
                buf[0] = status::INVALID_LENGTH;
                &buf[..1]
            } else {
                get_next_assertion(
                    storage,
                    pin_uv_auth,
                    key_store,
                    entropy,
                    assertion_state,
                    buf,
                )
            }
        }
        cmd::AUTHENTICATOR_CLIENT_PIN => {
            assertion_state.clear();
            credential_management_state.clear();
            #[cfg(feature = "ctap2-no-client-pin")]
            {
                buf[0] = status::INVALID_COMMAND;
                &buf[..1]
            }
            #[cfg(not(feature = "ctap2-no-client-pin"))]
            client_pin(&data[1..], pin_uv_auth, entropy, buf)
        }
        cmd::AUTHENTICATOR_CREDENTIAL_MANAGEMENT => {
            assertion_state.clear();
            credential_management(
                &data[1..],
                storage,
                pin_uv_auth,
                key_store,
                credential_management_state,
                buf,
            )
        }
        cmd::AUTHENTICATOR_RESET => {
            assertion_state.clear();
            credential_management_state.clear();
            reset::reset_with_keys(&data[1..], storage, presence, pin_uv_auth, key_store, buf)
        }
        _ => {
            assertion_state.clear();
            credential_management_state.clear();
            buf[0] = status::INVALID_COMMAND;
            &buf[..1]
        }
    }
}
