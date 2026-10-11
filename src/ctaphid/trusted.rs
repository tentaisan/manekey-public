use super::channel::{MAX_MESSAGE_SIZE, MAX_REQUEST_SIZE};
use super::ctap2::{self, AssertionState, CredentialManagementState};
use super::entropy::EntropySource;
use super::key_store::PrivateKeyStore;
use super::pin_uv_auth::PinUvAuthProvider;
use super::storage::{self, StorageBackend};
use super::u2f;
use super::user_verification::UserVerification;
use crate::presence::{
    NoPresenceObserver, PresenceEvent, PresenceObserver, PresenceReason, PresenceStatus,
    PresenceUiHint, UserPresence,
};
use crate::transport;
use trusted_boundary::{operation, status};

pub const TRUSTED_REQUEST_MAX: usize = MAX_REQUEST_SIZE;

pub const TRUSTED_RESPONSE_MAX: usize = MAX_MESSAGE_SIZE;

pub enum TrustedResult<'a> {
    Response(&'a [u8]),

    UserPresencePending,

    Busy,

    InvalidRequest,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum PendingOperation {
    Cbor,
    U2fRegister,
    U2fAuthenticate,
}

/// Serialized command backend; adapters own hardware isolation and completion/cancellation semantics.
pub trait TrustedBackend {
    fn submit_cbor<'a>(&'a mut self, request: &[u8]) -> TrustedResult<'a>;
    fn submit_u2f<'a>(&'a mut self, request: &[u8]) -> TrustedResult<'a>;
    fn poll<'a>(&'a mut self) -> Option<TrustedResult<'a>>;
    fn cancel(&mut self) -> bool;
    fn is_busy(&self) -> bool;
}

/// Owns command state, not a hardware boundary; caller supplies protected storage/crypto and trusted UP/UV.
/// Request-copy omission requires an already private, immutable execution buffer.
/// Reset/cancel and buffer fills do not establish all-path secret erasure.
pub struct TrustedDispatcher<
    B: StorageBackend,
    P: UserPresence,
    V: UserVerification,
    A: PinUvAuthProvider,
    K: PrivateKeyStore,
    E: EntropySource,
    O: PresenceObserver = NoPresenceObserver,
> {
    storage: storage::Storage<B>,
    presence: P,
    presence_observer: O,
    pending_presence_reason: PresenceReason,
    pending_operation: PendingOperation,
    verification: V,
    pin_uv_auth: A,
    key_store: K,
    entropy: E,
    assertion_state: AssertionState,
    credential_management_state: CredentialManagementState,
    transports: &'static [&'static [u8]],
    request: [u8; TRUSTED_REQUEST_MAX],
    request_len: usize,
    pending: bool,
    response: [u8; TRUSTED_RESPONSE_MAX],
}

impl<
    B: StorageBackend,
    P: UserPresence,
    V: UserVerification,
    A: PinUvAuthProvider,
    K: PrivateKeyStore,
    E: EntropySource,
> TrustedDispatcher<B, P, V, A, K, E, NoPresenceObserver>
{
    pub const fn new(
        storage: storage::Storage<B>,
        presence: P,
        verification: V,
        pin_uv_auth: A,
        key_store: K,
        entropy: E,
    ) -> Self {
        Self::new_with_transports(
            storage,
            presence,
            verification,
            pin_uv_auth,
            key_store,
            entropy,
            transport::USB_TRANSPORTS,
        )
    }

    /// Initializes destination without dropping an existing value; caller disposes of old resources first.
    pub fn initialize_in_place(
        destination: &mut core::mem::MaybeUninit<Self>,
        storage: storage::Storage<B>,
        presence: P,
        verification: V,
        pin_uv_auth: A,
        key_store: K,
        entropy: E,
    ) -> &mut Self {
        let pointer = destination.as_mut_ptr();

        unsafe {
            core::ptr::addr_of_mut!((*pointer).storage).write(storage);
            core::ptr::addr_of_mut!((*pointer).presence).write(presence);
            core::ptr::addr_of_mut!((*pointer).presence_observer).write(NoPresenceObserver);
            core::ptr::addr_of_mut!((*pointer).pending_presence_reason)
                .write(PresenceReason::Other);
            core::ptr::addr_of_mut!((*pointer).pending_operation).write(PendingOperation::Cbor);
            core::ptr::addr_of_mut!((*pointer).verification).write(verification);
            core::ptr::addr_of_mut!((*pointer).pin_uv_auth).write(pin_uv_auth);
            core::ptr::addr_of_mut!((*pointer).key_store).write(key_store);
            core::ptr::addr_of_mut!((*pointer).entropy).write(entropy);
            core::ptr::addr_of_mut!((*pointer).assertion_state).write(AssertionState::new());
            core::ptr::addr_of_mut!((*pointer).credential_management_state)
                .write(CredentialManagementState::new());
            core::ptr::addr_of_mut!((*pointer).transports).write(transport::USB_TRANSPORTS);
            core::ptr::addr_of_mut!((*pointer).request).write_bytes(0, 1);
            core::ptr::addr_of_mut!((*pointer).request_len).write(0);
            core::ptr::addr_of_mut!((*pointer).pending).write(false);
            core::ptr::addr_of_mut!((*pointer).response).write_bytes(0, 1);
        }

        let initialized = unsafe { destination.assume_init_mut() };
        let Self {
            storage: _,
            presence: _,
            presence_observer: _,
            pending_presence_reason: _,
            pending_operation: _,
            verification: _,
            pin_uv_auth: _,
            key_store: _,
            entropy: _,
            assertion_state: _,
            credential_management_state: _,
            transports: _,
            request: _,
            request_len: _,
            pending: _,
            response: _,
        } = initialized;
        initialized
    }

    pub const fn new_with_transports(
        storage: storage::Storage<B>,
        presence: P,
        verification: V,
        pin_uv_auth: A,
        key_store: K,
        entropy: E,
        transports: &'static [&'static [u8]],
    ) -> Self {
        Self::new_with_transports_and_presence_observer(
            storage,
            presence,
            verification,
            pin_uv_auth,
            key_store,
            entropy,
            transports,
            NoPresenceObserver,
        )
    }
}

impl<
    B: StorageBackend,
    P: UserPresence,
    V: UserVerification,
    A: PinUvAuthProvider,
    K: PrivateKeyStore,
    E: EntropySource,
    O: PresenceObserver,
> TrustedDispatcher<B, P, V, A, K, E, O>
{
    pub const fn new_with_transports_and_presence_observer(
        storage: storage::Storage<B>,
        presence: P,
        verification: V,
        pin_uv_auth: A,
        key_store: K,
        entropy: E,
        transports: &'static [&'static [u8]],
        presence_observer: O,
    ) -> Self {
        Self {
            storage,
            presence,
            presence_observer,
            pending_presence_reason: PresenceReason::Other,
            pending_operation: PendingOperation::Cbor,
            verification,
            pin_uv_auth,
            key_store,
            entropy,
            assertion_state: AssertionState::new(),
            credential_management_state: CredentialManagementState::new(),
            transports,
            request: [0; TRUSTED_REQUEST_MAX],
            request_len: 0,
            pending: false,
            response: [0; TRUSTED_RESPONSE_MAX],
        }
    }

    /// Copies a bounded command; poll pending operations and do not replay failed mutations blindly.
    pub fn submit_cbor<'a>(&'a mut self, request: &[u8]) -> TrustedResult<'a> {
        if self.pending {
            return TrustedResult::Busy;
        }
        if request.is_empty() || request.len() > TRUSTED_REQUEST_MAX {
            return TrustedResult::InvalidRequest;
        }

        self.request[..request.len()].copy_from_slice(request);
        self.request_len = request.len();

        if let Some(reason) = ctap2::user_presence_reason(&self.request[..self.request_len]) {
            self.begin_pending(reason, PendingOperation::Cbor);
            return TrustedResult::UserPresencePending;
        }

        self.execute_copied_request()
    }

    /// Copies a bounded APDU; registration uses public development attestation.
    pub fn submit_u2f<'a>(&'a mut self, request: &[u8]) -> TrustedResult<'a> {
        if self.pending {
            return TrustedResult::Busy;
        }
        if request.is_empty() || request.len() > TRUSTED_REQUEST_MAX {
            return TrustedResult::InvalidRequest;
        }

        self.request[..request.len()].copy_from_slice(request);
        self.request_len = request.len();
        if u2f::register_needs_user_presence(&self.request[..self.request_len]) {
            self.begin_pending(
                PresenceReason::MakeCredential,
                PendingOperation::U2fRegister,
            );
            return TrustedResult::UserPresencePending;
        }
        if u2f::authenticate_needs_user_presence(
            &self.request[..self.request_len],
            &mut self.storage,
        ) {
            self.begin_pending(
                PresenceReason::GetAssertion,
                PendingOperation::U2fAuthenticate,
            );
            return TrustedResult::UserPresencePending;
        }
        self.execute_copied_u2f_request()
    }

    pub fn poll<'a>(&'a mut self) -> Option<TrustedResult<'a>> {
        if !self.pending {
            return None;
        }

        match self.presence.poll() {
            PresenceStatus::Pending => Some(TrustedResult::UserPresencePending),
            PresenceStatus::TimedOut => {
                let reason = self.pending_presence_reason;
                let operation = self.pending_operation;
                self.presence_observer
                    .on_presence_event(PresenceEvent::TimedOut {
                        reason,
                        ui_hint: PresenceUiHint::Attention,
                    });
                self.finish_pending();
                let response_len = match operation {
                    PendingOperation::Cbor => {
                        self.response[0] = ctap2::OPERATION_DENIED_STATUS;
                        1
                    }
                    PendingOperation::U2fAuthenticate => {
                        u2f::operation_denied_response(&mut self.response)
                    }
                    PendingOperation::U2fRegister => {
                        u2f::operation_denied_response(&mut self.response)
                    }
                };
                Some(TrustedResult::Response(&self.response[..response_len]))
            }
            PresenceStatus::Confirmed => {
                let reason = self.pending_presence_reason;
                self.presence_observer
                    .on_presence_event(PresenceEvent::Confirmed {
                        reason,
                        ui_hint: PresenceUiHint::TouchConfirmed,
                    });
                self.pending = false;

                Some(match self.pending_operation {
                    PendingOperation::Cbor => self.execute_copied_request(),
                    PendingOperation::U2fRegister => self.execute_copied_u2f_request(),
                    PendingOperation::U2fAuthenticate => self.execute_copied_u2f_request(),
                })
            }
        }
    }

    pub fn cancel(&mut self) -> bool {
        if !self.pending {
            return false;
        }
        let reason = self.pending_presence_reason;
        self.presence_observer
            .on_presence_event(PresenceEvent::Cancelled {
                reason,
                ui_hint: PresenceUiHint::Attention,
            });
        self.finish_pending();
        true
    }

    pub fn is_busy(&self) -> bool {
        self.pending
    }

    #[cfg(not(feature = "trusted-no-private-request-copy"))]
    fn execute_copied_request<'a>(&'a mut self) -> TrustedResult<'a> {
        let mut request = [0u8; TRUSTED_REQUEST_MAX];
        let request_len = self.request_len;
        request[..request_len].copy_from_slice(&self.request[..request_len]);
        self.clear_request();

        let data = ctap2::handle_with_transports(
            &request[..request_len],
            &mut self.storage,
            &mut self.presence,
            &mut self.verification,
            &mut self.pin_uv_auth,
            &mut self.key_store,
            &mut self.entropy,
            &mut self.assertion_state,
            &mut self.credential_management_state,
            &mut self.response,
            self.transports,
        );
        request[..request_len].fill(0);
        TrustedResult::Response(data)
    }

    #[cfg(not(feature = "trusted-no-private-request-copy"))]
    fn execute_copied_u2f_request<'a>(&'a mut self) -> TrustedResult<'a> {
        let mut request = [0u8; TRUSTED_REQUEST_MAX];
        let request_len = self.request_len;
        request[..request_len].copy_from_slice(&self.request[..request_len]);
        self.clear_request();

        let response_len = u2f::handle_with_trusted_state(
            &request[..request_len],
            &mut self.storage,
            &mut self.key_store,
            &mut self.entropy,
            &mut self.response,
        );
        request[..request_len].fill(0);
        TrustedResult::Response(&self.response[..response_len])
    }

    #[cfg(feature = "trusted-no-private-request-copy")]
    fn execute_copied_request<'a>(&'a mut self) -> TrustedResult<'a> {
        let request_len = self.request_len;
        let response_len = {
            let data = ctap2::handle_with_transports(
                &self.request[..request_len],
                &mut self.storage,
                &mut self.presence,
                &mut self.verification,
                &mut self.pin_uv_auth,
                &mut self.key_store,
                &mut self.entropy,
                &mut self.assertion_state,
                &mut self.credential_management_state,
                &mut self.response,
                self.transports,
            );
            data.len()
        };
        self.clear_request();
        TrustedResult::Response(&self.response[..response_len])
    }

    #[cfg(feature = "trusted-no-private-request-copy")]
    fn execute_copied_u2f_request<'a>(&'a mut self) -> TrustedResult<'a> {
        let request_len = self.request_len;
        let response_len = u2f::handle_with_trusted_state(
            &self.request[..request_len],
            &mut self.storage,
            &mut self.key_store,
            &mut self.entropy,
            &mut self.response,
        );
        self.clear_request();
        TrustedResult::Response(&self.response[..response_len])
    }

    fn finish_pending(&mut self) {
        self.pending = false;
        self.pending_presence_reason = PresenceReason::Other;
        self.pending_operation = PendingOperation::Cbor;
        self.presence.cancel();
        self.clear_request();
    }

    fn clear_request(&mut self) {
        self.request[..self.request_len].fill(0);
        self.request_len = 0;
    }

    fn begin_pending(&mut self, reason: PresenceReason, operation: PendingOperation) {
        self.pending = true;
        self.pending_presence_reason = reason;
        self.pending_operation = operation;
        self.presence.begin_wait();
        self.presence_observer
            .on_presence_event(PresenceEvent::WaitStarted {
                reason,
                ui_hint: PresenceUiHint::TouchRequired,
            });
    }
}

impl<
    B: StorageBackend,
    P: UserPresence,
    V: UserVerification,
    A: PinUvAuthProvider,
    K: PrivateKeyStore,
    E: EntropySource,
    O: PresenceObserver,
> TrustedBackend for TrustedDispatcher<B, P, V, A, K, E, O>
{
    fn submit_cbor<'a>(&'a mut self, request: &[u8]) -> TrustedResult<'a> {
        TrustedDispatcher::submit_cbor(self, request)
    }

    fn submit_u2f<'a>(&'a mut self, request: &[u8]) -> TrustedResult<'a> {
        TrustedDispatcher::submit_u2f(self, request)
    }

    fn poll<'a>(&'a mut self) -> Option<TrustedResult<'a>> {
        TrustedDispatcher::poll(self)
    }

    fn cancel(&mut self) -> bool {
        TrustedDispatcher::cancel(self)
    }

    fn is_busy(&self) -> bool {
        TrustedDispatcher::is_busy(self)
    }
}

impl<
    B: StorageBackend,
    P: UserPresence,
    V: UserVerification,
    A: PinUvAuthProvider,
    K: PrivateKeyStore,
    E: EntropySource,
    O: PresenceObserver,
> crate::boundary::mailbox::MailboxService for TrustedDispatcher<B, P, V, A, K, E, O>
{
    fn process(
        &mut self,
        request: &[u8],
        response: &mut [u8],
    ) -> Result<usize, crate::boundary::mailbox::MailboxError> {
        match self.submit_cbor(request) {
            TrustedResult::Response(payload) if payload.len() <= response.len() => {
                response[..payload.len()].copy_from_slice(payload);
                Ok(payload.len())
            }

            TrustedResult::Response(_) | TrustedResult::UserPresencePending => {
                Err(crate::boundary::mailbox::MailboxError::InvalidState)
            }
            TrustedResult::Busy | TrustedResult::InvalidRequest => {
                Err(crate::boundary::mailbox::MailboxError::InvalidTransition)
            }
        }
    }
}

impl<T: TrustedBackend> crate::boundary::mailbox::MailboxOperationService for T {
    fn process_operation(
        &mut self,
        operation_code: u32,
        request: &[u8],
        response: &mut [u8],
    ) -> Result<(u32, usize), crate::boundary::mailbox::MailboxError> {
        let result = match operation_code {
            operation::SUBMIT_CBOR => self.submit_cbor(request),
            operation::SUBMIT_U2F => self.submit_u2f(request),
            operation::POLL => self.poll().unwrap_or(TrustedResult::Busy),
            operation::CANCEL => {
                self.cancel();
                return Ok((status::OK, 0));
            }
            _ => return Ok((status::INVALID_OPERATION, 0)),
        };

        Ok(match result {
            TrustedResult::Response(payload) if payload.len() <= response.len() => {
                response[..payload.len()].copy_from_slice(payload);
                (status::OK, payload.len())
            }
            TrustedResult::Response(_) => (status::OUTPUT_TOO_SMALL, 0),
            TrustedResult::UserPresencePending => (status::USER_PRESENCE_PENDING, 0),
            TrustedResult::Busy => (status::BUSY, 0),
            TrustedResult::InvalidRequest => (status::INVALID_REQUEST, 0),
        })
    }
}
