pub mod attestation;
pub mod auth_data;
pub mod cbor;
pub mod channel;
pub mod credential;
pub mod credential_signature;
pub mod crypto;
pub mod ctap2;
pub mod descriptor;
pub mod entropy;

pub mod flash_key_storage;
pub mod framing;
pub mod handler;
pub mod hash;
pub mod hid_app;
pub mod key_handle;
pub mod key_store;
#[cfg(feature = "key-wrap")]
pub mod key_wrap;
pub mod managed_key_store;
pub mod parser;
pub mod pin_uv_auth;
#[cfg(feature = "experimental-ml-dsa-algorithm")]
pub mod pqc_signature;
#[cfg(feature = "experimental-ml-dsa-fips204")]
pub mod pqc_signature_fips204;

#[cfg(feature = "experimental-ml-dsa-fips204-scratch")]
pub mod pqc_signature_fips204_scratch;
#[cfg(feature = "experimental-ml-dsa-mldsa-native")]
pub mod pqc_signature_mldsa_native;
pub mod storage;
pub mod trusted;
pub mod u2f;
mod u2f_attestation;
pub mod user_verification;
#[cfg(feature = "key-wrap")]
pub mod wrapped_key_pages;

pub use handler::Response;
pub use hid_app::HidCtaphidApp;

use crate::presence::{NoPresenceObserver, PresenceObserver, UserPresence};
use channel::Channel;
use descriptor::REPORT_SIZE;
use entropy::EntropySource;
use handler::{
    CANCEL_COMMAND, cbor_status_response, handle_transport, keepalive_up_needed_response,
};
use key_store::PrivateKeyStore;
use parser::Packet;
use pin_uv_auth::PinUvAuthProvider;
use storage::StorageBackend;
use trusted::{TrustedBackend, TrustedDispatcher, TrustedResult};
use user_verification::UserVerification;

use crate::ctaphid::handler::channel_error;
const CBOR_RESPONSE_COMMAND: u8 = 0x90;
const U2F_RESPONSE_COMMAND: u8 = 0x83;

/// Connection-local protocol state; serialize backend ownership and continue polling deferred cancellation.
pub struct CtaphidProtocol {
    channel: Channel,
    pending_cid: Option<u32>,
    pending_response_command: Option<u8>,
    cancel_cid: Option<u32>,
    cancel_response_command: Option<u8>,
    resp_buf: [u8; channel::MAX_MESSAGE_SIZE],
}

/// Protocol/backend composition, not hardware isolation or transport-delivery acknowledgment.
pub struct CtaphidFrontend<T: TrustedBackend> {
    protocol: CtaphidProtocol,
    trusted: T,
}

pub type Ctaphid<B, P, V, A, K, E, O = NoPresenceObserver> =
    CtaphidFrontend<TrustedDispatcher<B, P, V, A, K, E, O>>;

impl<
    B: StorageBackend,
    P: UserPresence,
    V: UserVerification,
    A: PinUvAuthProvider,
    K: PrivateKeyStore,
    E: EntropySource,
> CtaphidFrontend<TrustedDispatcher<B, P, V, A, K, E>>
{
    pub const fn new(
        storage: storage::Storage<B>,
        presence: P,
        verification: V,
        pin_uv_auth: A,
        key_store: K,
        entropy: E,
    ) -> Self {
        Self::with_trusted_backend(TrustedDispatcher::new(
            storage,
            presence,
            verification,
            pin_uv_auth,
            key_store,
            entropy,
        ))
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
> CtaphidFrontend<TrustedDispatcher<B, P, V, A, K, E, O>>
{
    pub const fn new_with_presence_observer(
        storage: storage::Storage<B>,
        presence: P,
        verification: V,
        pin_uv_auth: A,
        key_store: K,
        entropy: E,
        presence_observer: O,
    ) -> Self {
        Self::with_trusted_backend(
            TrustedDispatcher::new_with_transports_and_presence_observer(
                storage,
                presence,
                verification,
                pin_uv_auth,
                key_store,
                entropy,
                crate::transport::USB_TRANSPORTS,
                presence_observer,
            ),
        )
    }
}

impl CtaphidProtocol {
    pub const fn new() -> Self {
        Self {
            channel: Channel::new(),
            pending_cid: None,
            pending_response_command: None,
            cancel_cid: None,
            cancel_response_command: None,
            resp_buf: [0; channel::MAX_MESSAGE_SIZE],
        }
    }

    fn handle_packet<'a, T: TrustedBackend>(
        &'a mut self,
        packet: Packet,
        trusted: &'a mut T,
    ) -> Option<Response<'a>> {
        let cid = packet.cid();

        let msg = match self.channel.push(packet) {
            Ok(Some(msg)) => msg,
            Ok(None) => return None,
            Err(err) => return Some(channel_error(cid, err, &mut self.resp_buf)),
        };
        if msg.cmd == CANCEL_COMMAND {
            if !msg.data.is_empty() {
                return Some(channel_error(
                    cid,
                    channel::ChannelError::InvalidLen,
                    &mut self.resp_buf,
                ));
            }

            if self.pending_cid == Some(msg.cid) && trusted.cancel() {
                self.pending_cid = None;
                let response_command = self
                    .pending_response_command
                    .take()
                    .unwrap_or(CBOR_RESPONSE_COMMAND);

                if trusted.is_busy() {
                    self.cancel_cid = Some(msg.cid);
                    self.cancel_response_command = Some(response_command);
                    return None;
                }
                return Some(self.cancelled_response(cid, response_command));
            }

            return None;
        }

        if self.pending_cid.is_some() && trusted.is_busy() {
            return Some(channel_error(
                msg.cid,
                channel::ChannelError::ChannelBusy,
                &mut self.resp_buf,
            ));
        }

        if msg.cmd == 0x10 {
            return match trusted.submit_cbor(msg.data) {
                TrustedResult::Response(data) => Some(Response::Msg {
                    cid: msg.cid,
                    cmd: CBOR_RESPONSE_COMMAND,
                    data,
                }),
                TrustedResult::UserPresencePending => {
                    self.pending_cid = Some(msg.cid);
                    self.pending_response_command = Some(CBOR_RESPONSE_COMMAND);
                    Some(keepalive_up_needed_response(msg.cid, &mut self.resp_buf))
                }
                TrustedResult::Busy => Some(channel_error(
                    msg.cid,
                    channel::ChannelError::ChannelBusy,
                    &mut self.resp_buf,
                )),
                TrustedResult::InvalidRequest => Some(channel_error(
                    msg.cid,
                    channel::ChannelError::InvalidLen,
                    &mut self.resp_buf,
                )),
            };
        }

        if msg.cmd == 0x03 {
            return match trusted.submit_u2f(msg.data) {
                TrustedResult::Response(data) => Some(Response::Msg {
                    cid: msg.cid,
                    cmd: U2F_RESPONSE_COMMAND,
                    data,
                }),
                TrustedResult::UserPresencePending => {
                    self.pending_cid = Some(msg.cid);
                    self.pending_response_command = Some(U2F_RESPONSE_COMMAND);
                    Some(keepalive_up_needed_response(msg.cid, &mut self.resp_buf))
                }
                TrustedResult::Busy => Some(channel_error(
                    msg.cid,
                    channel::ChannelError::ChannelBusy,
                    &mut self.resp_buf,
                )),
                TrustedResult::InvalidRequest => Some(channel_error(
                    msg.cid,
                    channel::ChannelError::InvalidLen,
                    &mut self.resp_buf,
                )),
            };
        }

        Some(handle_transport(msg, &mut self.resp_buf))
    }

    pub fn handle_report_with_backend<'a, T: TrustedBackend>(
        &'a mut self,
        buf: &[u8; REPORT_SIZE],
        trusted: &'a mut T,
    ) -> Option<Response<'a>> {
        let packet = parser::parse_packet(buf);
        self.handle_packet(packet, trusted)
    }

    pub fn handle_raw_with_backend<'a, T: TrustedBackend>(
        &'a mut self,
        buf: [u8; REPORT_SIZE],
        trusted: &'a mut T,
    ) -> Option<Response<'a>> {
        self.handle_report_with_backend(&buf, trusted)
    }

    /// Advances a reassembly timeout tick; caller controls cadence and delivers returned responses.
    pub fn poll_with_backend<'a, T: TrustedBackend>(
        &'a mut self,
        trusted: &'a mut T,
    ) -> Option<Response<'a>> {
        if let Some(cid) = self.channel.poll_timeout() {
            return Some(channel_error(
                cid,
                channel::ChannelError::MessageTimeout,
                &mut self.resp_buf,
            ));
        }

        self.poll_trusted_operation(trusted)
    }

    fn poll_trusted_operation<'a, T: TrustedBackend>(
        &'a mut self,
        trusted: &'a mut T,
    ) -> Option<Response<'a>> {
        if let Some(cid) = self.cancel_cid {
            let _ = trusted.poll();
            if !trusted.is_busy() {
                self.cancel_cid = None;
                let response_command = self
                    .cancel_response_command
                    .take()
                    .unwrap_or(CBOR_RESPONSE_COMMAND);
                return Some(self.cancelled_response(cid, response_command));
            }
            return None;
        }
        let trusted_result = trusted.poll();
        let cid = self.pending_cid?;
        let response_command = self
            .pending_response_command
            .unwrap_or(CBOR_RESPONSE_COMMAND);
        match trusted_result? {
            TrustedResult::Response(data) => {
                self.pending_cid = None;
                self.pending_response_command = None;
                Some(Response::Msg {
                    cid,
                    cmd: response_command,
                    data,
                })
            }
            TrustedResult::UserPresencePending => {
                Some(keepalive_up_needed_response(cid, &mut self.resp_buf))
            }
            TrustedResult::Busy => Some(channel_error(
                cid,
                channel::ChannelError::ChannelBusy,
                &mut self.resp_buf,
            )),
            TrustedResult::InvalidRequest => {
                self.pending_cid = None;
                self.pending_response_command = None;
                if response_command == U2F_RESPONSE_COMMAND {
                    let response_len = u2f::operation_denied_response(&mut self.resp_buf);
                    Some(Response::Msg {
                        cid,
                        cmd: U2F_RESPONSE_COMMAND,
                        data: &self.resp_buf[..response_len],
                    })
                } else {
                    Some(cbor_status_response(
                        cid,
                        ctap2::OPERATION_DENIED_STATUS,
                        &mut self.resp_buf,
                    ))
                }
            }
        }
    }

    fn operation_denied_response<'a>(&'a mut self, cid: u32, response_command: u8) -> Response<'a> {
        if response_command == U2F_RESPONSE_COMMAND {
            let response_len = u2f::operation_denied_response(&mut self.resp_buf);
            Response::Msg {
                cid,
                cmd: U2F_RESPONSE_COMMAND,
                data: &self.resp_buf[..response_len],
            }
        } else {
            cbor_status_response(cid, ctap2::OPERATION_DENIED_STATUS, &mut self.resp_buf)
        }
    }

    fn cancelled_response<'a>(&'a mut self, cid: u32, response_command: u8) -> Response<'a> {
        if response_command == U2F_RESPONSE_COMMAND {
            self.operation_denied_response(cid, response_command)
        } else {
            cbor_status_response(cid, ctap2::KEEPALIVE_CANCEL_STATUS, &mut self.resp_buf)
        }
    }

    /// Settles backend work without advancing the reassembly timeout.
    pub fn poll_trusted_only_with_backend<'a, T: TrustedBackend>(
        &'a mut self,
        trusted: &'a mut T,
    ) -> Option<Response<'a>> {
        self.poll_trusted_operation(trusted)
    }
}

impl<T: TrustedBackend> CtaphidFrontend<T> {
    pub const fn with_trusted_backend(trusted: T) -> Self {
        Self {
            protocol: CtaphidProtocol::new(),
            trusted,
        }
    }

    pub fn handle_report<'a>(&'a mut self, buf: &[u8; REPORT_SIZE]) -> Option<Response<'a>> {
        self.protocol
            .handle_report_with_backend(buf, &mut self.trusted)
    }

    pub fn handle_raw<'a>(&'a mut self, buf: [u8; REPORT_SIZE]) -> Option<Response<'a>> {
        self.protocol
            .handle_raw_with_backend(buf, &mut self.trusted)
    }

    pub fn poll<'a>(&'a mut self) -> Option<Response<'a>> {
        self.protocol.poll_with_backend(&mut self.trusted)
    }

    pub fn poll_trusted_only<'a>(&'a mut self) -> Option<Response<'a>> {
        self.protocol
            .poll_trusted_only_with_backend(&mut self.trusted)
    }
}
