use super::mailbox::MailboxClientTransport;
use crate::ctaphid::trusted::{TRUSTED_RESPONSE_MAX, TrustedBackend, TrustedResult};
use trusted_boundary::status;

/// Deferred backend adapter, not hardware isolation or automatic secret erasure.
/// Cancellation acceptance requires polling until settled; transport errors require reconciliation.
pub struct MailboxTrustedBackend<T: MailboxClientTransport> {
    transport: T,
    state: MailboxState,
    response: [u8; TRUSTED_RESPONSE_MAX],
    response_len: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum MailboxState {
    Idle,

    AwaitingResponse,

    PollReady,

    CancelWhenIdle,

    AwaitingCancel,
}

impl<T: MailboxClientTransport> MailboxTrustedBackend<T> {
    pub const fn new(transport: T) -> Self {
        Self {
            transport,
            state: MailboxState::Idle,
            response: [0; TRUSTED_RESPONSE_MAX],
            response_len: 0,
        }
    }

    pub fn into_transport(self) -> T {
        self.transport
    }

    fn submit<'a>(&'a mut self, operation_code: u32, request: &[u8]) -> TrustedResult<'a> {
        if self
            .transport
            .submit_operation(operation_code, request)
            .is_err()
        {
            self.reset();
            return TrustedResult::InvalidRequest;
        }
        self.state = MailboxState::AwaitingResponse;
        self.drive()
    }

    fn drive<'a>(&'a mut self) -> TrustedResult<'a> {
        let received = match self.transport.try_receive_response(&mut self.response) {
            Ok(received) => received,
            Err(_) => {
                self.reset();
                return TrustedResult::InvalidRequest;
            }
        };
        let Some((status_code, len)) = received else {
            return TrustedResult::UserPresencePending;
        };

        if self.state == MailboxState::CancelWhenIdle {
            return self.submit_cancel();
        }
        if self.state == MailboxState::AwaitingCancel {
            self.reset();
            return TrustedResult::InvalidRequest;
        }

        match (status_code, len) {
            (status::OK, len) if len <= self.response.len() => {
                self.state = MailboxState::Idle;
                self.response_len = len;
                TrustedResult::Response(&self.response[..self.response_len])
            }
            (status::USER_PRESENCE_PENDING, 0) => {
                self.state = MailboxState::PollReady;
                self.response_len = 0;
                TrustedResult::UserPresencePending
            }
            (status::BUSY, 0) => {
                self.reset();
                TrustedResult::Busy
            }
            (status::INVALID_REQUEST, 0)
            | (status::INVALID_DESCRIPTOR, 0)
            | (status::INVALID_RESPONSE, 0)
            | (status::OUTPUT_TOO_SMALL, 0)
            | (status::INVALID_OPERATION, 0) => {
                self.reset();
                self.response_len = 0;
                TrustedResult::InvalidRequest
            }
            _ => {
                self.reset();
                self.response_len = 0;
                TrustedResult::InvalidRequest
            }
        }
    }

    fn submit_cancel<'a>(&'a mut self) -> TrustedResult<'a> {
        if self
            .transport
            .submit_operation(trusted_boundary::operation::CANCEL, &[])
            .is_err()
        {
            self.reset();
            return TrustedResult::InvalidRequest;
        }
        self.state = MailboxState::AwaitingCancel;
        TrustedResult::UserPresencePending
    }

    fn reset(&mut self) {
        self.state = MailboxState::Idle;
        self.response_len = 0;
    }
}

impl<T: MailboxClientTransport> TrustedBackend for MailboxTrustedBackend<T> {
    fn submit_cbor<'a>(&'a mut self, request: &[u8]) -> TrustedResult<'a> {
        if self.is_busy() {
            return TrustedResult::Busy;
        }
        self.submit(trusted_boundary::operation::SUBMIT_CBOR, request)
    }

    fn submit_u2f<'a>(&'a mut self, request: &[u8]) -> TrustedResult<'a> {
        if self.is_busy() {
            return TrustedResult::Busy;
        }
        self.submit(trusted_boundary::operation::SUBMIT_U2F, request)
    }

    fn poll<'a>(&'a mut self) -> Option<TrustedResult<'a>> {
        Some(match self.state {
            MailboxState::Idle => return None,
            MailboxState::AwaitingResponse | MailboxState::CancelWhenIdle => self.drive(),
            MailboxState::AwaitingCancel => {
                let _ = self.drive();
                return None;
            }
            MailboxState::PollReady => self.submit(trusted_boundary::operation::POLL, &[]),
        })
    }

    fn cancel(&mut self) -> bool {
        if !self.is_busy() {
            return false;
        }
        match self.state {
            MailboxState::PollReady => {
                let _ = self.submit_cancel();
            }
            MailboxState::AwaitingResponse => self.state = MailboxState::CancelWhenIdle,
            MailboxState::CancelWhenIdle | MailboxState::AwaitingCancel | MailboxState::Idle => {}
        }
        true
    }

    fn is_busy(&self) -> bool {
        self.state != MailboxState::Idle
    }
}
