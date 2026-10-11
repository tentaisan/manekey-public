use manekey::boundary::{
    mailbox::{MailboxClientTransport, MailboxEndpoint, MailboxError, MailboxState},
    mailbox_backend::MailboxTrustedBackend,
};
use manekey::ctaphid::{
    CtaphidFrontend,
    trusted::{TRUSTED_REQUEST_MAX, TRUSTED_RESPONSE_MAX},
};

pub type EspTrustedTransport =
    EspPollingMailboxTransport<'static, TRUSTED_REQUEST_MAX, TRUSTED_RESPONSE_MAX>;

pub type EspCtaphid = CtaphidFrontend<MailboxTrustedBackend<EspTrustedTransport>>;

pub fn build_ctaphid_frontend(
    endpoint: &'static MailboxEndpoint<TRUSTED_REQUEST_MAX, TRUSTED_RESPONSE_MAX>,
) -> EspCtaphid {
    let transport = EspPollingMailboxTransport::new(endpoint);
    CtaphidFrontend::with_trusted_backend(MailboxTrustedBackend::new(transport))
}

/// Copied software exchange, not hardware isolation; caller preserves phase ownership and polls cancellation to completion.
pub struct EspPollingMailboxTransport<'a, const REQUEST: usize, const RESPONSE: usize> {
    endpoint: &'a MailboxEndpoint<REQUEST, RESPONSE>,
}

impl<'a, const REQUEST: usize, const RESPONSE: usize>
    EspPollingMailboxTransport<'a, REQUEST, RESPONSE>
{
    pub const fn new(endpoint: &'a MailboxEndpoint<REQUEST, RESPONSE>) -> Self {
        Self { endpoint }
    }
}

impl<const REQUEST: usize, const RESPONSE: usize> MailboxClientTransport
    for EspPollingMailboxTransport<'_, REQUEST, RESPONSE>
{
    fn submit_operation(
        &mut self,
        operation_code: u32,
        request: &[u8],
    ) -> Result<(), MailboxError> {
        self.endpoint.submit_operation(operation_code, request)
    }

    fn try_receive_response(
        &mut self,
        response: &mut [u8],
    ) -> Result<Option<(u32, usize)>, MailboxError> {
        if self.endpoint.state()? == MailboxState::ResponseReady {
            self.endpoint.take_status_response(response).map(Some)
        } else {
            Ok(None)
        }
    }
}
