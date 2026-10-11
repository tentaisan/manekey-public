use manekey::{
    boundary::{
        mailbox::{
            LocalMailboxTransport, LocalMailboxWorker, MailboxEndpoint, MailboxOperationService,
        },
        mailbox_backend::MailboxTrustedBackend,
    },
    ctaphid::trusted::{TRUSTED_REQUEST_MAX, TRUSTED_RESPONSE_MAX},
    transport::ble::BleFidoFrontend,
};

pub type EspMailboxEndpoint = MailboxEndpoint<TRUSTED_REQUEST_MAX, TRUSTED_RESPONSE_MAX>;

pub type EspMailboxBleFrontend<'a> = BleFidoFrontend<
    MailboxTrustedBackend<LocalMailboxTransport<'a, TRUSTED_REQUEST_MAX, TRUSTED_RESPONSE_MAX>>,
>;

pub fn build_mailbox_ble_frontend(
    endpoint: &EspMailboxEndpoint,
    max_fragment_len: usize,
) -> EspMailboxBleFrontend<'_> {
    BleFidoFrontend::new(
        max_fragment_len,
        MailboxTrustedBackend::new(LocalMailboxTransport::new(endpoint)),
    )
}

/// Cooperative software mailbox worker, not hardware isolation; pump errors require caller recovery.
pub struct EspLocalTrustedWorker<D> {
    worker: LocalMailboxWorker<D, TRUSTED_REQUEST_MAX, TRUSTED_RESPONSE_MAX>,
}

impl<D: MailboxOperationService> EspLocalTrustedWorker<D> {
    pub fn new(dispatcher: D) -> Self {
        Self {
            worker: LocalMailboxWorker::new(dispatcher),
        }
    }

    pub fn pump(&mut self, endpoint: &EspMailboxEndpoint) {
        let _ = self.worker.pump_once(endpoint);
    }
}

pub async fn run_local_trusted_worker<D: MailboxOperationService>(
    worker: &mut EspLocalTrustedWorker<D>,
    endpoint: &EspMailboxEndpoint,
) -> ! {
    loop {
        worker.pump(endpoint);
        embassy_time::Timer::after_millis(2).await;
    }
}
