use embassy_time::Timer;
use manekey::{
    boundary::{
        copied_mailbox::CopiedBackendWorker,
        mailbox::{LocalMailboxTransport, MailboxEndpoint},
        mailbox_backend::MailboxTrustedBackend,
    },
    ctaphid::trusted::{TRUSTED_REQUEST_MAX, TRUSTED_RESPONSE_MAX, TrustedBackend},
};

pub type Nrf54MailboxEndpoint = MailboxEndpoint<TRUSTED_REQUEST_MAX, TRUSTED_RESPONSE_MAX>;

pub static NRF54_MAILBOX: Nrf54MailboxEndpoint = Nrf54MailboxEndpoint::new();

/// Cooperative same-image mailbox, not TrustZone isolation; reserve one frontend and worker owner.
pub type Nrf54LocalMailboxBackend = MailboxTrustedBackend<
    LocalMailboxTransport<'static, TRUSTED_REQUEST_MAX, TRUSTED_RESPONSE_MAX>,
>;

pub fn local_mailbox_backend() -> Nrf54LocalMailboxBackend {
    MailboxTrustedBackend::new(LocalMailboxTransport::new(&NRF54_MAILBOX))
}

pub type Nrf54LocalTrustedWorker<D> = CopiedBackendWorker<D>;

/// Run once in thread mode; never invoke the worker from IRQ/MPSL/SDC callbacks.
pub async fn run_local_trusted_worker<D: TrustedBackend>(
    worker: &mut Nrf54LocalTrustedWorker<D>,
) -> ! {
    loop {
        match worker.pump_once(&NRF54_MAILBOX) {
            Ok(true) => {}
            Ok(false) | Err(_) => Timer::after_millis(1).await,
        }
    }
}
