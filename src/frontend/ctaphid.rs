use crate::{
    ctaphid::{
        CtaphidProtocol,
        channel::{CONT_PAYLOAD_SIZE, INIT_PAYLOAD_SIZE, MAX_MESSAGE_SIZE},
        descriptor::REPORT_SIZE,
        framing::ReportQueue,
        trusted::TrustedBackend,
    },
    frontend::ingress::{IngressArbiter, IngressId},
};

pub const MAX_CTAPHID_RESPONSE_REPORTS: usize =
    1 + (MAX_MESSAGE_SIZE - INIT_PAYLOAD_SIZE).div_ceil(CONT_PAYLOAD_SIZE);

/// Connection-local HID protocol and copied egress; callers serialize access and drain reports.
pub struct CtaphidReportFrontend {
    protocol: CtaphidProtocol,
    egress: ReportQueue<MAX_CTAPHID_RESPONSE_REPORTS>,
    settling_link_loss: bool,
}

impl CtaphidReportFrontend {
    pub const fn new() -> Self {
        Self {
            protocol: CtaphidProtocol::new(),
            egress: ReportQueue::new(),
            settling_link_loss: false,
        }
    }

    pub fn handle_report<T: TrustedBackend>(
        &mut self,
        arbiter: &mut IngressArbiter<T>,
        ingress: IngressId,
        report: [u8; REPORT_SIZE],
    ) {
        self.settle_link_loss(arbiter, ingress);
        let mut backend = arbiter.bind(ingress);
        self.egress.queue_response(
            self.protocol
                .handle_report_with_backend(&report, &mut backend),
        );
    }

    pub fn poll<T: TrustedBackend>(&mut self, arbiter: &mut IngressArbiter<T>, ingress: IngressId) {
        if self.current_report().is_some() {
            return;
        }
        if !self.settle_link_loss(arbiter, ingress) {
            return;
        }
        let mut backend = arbiter.bind(ingress);
        self.egress
            .queue_response(self.protocol.poll_with_backend(&mut backend));
    }

    pub fn current_report(&self) -> Option<&[u8; REPORT_SIZE]> {
        self.egress.current()
    }

    pub fn advance_report(&mut self) {
        self.egress.advance();
    }

    /// Discards link state and requests cancellation; continue polling until cancellation settles.
    pub fn on_link_lost<T: TrustedBackend>(
        &mut self,
        arbiter: &mut IngressArbiter<T>,
        ingress: IngressId,
    ) {
        self.protocol = CtaphidProtocol::new();
        self.egress.clear();
        self.settling_link_loss = arbiter.is_owned_by(ingress);
        let _ = arbiter.cancel(ingress);
        self.settle_link_loss(arbiter, ingress);
    }

    fn settle_link_loss<T: TrustedBackend>(
        &mut self,
        arbiter: &mut IngressArbiter<T>,
        ingress: IngressId,
    ) -> bool {
        if self.settling_link_loss {
            if arbiter.is_owned_by(ingress) {
                let _ = arbiter.poll(ingress);
            }
            self.settling_link_loss =
                arbiter.is_owned_by(ingress) && !arbiter.finish_cancel(ingress);
        }
        !self.settling_link_loss
    }
}

impl Default for CtaphidReportFrontend {
    fn default() -> Self {
        Self::new()
    }
}
