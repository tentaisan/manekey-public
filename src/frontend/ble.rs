use crate::{
    ctaphid::trusted::TrustedBackend,
    frontend::ingress::{IngressArbiter, IngressId},
    transport::ble::{BleFidoError, BleFidoFragmentSink, BleFidoProfileHandler, BleFidoProtocol},
};

/// Connection-local BLE framing bound to one ingress owner.
/// Disconnect cancellation may require subsequent settle polling.
pub struct BleFidoIngressFrontend {
    protocol: BleFidoProtocol,
    ingress: IngressId,
    settling_disconnect: bool,
}

impl BleFidoIngressFrontend {
    pub const fn new(max_fragment_len: usize, ingress: IngressId) -> Self {
        Self {
            protocol: BleFidoProtocol::new(max_fragment_len),
            ingress,
            settling_disconnect: false,
        }
    }

    pub const fn ingress_id(&self) -> IngressId {
        self.ingress
    }

    pub fn bind<'a, T: TrustedBackend>(
        &'a mut self,
        arbiter: &'a mut IngressArbiter<T>,
    ) -> BleFidoIngressHandler<'a, T> {
        BleFidoIngressHandler {
            frontend: self,
            arbiter,
        }
    }
}

pub struct BleFidoIngressHandler<'a, T: TrustedBackend> {
    frontend: &'a mut BleFidoIngressFrontend,
    arbiter: &'a mut IngressArbiter<T>,
}

impl<T: TrustedBackend> BleFidoProfileHandler for BleFidoIngressHandler<'_, T> {
    fn handle_control_point_write<const MAX_FRAGMENT: usize>(
        &mut self,
        fragment: &[u8],
        sink: &mut impl BleFidoFragmentSink,
    ) -> Result<usize, BleFidoError> {
        let mut backend = self.arbiter.bind(self.frontend.ingress);
        self.frontend
            .protocol
            .handle_write_with_backend::<MAX_FRAGMENT>(fragment, sink, &mut backend)
    }

    fn poll_status<const MAX_FRAGMENT: usize>(
        &mut self,
        sink: &mut impl BleFidoFragmentSink,
    ) -> Result<usize, BleFidoError> {
        let mut backend = self.arbiter.bind(self.frontend.ingress);
        self.frontend
            .protocol
            .poll_with_backend::<MAX_FRAGMENT>(sink, &mut backend)
    }

    fn on_disconnect(&mut self) {
        let mut backend = self.arbiter.bind(self.frontend.ingress);
        self.frontend.protocol.disconnect_with_backend(&mut backend);
        self.frontend.settling_disconnect = true;
    }

    fn settle_disconnected_backend(&mut self) -> bool {
        if !self.frontend.settling_disconnect {
            return true;
        }
        if !self.arbiter.is_owned_by(self.frontend.ingress) {
            self.frontend.settling_disconnect = false;
            return true;
        }
        let mut backend = self.arbiter.bind(self.frontend.ingress);
        let settled = self
            .frontend
            .protocol
            .settle_disconnected_backend(&mut backend);
        self.frontend.settling_disconnect = !settled;
        settled
    }
}
