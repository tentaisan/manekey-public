use manekey::{
    ctaphid::trusted::TrustedBackend,
    frontend::{ble::BleFidoIngressFrontend, ingress::IngressId},
    transport::ble::{BleFidoError, BleFidoFragmentSink, BleFidoProfileHandler},
};

pub use crate::ingress::SharedArbiter;

/// Cooperative BLE protocol ingress; port owns GATT delivery and disconnect settle polling.
pub struct SharedBleIngressFrontend<T: TrustedBackend + 'static> {
    frontend: BleFidoIngressFrontend,
    arbiter: &'static SharedArbiter<T>,
}

impl<T: TrustedBackend + 'static> SharedBleIngressFrontend<T> {
    pub const fn new(
        max_fragment_len: usize,
        ingress: IngressId,
        arbiter: &'static SharedArbiter<T>,
    ) -> Self {
        Self {
            frontend: BleFidoIngressFrontend::new(max_fragment_len, ingress),
            arbiter,
        }
    }
}

impl<T: TrustedBackend + 'static> BleFidoProfileHandler for SharedBleIngressFrontend<T> {
    fn handle_control_point_write<const MAX_FRAGMENT: usize>(
        &mut self,
        fragment: &[u8],
        sink: &mut impl BleFidoFragmentSink,
    ) -> Result<usize, BleFidoError> {
        self.arbiter.lock(|cell| {
            let mut arbiter = cell.borrow_mut();
            self.frontend
                .bind(&mut arbiter)
                .handle_control_point_write::<MAX_FRAGMENT>(fragment, sink)
        })
    }

    fn poll_status<const MAX_FRAGMENT: usize>(
        &mut self,
        sink: &mut impl BleFidoFragmentSink,
    ) -> Result<usize, BleFidoError> {
        self.arbiter.lock(|cell| {
            let mut arbiter = cell.borrow_mut();
            self.frontend
                .bind(&mut arbiter)
                .poll_status::<MAX_FRAGMENT>(sink)
        })
    }

    fn on_disconnect(&mut self) {
        self.arbiter.lock(|cell| {
            let mut arbiter = cell.borrow_mut();
            self.frontend.bind(&mut arbiter).on_disconnect();
        });
    }

    fn settle_disconnected_backend(&mut self) -> bool {
        self.arbiter.lock(|cell| {
            let mut arbiter = cell.borrow_mut();
            self.frontend
                .bind(&mut arbiter)
                .settle_disconnected_backend()
        })
    }
}
