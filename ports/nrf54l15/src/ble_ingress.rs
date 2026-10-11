use core::cell::RefCell;

use embassy_sync::blocking_mutex::{Mutex, raw::NoopRawMutex};
use manekey::{
    ctaphid::trusted::TrustedBackend,
    frontend::{
        ble::BleFidoIngressFrontend,
        ingress::{IngressArbiter, IngressId, IngressKind},
    },
    transport::ble::{BleFidoError, BleFidoFragmentSink, BleFidoProfileHandler},
};

#[cfg(feature = "ble")]
use crate::{fido::RramDispatcher, presence::UserKeyPresence};

#[cfg(all(feature = "ble", feature = "up-always-present"))]
pub type BleProductPresence = manekey::presence::AlwaysPresent;
#[cfg(all(feature = "ble", not(feature = "up-always-present")))]
pub type BleProductPresence = UserKeyPresence<'static>;
#[cfg(feature = "ble")]
pub type BleProductDispatcher = RramDispatcher<'static, BleProductPresence>;
#[cfg(feature = "nrf54l15-dual-task")]
pub type BleProductBackend = crate::mailbox::Nrf54LocalMailboxBackend;
#[cfg(all(feature = "ble", not(feature = "nrf54l15-dual-task")))]
pub type BleProductBackend = BleProductDispatcher;
#[cfg(feature = "ble")]
pub type BleProductArbiter = SharedIngressArbiter<BleProductBackend>;

/// Single-executor task arbiter; no IRQ/multicore use and no borrow across await.
pub type SharedIngressArbiter<T> = Mutex<NoopRawMutex, RefCell<IngressArbiter<T>>>;

#[cfg(feature = "ble")]
pub type SharedRramIngressArbiter<'d, P = UserKeyPresence<'d>> =
    SharedIngressArbiter<RramDispatcher<'d, P>>;

const BLE_INGRESS: IngressId = IngressId::new(IngressKind::Ble, 0);

/// One BLE ingress owner borrowing the shared arbiter synchronously.
pub struct SharedBleIngressFrontend<'a, T: TrustedBackend> {
    frontend: BleFidoIngressFrontend,
    arbiter: &'a SharedIngressArbiter<T>,
}

impl<'a, T: TrustedBackend> SharedBleIngressFrontend<'a, T> {
    pub const fn new(max_fragment_len: usize, arbiter: &'a SharedIngressArbiter<T>) -> Self {
        Self {
            frontend: BleFidoIngressFrontend::new(max_fragment_len, BLE_INGRESS),
            arbiter,
        }
    }
}

impl<T: TrustedBackend> BleFidoProfileHandler for SharedBleIngressFrontend<'_, T> {
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
