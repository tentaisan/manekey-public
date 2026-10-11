use manekey::{
    ctaphid::{descriptor::REPORT_SIZE, trusted::TrustedBackend},
    frontend::{
        ctaphid::CtaphidReportFrontend,
        ingress::{IngressArbiter, IngressId, IngressKind},
    },
};

const USB_INGRESS: IngressId = IngressId::new(IngressKind::UsbHid, 0);
pub use crate::ingress::SharedArbiter;

/// Cooperative HID ingress; continue polling deferred disconnect cancellation and drain accepted reports.
pub struct UsbIngressFrontend<T: TrustedBackend + 'static> {
    reports: CtaphidReportFrontend,
    arbiter: &'static SharedArbiter<T>,
}

impl<T: TrustedBackend + 'static> UsbIngressFrontend<T> {
    pub fn new(arbiter: &'static SharedArbiter<T>) -> Self {
        Self {
            reports: CtaphidReportFrontend::new(),
            arbiter,
        }
    }

    pub fn arbiter(&self) -> &'static SharedArbiter<T> {
        self.arbiter
    }

    pub fn handle_report(&mut self, report: [u8; REPORT_SIZE]) {
        self.arbiter.lock(|cell| {
            let mut arbiter = cell.borrow_mut();
            self.reports
                .handle_report(&mut arbiter, USB_INGRESS, report);
        });
    }

    pub fn poll(&mut self) {
        self.arbiter.lock(|cell| {
            let mut arbiter = cell.borrow_mut();
            self.reports.poll(&mut arbiter, USB_INGRESS);
        });
    }

    pub fn current_report(&self) -> Option<&[u8; REPORT_SIZE]> {
        self.reports.current_report()
    }

    pub fn advance_report(&mut self) {
        self.reports.advance_report();
    }

    pub fn on_disconnect(&mut self) {
        self.arbiter.lock(|cell| {
            let mut arbiter = cell.borrow_mut();
            self.reports.on_link_lost(&mut arbiter, USB_INGRESS);
        });
    }
}

use manekey::transport::usb::embassy::{UsbIngressAccess, UsbIngressReportApp};

pub struct EspUsbArbiterAccess<T: TrustedBackend + 'static>(pub &'static SharedArbiter<T>);
impl<T: TrustedBackend + 'static> UsbIngressAccess<T> for EspUsbArbiterAccess<T> {
    fn with_arbiter<R>(&self, f: impl FnOnce(&mut IngressArbiter<T>) -> R) -> R {
        self.0.lock(|cell| f(&mut cell.borrow_mut()))
    }
}
impl<T: TrustedBackend + 'static> UsbIngressReportApp for UsbIngressFrontend<T> {
    fn handle_report(&mut self, report: [u8; REPORT_SIZE]) {
        Self::handle_report(self, report);
    }
    fn poll(&mut self) {
        Self::poll(self);
    }
    fn current_report(&self) -> Option<&[u8; REPORT_SIZE]> {
        Self::current_report(self)
    }
    fn advance_report(&mut self) {
        Self::advance_report(self);
    }
    fn on_disconnect(&mut self) {
        Self::on_disconnect(self);
    }
}
