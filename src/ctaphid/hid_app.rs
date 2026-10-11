use super::descriptor::REPORT_SIZE;
use super::trusted::TrustedBackend;
use super::{CtaphidFrontend, Response};

/// Report processing and polling for a trusted-backend frontend.
pub trait HidCtaphidApp {
    fn handle_hid_report<'a>(&'a mut self, report: [u8; REPORT_SIZE]) -> Option<Response<'a>>;

    fn poll_hid<'a>(&'a mut self) -> Option<Response<'a>>;
}

impl<T: TrustedBackend> HidCtaphidApp for CtaphidFrontend<T> {
    fn handle_hid_report<'a>(&'a mut self, report: [u8; REPORT_SIZE]) -> Option<Response<'a>> {
        self.handle_raw(report)
    }

    fn poll_hid<'a>(&'a mut self) -> Option<Response<'a>> {
        self.poll()
    }
}
