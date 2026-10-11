use super::{CcidUsbClass, CcidUsbError};
use crate::{
    ctaphid::{descriptor::REPORT_SIZE, trusted::TrustedBackend},
    frontend::{
        ccid::{CCID_RESPONSE_MAX, CcidFrontend},
        ctaphid::CtaphidReportFrontend,
        ingress::{IngressArbiter, IngressId, IngressKind},
    },
};
use core::cell::RefCell;
use embassy_futures::select::{Either, select};
use embassy_sync::blocking_mutex::{Mutex, raw::NoopRawMutex};
use embassy_time::{Duration, Ticker, Timer};
use embassy_usb::{
    class::hid::{HidReaderWriter, ReadError},
    driver::Driver,
};

const USB_INGRESS: IngressId = IngressId::new(IngressKind::UsbHid, 0);
const POLL_INTERVAL_MS: u64 = 100;
const WRITE_STALL_MS: u64 = 1_000;

/// Single-context arbiter; NoopRawMutex does not synchronize threads or cores.
pub type SharedUsbArbiter<T> = Mutex<NoopRawMutex, RefCell<IngressArbiter<T>>>;

pub trait UsbIngressAccess<T: TrustedBackend> {
    fn with_arbiter<R>(&self, f: impl FnOnce(&mut IngressArbiter<T>) -> R) -> R;
}
impl<T: TrustedBackend> UsbIngressAccess<T> for &SharedUsbArbiter<T> {
    fn with_arbiter<R>(&self, f: impl FnOnce(&mut IngressArbiter<T>) -> R) -> R {
        self.lock(|cell| f(&mut cell.borrow_mut()))
    }
}

pub trait UsbIngressReportApp {
    fn handle_report(&mut self, report: [u8; REPORT_SIZE]);
    fn poll(&mut self);
    fn current_report(&self) -> Option<&[u8; REPORT_SIZE]>;
    fn advance_report(&mut self);
    fn on_disconnect(&mut self);
}

pub struct UsbIngressFrontend<T: TrustedBackend + 'static> {
    reports: CtaphidReportFrontend,
    arbiter: &'static SharedUsbArbiter<T>,
}

impl<T: TrustedBackend + 'static> UsbIngressFrontend<T> {
    pub fn new(arbiter: &'static SharedUsbArbiter<T>) -> Self {
        Self {
            reports: CtaphidReportFrontend::new(),
            arbiter,
        }
    }
    pub fn arbiter(&self) -> &'static SharedUsbArbiter<T> {
        self.arbiter
    }
    pub fn handle_report(&mut self, report: [u8; REPORT_SIZE]) {
        self.arbiter.lock(|cell| {
            self.reports
                .handle_report(&mut cell.borrow_mut(), USB_INGRESS, report)
        });
    }
    pub fn poll(&mut self) {
        self.arbiter
            .lock(|cell| self.reports.poll(&mut cell.borrow_mut(), USB_INGRESS));
    }
    pub fn current_report(&self) -> Option<&[u8; REPORT_SIZE]> {
        self.reports.current_report()
    }
    pub fn advance_report(&mut self) {
        self.reports.advance_report();
    }
    pub fn on_disconnect(&mut self) {
        self.arbiter.lock(|cell| {
            self.reports
                .on_link_lost(&mut cell.borrow_mut(), USB_INGRESS)
        });
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

pub struct CcidIoBuffers {
    request: [u8; CCID_RESPONSE_MAX],
    response: [u8; CCID_RESPONSE_MAX],
    frontend: CcidFrontend,
}
impl CcidIoBuffers {
    pub const fn new() -> Self {
        Self {
            request: [0; CCID_RESPONSE_MAX],
            response: [0; CCID_RESPONSE_MAX],
            frontend: CcidFrontend::new(0),
        }
    }
}
impl Default for CcidIoBuffers {
    fn default() -> Self {
        Self::new()
    }
}

pub async fn run_ccid_ingress_loop<
    'd,
    D: Driver<'d>,
    T: TrustedBackend + 'static,
    A: UsbIngressAccess<T>,
>(
    mut transport: CcidUsbClass<'d, D>,
    arbiter: A,
    buffers: &mut CcidIoBuffers,
) -> ! {
    let frontend = &mut buffers.frontend;
    let mut ticker = Ticker::every(Duration::from_millis(POLL_INTERVAL_MS));
    loop {
        if transport.take_bus_reset() {
            arbiter.with_arbiter(|arbiter| frontend.disconnect(arbiter));
        }
        if let Some((slot, sequence)) = transport.take_control_abort() {
            arbiter.with_arbiter(|arbiter| frontend.begin_abort(arbiter, slot, sequence));
        }
        let event = select(transport.read_message(&mut buffers.request), ticker.next()).await;
        if transport.take_bus_reset() {
            arbiter.with_arbiter(|arbiter| frontend.disconnect(arbiter));
        }
        if let Some((slot, sequence)) = transport.take_control_abort() {
            arbiter.with_arbiter(|arbiter| frontend.begin_abort(arbiter, slot, sequence));
        }
        let response_len = match event {
            Either::First(Ok(len)) => arbiter.with_arbiter(|arbiter| {
                frontend
                    .handle_message(arbiter, &buffers.request[..len], &mut buffers.response)
                    .ok()
            }),
            Either::First(Err(CcidUsbError::Disabled)) => {
                arbiter.with_arbiter(|arbiter| frontend.disconnect(arbiter));
                transport.wait_connection().await;
                continue;
            }
            Either::First(Err(_)) => {
                ticker.next().await;
                continue;
            }
            Either::Second(()) => arbiter.with_arbiter(|arbiter| {
                frontend.poll(arbiter, &mut buffers.response).ok().flatten()
            }),
        };
        if let Some(len) = response_len {
            let _ = transport.write_message(&buffers.response[..len]).await;
        }
    }
}

pub async fn run_hid_ingress_loop<'d, D: Driver<'d>, A: UsbIngressReportApp>(
    mut hid: HidReaderWriter<'d, D, REPORT_SIZE, REPORT_SIZE>,
    app: &mut A,
) -> ! {
    let mut report = [0u8; REPORT_SIZE];
    loop {
        if let Either::Second(()) = select(hid.ready(), Timer::after_millis(POLL_INTERVAL_MS)).await
        {
            app.on_disconnect();
            continue;
        }
        if let Some(next) = app.current_report() {
            let next = *next;
            match select(hid.write(&next), Timer::after_millis(WRITE_STALL_MS)).await {
                Either::First(Ok(())) => app.advance_report(),
                Either::First(Err(_)) | Either::Second(()) => app.on_disconnect(),
            }
            continue;
        }
        match select(hid.read(&mut report), Timer::after_millis(POLL_INTERVAL_MS)).await {
            Either::First(Ok(REPORT_SIZE)) => app.handle_report(report),
            Either::First(Err(ReadError::Disabled)) => {
                app.on_disconnect();
                Timer::after_millis(POLL_INTERVAL_MS).await;
            }
            Either::First(Ok(_)) | Either::First(Err(_)) => {
                Timer::after_millis(POLL_INTERVAL_MS).await
            }
            Either::Second(()) => app.poll(),
        }
    }
}
