use crate::{usb_ccid::CcidUsbClass, usb_hid::CtapHidClass};
use manekey::{
    ctaphid::trusted::TrustedBackend,
    frontend::{
        ccid::{CCID_RESPONSE_MAX, CcidFrontend},
        ctaphid::CtaphidReportFrontend,
        ingress::{IngressArbiter, IngressId, IngressKind},
    },
    transport::usb::ccid_bulk::CcidBulkAssembler,
};
use usb_device::{bus::UsbBus, device::UsbDevice};

/// Single-owner HID/CCID ingress; endpoint acceptance does not acknowledge peer delivery.
pub struct UsbIngress {
    hid: CtaphidReportFrontend,
    ccid: CcidFrontend,
    request: CcidBulkAssembler<CCID_RESPONSE_MAX>,
    response: [u8; CCID_RESPONSE_MAX],
    tx_len: usize,
    tx_sent: usize,
    tx_zlp: bool,
    last_poll: u32,
}
impl UsbIngress {
    pub const fn new() -> Self {
        Self {
            hid: CtaphidReportFrontend::new(),
            ccid: CcidFrontend::new(0),
            request: CcidBulkAssembler::new(),
            response: [0; CCID_RESPONSE_MAX],
            tx_len: 0,
            tx_sent: 0,
            tx_zlp: false,
            last_poll: 0,
        }
    }
    pub fn poll<B: UsbBus, T: TrustedBackend>(
        &mut self,
        arbiter: &mut IngressArbiter<T>,
        usb: &mut UsbDevice<'_, B>,
        hid: &mut CtapHidClass<'_, B>,
        ccid: &mut CcidUsbClass<'_, B>,
        now: u32,
    ) {
        let ingress = IngressId::new(IngressKind::UsbHid, 0);
        let active = usb.poll(&mut [hid, ccid]);
        if ccid.take_bus_reset() {
            self.hid.on_link_lost(arbiter, ingress);
            self.ccid.disconnect(arbiter);
            self.request.reset();
            self.tx_len = 0;
            self.tx_sent = 0;
            self.tx_zlp = false;
        }
        if let Some((slot, seq)) = ccid.take_control_abort() {
            self.ccid.begin_abort(arbiter, slot, seq);
            self.request.reset();
            self.tx_len = 0;
            self.tx_sent = 0;
            self.tx_zlp = false;
        }
        if let Some(report) = self.hid.current_report() {
            if hid.write(report).is_ok() {
                self.hid.advance_report();
            }
        }
        if active && self.hid.current_report().is_none() {
            let mut report = [0; 64];
            if let Ok(64) = hid.read(&mut report) {
                self.hid.handle_report(arbiter, ingress, report);
            }
        }
        if self.tx_sent < self.tx_len || self.tx_zlp {
            let end = (self.tx_sent + 64).min(self.tx_len);
            if ccid.write_packet(&self.response[self.tx_sent..end]).is_ok() {
                self.tx_sent = end;
                if self.tx_sent == self.tx_len {
                    if self.tx_zlp {
                        self.tx_zlp = false;
                    } else if self.tx_len % 64 == 0 {
                        self.tx_zlp = true;
                    }
                }
            }
        }
        if active && self.tx_sent == self.tx_len && !self.tx_zlp {
            let mut packet = [0; 64];
            if let Ok(size) = ccid.read_packet(&mut packet) {
                if let Ok(Some(message)) = self.request.push(&packet[..size]) {
                    self.tx_len = self
                        .ccid
                        .handle_message(arbiter, message, &mut self.response)
                        .unwrap_or(0);
                    self.tx_sent = 0;
                    self.request.reset();
                }
            }
        }
        if now.wrapping_sub(self.last_poll) >= 100 {
            self.last_poll = now;
            if self.hid.current_report().is_none() {
                self.hid.poll(arbiter, ingress);
            }
            if self.tx_sent == self.tx_len && !self.tx_zlp {
                self.tx_len = self
                    .ccid
                    .poll(arbiter, &mut self.response)
                    .ok()
                    .flatten()
                    .unwrap_or(0);
                self.tx_sent = 0;
            }
        }
    }
}

/// Exclusively reserve RTC2 and keep its LF clock active.
pub fn start_clock(rtc: nrf52840_pac::RTC2) {
    rtc.tasks_stop.write(|w| unsafe { w.bits(1) });
    rtc.prescaler.write(|w| unsafe { w.bits(0) });
    rtc.tasks_clear.write(|w| unsafe { w.bits(1) });
    rtc.tasks_start.write(|w| unsafe { w.bits(1) });
}
/// Milliseconds from a wrapping 24-bit RTC counter, not an unbounded monotonic clock.
pub fn now_ms() -> u32 {
    let rtc = unsafe { &*nrf52840_pac::RTC2::ptr() };
    ((u64::from(rtc.counter.read().bits()) * 1000) / 32768) as u32
}
