#[cfg(any(
    feature = "riscv-pmp-usb-internal-ccid",
    not(any(
        feature = "riscv-single-core-task-transport",
        feature = "riscv-dual-core-internal-ccid"
    ))
))]
use manekey::ctaphid::trusted::TrustedResult;
use manekey::{
    ctaphid::trusted::{TRUSTED_RESPONSE_MAX, TrustedBackend},
    frontend::{
        ccid::{CCID_RESPONSE_MAX, CcidFrontend},
        ctaphid::CtaphidReportFrontend,
        ingress::{IngressArbiter, IngressId, IngressKind},
        internal::{InterconnectCtap2Frontend, InterconnectCtap2Outcome},
    },
    transport::usb::{ccid_bulk::CcidBulkAssembler, polling_ccid::PollingCcid},
};
#[cfg(not(feature = "riscv-pmp-usb-internal-ccid"))]
use rp235x_hal as hal;
use usb_device::{
    bus::UsbBus,
    class_prelude::UsbClass,
    device::{UsbDevice, UsbDeviceState},
};
use usbd_hid::hid_class::HIDClass;

#[cfg(any(
    feature = "riscv-pmp-usb-internal-ccid",
    not(any(
        feature = "riscv-single-core-task-transport",
        feature = "riscv-dual-core-internal-ccid"
    ))
))]
/// Exclusive borrowed backend; the enclosing arbiter must serialize all ingress operations.
pub struct BorrowedBackend<'a, T>(pub &'a mut T);

#[cfg(any(
    feature = "riscv-pmp-usb-internal-ccid",
    not(any(
        feature = "riscv-single-core-task-transport",
        feature = "riscv-dual-core-internal-ccid"
    ))
))]
impl<T: TrustedBackend> TrustedBackend for BorrowedBackend<'_, T> {
    fn submit_cbor<'a>(&'a mut self, request: &[u8]) -> TrustedResult<'a> {
        self.0.submit_cbor(request)
    }
    fn submit_u2f<'a>(&'a mut self, request: &[u8]) -> TrustedResult<'a> {
        self.0.submit_u2f(request)
    }
    fn poll<'a>(&'a mut self) -> Option<TrustedResult<'a>> {
        self.0.poll()
    }
    fn cancel(&mut self) -> bool {
        self.0.cancel()
    }
    fn is_busy(&self) -> bool {
        self.0.is_busy()
    }
}

#[cfg(not(feature = "riscv-pmp-usb-internal-ccid"))]
/// Sole polling owner of USB/UART and the backend; TIMER0 counter ticks must be microseconds.
pub fn run<T: TrustedBackend>(
    backend: T,
    pump: &mut impl FnMut(),
    timer: hal::timer::Timer<hal::timer::CopyableTimer0>,
    usb: &mut UsbDevice<'_, hal::usb::UsbBus>,
    hid: &mut HIDClass<'_, hal::usb::UsbBus>,
    ccid: &mut PollingCcid<'_, hal::usb::UsbBus>,
    read: impl FnMut(&mut [u8]) -> usize,
    write: impl FnMut(&[u8]),
) -> ! {
    run_with_clock(
        backend,
        pump,
        || timer.get_counter().ticks(),
        usb,
        hid,
        ccid,
        &mut |_, _, _| {},
        read,
        write,
    )
}

/// Sole non-reentrant polling owner; now_us must be monotonic microseconds and read must return at most its buffer length.
/// write must consume every byte; callbacks cannot retain buffers or re-enter the frontend.
/// Endpoint writes retry without an overall timeout or host delivery acknowledgement.
pub fn run_with_clock<T: TrustedBackend, B: UsbBus>(
    backend: T,
    pump: &mut impl FnMut(),
    mut now_us: impl FnMut() -> u64,
    usb: &mut UsbDevice<'_, B>,
    hid: &mut HIDClass<'_, B>,
    ccid: &mut PollingCcid<'_, B>,
    usb_progress: &mut impl FnMut(&UsbDevice<'_, B>, bool, bool),
    mut read: impl FnMut(&mut [u8]) -> usize,
    mut write: impl FnMut(&[u8]),
) -> ! {
    const HID: IngressId = IngressId::new(IngressKind::UsbHid, 0);
    let mut arbiter = IngressArbiter::new(backend);
    let mut hid_frontend = CtaphidReportFrontend::new();
    let mut ccid_frontend = CcidFrontend::new(0);
    let mut assembler = CcidBulkAssembler::<CCID_RESPONSE_MAX>::new();
    let mut ccid_response = [0; CCID_RESPONSE_MAX];
    let (mut ccid_len, mut ccid_sent, mut zlp) = (0usize, 0usize, false);
    let mut internal = InterconnectCtap2Frontend::<{ TRUSTED_RESPONSE_MAX + 32 }>::new(0);
    let mut internal_response = [0; TRUSTED_RESPONSE_MAX + 32];
    let mut last_poll = now_us();
    let mut configured = false;
    loop {
        pump();
        let event = usb.poll(&mut [hid as &mut dyn UsbClass<B>, ccid]);
        let now_configured = usb.state() == UsbDeviceState::Configured;
        if configured && !now_configured {
            hid_frontend.on_link_lost(&mut arbiter, HID);
        }
        configured = now_configured;
        if ccid.take_reset() {
            ccid_frontend.disconnect(&mut arbiter);
            assembler.reset();
            ccid_len = 0;
            ccid_sent = 0;
            zlp = false;
        }
        if let Some((slot, sequence)) = ccid.take_abort() {
            ccid_frontend.begin_abort(&mut arbiter, slot, sequence);
        }
        if event && hid_frontend.current_report().is_none() {
            let mut report = [0; 64];
            if let Ok(64) = hid.pull_raw_output(&mut report) {
                hid_frontend.handle_report(&mut arbiter, HID, report);
                usb_progress(usb, true, false);
            }
        }
        if ccid_len == 0 && !zlp {
            let mut packet = [0; 64];
            if let Ok(length) = ccid.read(&mut packet) {
                match assembler.push(&packet[..length]) {
                    Ok(Some(message)) => {
                        ccid_len = ccid_frontend
                            .handle_message(&mut arbiter, message, &mut ccid_response)
                            .unwrap_or(0);
                        ccid_sent = 0;
                        assembler.reset();
                    }
                    Err(_) => assembler.reset(),
                    Ok(None) => {}
                }
            }
        }
        let mut input = [0; 64];
        let length = read(&mut input);
        for byte in &input[..length] {
            if let Ok(Some(InterconnectCtap2Outcome::Response { len })) =
                internal.push_byte(&mut arbiter, *byte, &mut internal_response)
            {
                for chunk in internal_response[..len].chunks(32) {
                    write(chunk);
                }
            }
            pump();
        }
        internal.poll_cancel(&mut arbiter);
        pump();
        let now = now_us();
        if now.saturating_sub(last_poll) >= 100_000 {
            last_poll = now;
            if hid_frontend.current_report().is_none() {
                hid_frontend.poll(&mut arbiter, HID);
            }
            if ccid_len == 0 && !zlp {
                ccid_len = ccid_frontend
                    .poll(&mut arbiter, &mut ccid_response)
                    .ok()
                    .flatten()
                    .unwrap_or(0);
                ccid_sent = 0;
            }
        }
        if let Some(report) = hid_frontend.current_report() {
            if hid.push_raw_input(report).is_ok() {
                hid_frontend.advance_report();
                usb_progress(usb, false, true);
            }
        }
        if ccid_len != 0 {
            let end = (ccid_sent + 64).min(ccid_len);
            if let Ok(length) = ccid.write(&ccid_response[ccid_sent..end]) {
                ccid_sent += length;
                if ccid_sent == ccid_len {
                    zlp = ccid_len % 64 == 0;
                    ccid_len = 0;
                }
            }
        } else if zlp && ccid.write(&[]).is_ok() {
            zlp = false;
        }
    }
}
