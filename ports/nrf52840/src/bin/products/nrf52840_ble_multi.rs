use core::cell::RefCell;

use embassy_sync::blocking_mutex::{Mutex, raw::ThreadModeRawMutex};
use manekey::ctaphid::{
    CtaphidProtocol,
    channel::{CONT_PAYLOAD_SIZE, INIT_PAYLOAD_SIZE, MAX_MESSAGE_SIZE},
    descriptor::{CtaphidUsbDeviceInfo, POLL_MS, REPORT_SIZE},
    framing::ReportQueue,
};
#[cfg(feature = "nrf-ccid-experimental")]
use manekey::frontend::ccid::{CCID_RESPONSE_MAX, CcidFrontend};
use manekey::frontend::ingress::{IngressArbiter, IngressId, IngressKind};
use manekey::transport::ble::{
    BleFidoError, BleFidoFragmentSink, BleFidoProfileHandler, BleFidoProtocol,
};
#[cfg(feature = "nrf-ccid-experimental")]
use manekey::transport::usb::ccid_bulk::CcidBulkAssembler;
use nrf_softdevice::raw;
use nrf_usbd::Usbd;

#[cfg(feature = "nrf-ccid-experimental")]
use nrf52840::usb_ccid::CcidUsbClass;
use nrf52840::usb_hid::{CtapHidClass, NrfUsbd};
use nrf52840_pac::USBD;
use static_cell::StaticCell;
use usb_device::{
    UsbError,
    bus::UsbBusAllocator,
    device::{StringDescriptors, UsbDeviceBuilder, UsbVidPid},
};

#[cfg(not(feature = "nrf-dual-task"))]
use super::SelectedDispatcher;
use super::{BLE_PACKET_LEN, log, log_word, nrf52840_ble_poll_tick};

const USB_INGRESS: IngressId = IngressId::new(IngressKind::UsbHid, 0);
const BLE_INGRESS: IngressId = IngressId::new(IngressKind::Ble, 0);
const MAX_REPORTS: usize = 1 + (MAX_MESSAGE_SIZE - INIT_PAYLOAD_SIZE).div_ceil(CONT_PAYLOAD_SIZE);
#[cfg(not(feature = "nrf-dual-task"))]
pub(super) type SharedBackend = SelectedDispatcher;
#[cfg(feature = "nrf-dual-task")]
pub(super) type SharedBackend = nrf52840::fido::NrfLocalMailboxBackend;
/// Thread-mode-only shared arbiter; exclude IRQ access and reserve one owner per ingress.
pub(super) type SharedArbiter = Mutex<ThreadModeRawMutex, RefCell<IngressArbiter<SharedBackend>>>;

fn usb_power_ready() -> bool {
    let mut status = 0;
    let result = unsafe { raw::sd_power_usbregstatus_get(&mut status) };
    result == 0 && status & 0x03 == 0x03
}

fn usb_vbus_present() -> bool {
    let mut status = 0;
    let result = unsafe { raw::sd_power_usbregstatus_get(&mut status) };
    result == 0 && status & 0x01 != 0
}

/// Single BLE ingress owner; queued fragments do not acknowledge peer delivery.
pub(super) struct SharedBleFrontend {
    protocol: BleFidoProtocol,
    arbiter: &'static SharedArbiter,
}

impl SharedBleFrontend {
    pub(super) const fn new(arbiter: &'static SharedArbiter) -> Self {
        Self {
            protocol: BleFidoProtocol::new(BLE_PACKET_LEN),
            arbiter,
        }
    }
}

impl BleFidoProfileHandler for SharedBleFrontend {
    fn handle_control_point_write<const MAX_FRAGMENT: usize>(
        &mut self,
        fragment: &[u8],
        sink: &mut impl BleFidoFragmentSink,
    ) -> Result<usize, BleFidoError> {
        self.arbiter.lock(|arbiter| {
            let mut arbiter = arbiter.borrow_mut();
            let mut backend = arbiter.bind(BLE_INGRESS);
            self.protocol
                .handle_write_with_backend::<MAX_FRAGMENT>(fragment, sink, &mut backend)
        })
    }

    fn poll_status<const MAX_FRAGMENT: usize>(
        &mut self,
        sink: &mut impl BleFidoFragmentSink,
    ) -> Result<usize, BleFidoError> {
        self.arbiter.lock(|arbiter| {
            let mut arbiter = arbiter.borrow_mut();
            let mut backend = arbiter.bind(BLE_INGRESS);
            self.protocol
                .poll_with_backend::<MAX_FRAGMENT>(sink, &mut backend)
        })
    }

    fn on_disconnect(&mut self) {
        self.arbiter.lock(|arbiter| {
            let mut arbiter = arbiter.borrow_mut();
            let mut backend = arbiter.bind(BLE_INGRESS);
            self.protocol.disconnect_with_backend(&mut backend);
        });
    }

    fn settle_disconnected_backend(&mut self) -> bool {
        self.arbiter.lock(|arbiter| {
            let mut arbiter = arbiter.borrow_mut();
            let mut backend = arbiter.bind(BLE_INGRESS);
            self.protocol.settle_disconnected_backend(&mut backend)
        })
    }
}

#[embassy_executor::task]
/// Start once with exclusive USBD, USB wake registration and active SoftDevice power/clock services.
/// Reserve static buffers and supply authorized USB identity.
pub(super) async fn usb_fido_task(usbd: USBD, arbiter: &'static SharedArbiter) {
    log("multi usb task start");
    let detected = unsafe { raw::sd_power_usbdetected_enable(1) };
    let ready = unsafe { raw::sd_power_usbpwrrdy_enable(1) };
    let removed = unsafe { raw::sd_power_usbremoved_enable(1) };
    if detected != 0 || ready != 0 || removed != 0 {
        log_word(
            "multi usb power event enable failed",
            detected | ready | removed,
        );
        return;
    }
    let mut status = 0;
    let result = unsafe { raw::sd_power_usbregstatus_get(&mut status) };
    log_word("multi usb power query result", result);
    log_word("multi usb power status", status);
    let mut ticks = nrf52840_ble_poll_tick::usb_current();
    while !usb_vbus_present() {
        ticks = nrf52840_ble_poll_tick::usb_wait_after(ticks).await;
    }
    if unsafe { raw::sd_clock_hfclk_request() } != 0 {
        log("multi usb hfclk request failed");
        return;
    }
    let mut running = 0;
    for _ in 0..1_000 {
        if unsafe { raw::sd_clock_hfclk_is_running(&mut running) } == 0 && running != 0 {
            break;
        }
        ticks = nrf52840_ble_poll_tick::usb_wait_after(ticks).await;
    }
    if running == 0 {
        log("multi usb hfclk did not start");
        return;
    }
    log("multi usb hfclk running");
    static USB_BUS: StaticCell<UsbBusAllocator<Usbd<NrfUsbd>>> = StaticCell::new();
    log("multi usb bus create");
    let usb_bus = USB_BUS.init(UsbBusAllocator::new(Usbd::new(NrfUsbd(usbd))));
    let mut hid = CtapHidClass::new(usb_bus, POLL_MS);
    #[cfg(feature = "nrf-ccid-experimental")]
    let mut ccid = CcidUsbClass::new(usb_bus, CCID_RESPONSE_MAX as u32);
    let identity = CtaphidUsbDeviceInfo::new("ManeKey nRF52840 USB BLE FIDO", "nrf52840-multi");
    let mut usb_dev =
        UsbDeviceBuilder::new(usb_bus, UsbVidPid(identity.vendor_id, identity.product_id))
            .strings(&[StringDescriptors::default()
                .manufacturer(identity.manufacturer)
                .product(identity.product)
                .serial_number(identity.serial_number.unwrap_or(""))])
            .unwrap()
            .build();
    let _ = usb_dev.force_reset();
    log("multi usb initialized");
    let mut status = 0;
    let result = unsafe { raw::sd_power_usbregstatus_get(&mut status) };
    log_word("multi usb post-init power result", result);
    log_word("multi usb post-init power status", status);

    let mut protocol = CtaphidProtocol::new();
    #[cfg(feature = "nrf-internal-uart")]
    let mut internal = manekey::frontend::internal::InterconnectCtap2Frontend::<
        { manekey::ctaphid::trusted::TRUSTED_RESPONSE_MAX + 32 },
    >::new(0);
    #[cfg(feature = "nrf-internal-uart")]
    static UART_RESPONSE: StaticCell<[u8; manekey::ctaphid::trusted::TRUSTED_RESPONSE_MAX + 32]> =
        StaticCell::new();
    #[cfg(feature = "nrf-internal-uart")]
    let uart_response =
        UART_RESPONSE.init([0; manekey::ctaphid::trusted::TRUSTED_RESPONSE_MAX + 32]);
    let mut report = [0u8; REPORT_SIZE];
    let mut egress = ReportQueue::<MAX_REPORTS>::new();
    let mut poll_divider = 0u8;

    #[cfg(feature = "nrf-ccid-experimental")]
    let mut ccid_frontend = CcidFrontend::new(0);
    #[cfg(feature = "nrf-ccid-experimental")]
    let mut ccid_request = CcidBulkAssembler::<CCID_RESPONSE_MAX>::new();
    #[cfg(feature = "nrf-ccid-experimental")]
    let mut ccid_response = [0u8; CCID_RESPONSE_MAX];
    #[cfg(feature = "nrf-ccid-experimental")]
    let mut ccid_packet = [0u8; 64];
    #[cfg(feature = "nrf-ccid-experimental")]
    let (mut ccid_tx_len, mut ccid_tx_sent) = (0usize, 0usize);
    #[cfg(feature = "nrf-ccid-experimental")]
    let mut ccid_tx_zlp = false;
    loop {
        ticks = nrf52840_ble_poll_tick::usb_wait_after(ticks).await;
        #[cfg(feature = "nrf-internal-uart")]
        arbiter.lock(|arbiter| {
            let mut arbiter = arbiter.borrow_mut();
            let _ = internal.poll_cancel(&mut arbiter);
            if nrf52840::internal_uart::take_overflow() {
                internal.disconnect(&mut arbiter);
            }
            for _ in 0..64 {
                let Some(byte) = nrf52840::internal_uart::read() else {
                    break;
                };

                match internal.push_byte(&mut arbiter, byte, uart_response) {
                    Ok(Some(manekey::frontend::internal::InterconnectCtap2Outcome::Response {
                        len,
                    })) => nrf52840::internal_uart::write(&uart_response[..len]),
                    Err(_) => internal.disconnect(&mut arbiter),
                    _ => {}
                }
            }
        });

        if !usb_power_ready() {
            arbiter.lock(|arbiter| {
                let mut arbiter = arbiter.borrow_mut();
                let _ = arbiter.cancel(USB_INGRESS);
                #[cfg(feature = "nrf-ccid-experimental")]
                ccid_frontend.disconnect(&mut arbiter);
            });
            protocol = CtaphidProtocol::new();
            egress.clear();
            #[cfg(feature = "nrf-ccid-experimental")]
            {
                ccid_request.reset();
                ccid_tx_len = 0;
                ccid_tx_sent = 0;
                ccid_tx_zlp = false;
            }
            while !usb_power_ready() {
                ticks = nrf52840_ble_poll_tick::usb_wait_after(ticks).await;
            }
            let _ = usb_dev.force_reset();
        }
        #[cfg(not(feature = "nrf-ccid-experimental"))]
        let active = usb_dev.poll(&mut [&mut hid]);
        #[cfg(feature = "nrf-ccid-experimental")]
        let active = usb_dev.poll(&mut [&mut hid, &mut ccid]);
        #[cfg(feature = "nrf-ccid-experimental")]
        {
            if ccid.take_bus_reset() {
                arbiter.lock(|arbiter| {
                    let mut arbiter = arbiter.borrow_mut();
                    let _ = arbiter.cancel(USB_INGRESS);
                    ccid_frontend.disconnect(&mut arbiter);
                });
                protocol = CtaphidProtocol::new();
                egress.clear();
                ccid_request.reset();
                ccid_tx_len = 0;
                ccid_tx_sent = 0;
                ccid_tx_zlp = false;
            }
            if let Some((slot, sequence)) = ccid.take_control_abort() {
                arbiter.lock(|arbiter| {
                    ccid_frontend.begin_abort(&mut arbiter.borrow_mut(), slot, sequence);
                });
            }
            if ccid_tx_sent < ccid_tx_len || ccid_tx_zlp {
                let end = (ccid_tx_sent + 64).min(ccid_tx_len);
                if let Ok(_) = ccid.write_packet(&ccid_response[ccid_tx_sent..end]) {
                    ccid_tx_sent = end;
                    if ccid_tx_sent == ccid_tx_len {
                        if ccid_tx_zlp {
                            ccid_tx_zlp = false;
                        } else if ccid_tx_len % 64 == 0 {
                            ccid_tx_zlp = true;
                        }
                    }
                }
            }
            if active && ccid_tx_sent == ccid_tx_len && !ccid_tx_zlp {
                if let Ok(size) = ccid.read_packet(&mut ccid_packet) {
                    if let Ok(Some(request)) = ccid_request.push(&ccid_packet[..size]) {
                        ccid_tx_len = arbiter.lock(|arbiter| {
                            ccid_frontend
                                .handle_message(
                                    &mut arbiter.borrow_mut(),
                                    request,
                                    &mut ccid_response,
                                )
                                .unwrap_or(0)
                        });
                        ccid_tx_sent = 0;
                        ccid_request.reset();
                    }
                }
            }
        }
        if let Some(packet) = egress.current() {
            match hid.write(packet) {
                Ok(_) => {
                    egress.advance();
                }
                Err(UsbError::WouldBlock) => {}
                Err(_) => {
                    egress.clear();
                }
            }
        }
        if active && egress.is_empty() {
            if let Ok(REPORT_SIZE) = hid.read(&mut report) {
                arbiter.lock(|arbiter| {
                    let mut arbiter = arbiter.borrow_mut();
                    let mut backend = arbiter.bind(USB_INGRESS);
                    egress.queue_response(protocol.handle_raw_with_backend(report, &mut backend));
                });
            }
        }
        poll_divider = poll_divider.saturating_add(1);
        if poll_divider >= 100 {
            poll_divider = 0;
            if egress.is_empty() {
                arbiter.lock(|arbiter| {
                    let mut arbiter = arbiter.borrow_mut();
                    let mut backend = arbiter.bind(USB_INGRESS);
                    egress.queue_response(protocol.poll_with_backend(&mut backend));
                });
            }
            #[cfg(feature = "nrf-ccid-experimental")]
            if ccid_tx_sent == ccid_tx_len && !ccid_tx_zlp {
                ccid_tx_len = arbiter.lock(|arbiter| {
                    ccid_frontend
                        .poll(&mut arbiter.borrow_mut(), &mut ccid_response)
                        .ok()
                        .flatten()
                        .unwrap_or(0)
                });
                ccid_tx_sent = 0;
            }
        }
    }
}
