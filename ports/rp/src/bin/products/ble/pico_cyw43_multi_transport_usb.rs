use embassy_futures::select::{Either, select};
use embassy_rp::peripherals;
use embassy_rp::usb::Driver;
use embassy_time::{Duration, Ticker};
use embassy_usb::class::hid::{HidBootProtocol, HidReaderWriter, HidSubclass, State};
use embassy_usb::{Builder, Config};
use manekey::ctaphid::descriptor::{
    CtaphidUsbDeviceInfo, REPORT_DESCRIPTOR, REPORT_SIZE, REPORT_SIZE_U8, REPORT_SIZE_U16,
};
#[cfg(feature = "usb-ccid-experimental")]
use manekey::frontend::ccid::{CCID_RESPONSE_MAX, CcidFrontend};
use manekey::frontend::ctaphid::CtaphidReportFrontend;
use manekey::transport::usb::embassy::HidTransport;
#[cfg(feature = "usb-ccid-experimental")]
use manekey::transport::usb::embassy::{CcidUsbClass, CcidUsbError, CcidUsbState};
use static_cell::StaticCell;

#[cfg(feature = "usb-ccid-experimental")]
use super::FIDO_PENDING_POLL_MS;
use super::{SharedArbiter, USB_INGRESS, update_stack_watermark};

type UsbTransport = HidTransport<'static, Driver<'static, peripherals::USB>>;

const CONTROL_BUFFER_SIZE: usize = if cfg!(feature = "trustzone-usb-ble-nonsecure-experimental") {
    128
} else {
    REPORT_SIZE
};
#[cfg(feature = "usb-ccid-experimental")]
type CcidTransport = CcidUsbClass<'static, Driver<'static, peripherals::USB>>;

#[embassy_executor::task]
/// Sole HID owner; common report framing drains packets and settles owned requests after link loss.
pub(super) async fn multi_usb_frontend_task(
    mut transport: UsbTransport,
    arbiter: &'static SharedArbiter,
) -> ! {
    let mut frontend = CtaphidReportFrontend::new();
    let mut ticker = Ticker::every(Duration::from_millis(100));
    let mut link_lost = false;

    loop {
        if let Some(report) = frontend.current_report().copied() {
            if transport.write(&report).await.is_ok() {
                frontend.advance_report();
            } else {
                arbiter.lock(|arbiter| {
                    frontend.on_link_lost(&mut arbiter.borrow_mut(), USB_INGRESS);
                });
                link_lost = true;
            }
            update_stack_watermark();
            continue;
        }
        let event = select(transport.read(), ticker.next()).await;
        let io_failed = matches!(&event, Either::First(Err(_)));
        arbiter.lock(|arbiter| {
            let mut arbiter = arbiter.borrow_mut();
            match event {
                Either::First(Ok(report)) => {
                    link_lost = false;
                    frontend.handle_report(&mut arbiter, USB_INGRESS, report);
                }
                Either::First(Err(_)) if link_lost => frontend.poll(&mut arbiter, USB_INGRESS),
                Either::First(Err(_)) => {
                    frontend.on_link_lost(&mut arbiter, USB_INGRESS);
                    link_lost = true;
                }
                Either::Second(()) => frontend.poll(&mut arbiter, USB_INGRESS),
            }
        });
        update_stack_watermark();
        if io_failed {
            embassy_time::Timer::after_millis(10).await;
        }
    }
}

#[cfg(feature = "usb-ccid-experimental")]
#[embassy_executor::task]
/// Sole CCID protocol owner; bus reset and abort update the shared arbiter, while send failures are discarded.
pub(super) async fn multi_ccid_frontend_task(
    mut transport: CcidTransport,
    arbiter: &'static SharedArbiter,
) -> ! {
    let mut frontend = CcidFrontend::new(0);
    let mut request = [0u8; CCID_RESPONSE_MAX];
    let mut response = [0u8; CCID_RESPONSE_MAX];
    let mut ticker = Ticker::every(Duration::from_millis(FIDO_PENDING_POLL_MS));

    loop {
        if transport.take_bus_reset() {
            arbiter.lock(|arbiter| frontend.disconnect(&mut arbiter.borrow_mut()));
        }
        if let Some((slot, sequence)) = transport.take_control_abort() {
            arbiter.lock(|arbiter| {
                frontend.begin_abort(&mut arbiter.borrow_mut(), slot, sequence);
            });
        }
        let event = select(transport.read_message(&mut request), ticker.next()).await;
        if transport.take_bus_reset() {
            arbiter.lock(|arbiter| frontend.disconnect(&mut arbiter.borrow_mut()));
        }
        if let Some((slot, sequence)) = transport.take_control_abort() {
            arbiter.lock(|arbiter| {
                frontend.begin_abort(&mut arbiter.borrow_mut(), slot, sequence);
            });
        }
        let response_len = match event {
            Either::First(Ok(request_len)) => arbiter.lock(|arbiter| {
                frontend
                    .handle_message(
                        &mut arbiter.borrow_mut(),
                        &request[..request_len],
                        &mut response,
                    )
                    .ok()
            }),
            Either::First(Err(CcidUsbError::Disabled)) => {
                arbiter.lock(|arbiter| frontend.disconnect(&mut arbiter.borrow_mut()));
                transport.wait_connection().await;
                continue;
            }
            Either::First(Err(_)) => continue,
            Either::Second(()) => arbiter.lock(|arbiter| {
                frontend
                    .poll(&mut arbiter.borrow_mut(), &mut response)
                    .ok()
                    .flatten()
            }),
        };
        update_stack_watermark();
        if let Some(response_len) = response_len {
            let _ = transport.write_message(&response[..response_len]).await;
        }
    }
}

pub(super) struct MultiUsb {
    pub(super) device: embassy_usb::UsbDevice<'static, Driver<'static, peripherals::USB>>,
    pub(super) hid: UsbTransport,
    #[cfg(feature = "usb-ccid-experimental")]
    pub(super) ccid: CcidTransport,
}

/// Build once with exclusive USB ownership and the matching image's IRQ/peripheral attribution.
pub(super) fn build_usb(driver: Driver<'static, peripherals::USB>) -> MultiUsb {
    let identity = if cfg!(feature = "trustzone-usb-ble-nonsecure-experimental") {
        CtaphidUsbDeviceInfo::new("TrustZone UART + USB + BLE FIDO", "rp2350-tz-ble")
    } else if cfg!(feature = "trustzone-multi-ingress-nonsecure") {
        CtaphidUsbDeviceInfo::new("TrustZone UART + USB FIDO", "rp2350-tz-multi")
    } else {
        CtaphidUsbDeviceInfo::new("CYW43 USB + BLE FIDO", "cyw43-multi")
    };
    let mut config = Config::new(identity.vendor_id, identity.product_id);
    config.manufacturer = Some(identity.manufacturer);
    config.product = Some(identity.product);
    config.serial_number = identity.serial_number;
    config.max_power = 100;
    config.max_packet_size_0 = REPORT_SIZE_U8;

    static CONFIG_DESCRIPTOR: StaticCell<[u8; 256]> = StaticCell::new();
    static BOS_DESCRIPTOR: StaticCell<[u8; 256]> = StaticCell::new();
    static MSOS_DESCRIPTOR: StaticCell<[u8; 256]> = StaticCell::new();
    static CONTROL_BUF: StaticCell<[u8; CONTROL_BUFFER_SIZE]> = StaticCell::new();
    static STATE: StaticCell<State> = StaticCell::new();
    #[cfg(feature = "usb-ccid-experimental")]
    static CCID_STATE: StaticCell<CcidUsbState<'static>> = StaticCell::new();
    let mut builder = Builder::new(
        driver,
        config,
        CONFIG_DESCRIPTOR.init([0; 256]),
        BOS_DESCRIPTOR.init([0; 256]),
        MSOS_DESCRIPTOR.init([0; 256]),
        CONTROL_BUF.init([0; CONTROL_BUFFER_SIZE]),
    );
    let hid = HidReaderWriter::<_, REPORT_SIZE, REPORT_SIZE>::new(
        &mut builder,
        STATE.init(State::new()),
        embassy_usb::class::hid::Config {
            hid_subclass: HidSubclass::No,
            hid_boot_protocol: HidBootProtocol::None,
            poll_ms: identity.poll_ms,
            max_packet_size: REPORT_SIZE_U16,
            request_handler: None,
            report_descriptor: REPORT_DESCRIPTOR,
        },
    );
    #[cfg(feature = "usb-ccid-experimental")]
    let ccid = CcidUsbClass::new(
        &mut builder,
        CCID_STATE.init(CcidUsbState::new()),
        REPORT_SIZE_U16,
        CCID_RESPONSE_MAX as u32,
    );
    MultiUsb {
        device: builder.build(),
        hid: HidTransport::new(hid),
        #[cfg(feature = "usb-ccid-experimental")]
        ccid,
    }
}

#[embassy_executor::task]
/// Sole device runner; frontend tasks own their class endpoints separately.
pub(super) async fn multi_usb_device_task(
    mut usb: embassy_usb::UsbDevice<'static, Driver<'static, peripherals::USB>>,
) {
    usb.run().await;
}
