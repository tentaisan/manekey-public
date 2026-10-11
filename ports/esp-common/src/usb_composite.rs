use embassy_futures::join::join;
use embassy_usb::{
    Builder,
    class::hid::{Config as HidConfig, HidReaderWriter, State as HidState},
};
use esp_hal::usb::otg::embassy_usb_device::Driver;
use manekey::ctaphid::{
    descriptor::{CtaphidUsbDeviceInfo, POLL_MS, REPORT_DESCRIPTOR, REPORT_SIZE},
    trusted::TrustedBackend,
};
#[cfg(feature = "usb-ccid-experimental")]
pub use manekey::transport::usb::embassy::CcidIoBuffers;
#[cfg(feature = "usb-ccid-experimental")]
use manekey::transport::usb::embassy::run_ccid_ingress_loop as run_ccid_loop;
use manekey::transport::usb::embassy::run_hid_ingress_loop as run_hid_loop;
#[cfg(feature = "usb-ccid-experimental")]
use manekey::{
    frontend::ccid::CCID_RESPONSE_MAX,
    transport::usb::embassy::{CcidUsbClass, CcidUsbState},
};
use static_cell::StaticCell;

use crate::usb_ingress::UsbIngressFrontend;

#[cfg(feature = "usb-ccid-experimental")]
static CCID_STATE: StaticCell<CcidUsbState<'static>> = StaticCell::new();

/// Initialize once per boot; StaticCell reuse may panic. Caller supplies authorized USB identity.
/// Cooperative HID/optional CCID share the arbiter, not hardware isolation.
pub async fn run_esp_usb_ingress<T: TrustedBackend + 'static>(
    driver: Driver<'static>,
    app: &mut UsbIngressFrontend<T>,
    identity: &CtaphidUsbDeviceInfo,
    #[allow(unused_variables)] with_ccid: bool,
    #[cfg(feature = "usb-ccid-experimental")] buffers: &'static mut CcidIoBuffers,
) -> ! {
    let mut config = embassy_usb::Config::new(identity.vendor_id, identity.product_id);
    config.manufacturer = Some(identity.manufacturer);
    config.product = Some(identity.product);
    config.serial_number = identity.serial_number;

    static CONFIG_DESCRIPTOR: StaticCell<[u8; 256]> = StaticCell::new();
    static BOS_DESCRIPTOR: StaticCell<[u8; 256]> = StaticCell::new();
    static CONTROL_BUF: StaticCell<[u8; 128]> = StaticCell::new();
    static HID_STATE: StaticCell<HidState> = StaticCell::new();
    let mut builder = Builder::new(
        driver,
        config,
        CONFIG_DESCRIPTOR.init([0; 256]),
        BOS_DESCRIPTOR.init([0; 256]),
        &mut [],
        CONTROL_BUF.init([0; 128]),
    );
    let hid = HidReaderWriter::<_, REPORT_SIZE, REPORT_SIZE>::new(
        &mut builder,
        HID_STATE.init(HidState::new()),
        HidConfig {
            report_descriptor: REPORT_DESCRIPTOR,
            request_handler: None,
            poll_ms: POLL_MS,
            max_packet_size: REPORT_SIZE as u16,
            hid_subclass: embassy_usb::class::hid::HidSubclass::No,
            hid_boot_protocol: embassy_usb::class::hid::HidBootProtocol::None,
        },
    );
    #[cfg(feature = "usb-ccid-experimental")]
    if with_ccid {
        let ccid = CcidUsbClass::new(
            &mut builder,
            CCID_STATE.init(CcidUsbState::new()),
            REPORT_SIZE as u16,
            CCID_RESPONSE_MAX as u32,
        );
        let mut usb = builder.build();
        let arbiter = app.arbiter();
        join(
            usb.run(),
            join(
                run_hid_loop(hid, app),
                run_ccid_loop(
                    ccid,
                    crate::usb_ingress::EspUsbArbiterAccess(arbiter),
                    buffers,
                ),
            ),
        )
        .await;
    } else {
        let mut usb = builder.build();
        join(usb.run(), run_hid_loop(hid, app)).await;
    }
    #[cfg(not(feature = "usb-ccid-experimental"))]
    {
        let mut usb = builder.build();
        join(usb.run(), run_hid_loop(hid, app)).await;
    }
    unreachable!()
}
