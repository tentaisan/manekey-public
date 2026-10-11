use crate::mailbox::build_ctaphid_frontend;
#[cfg(feature = "usb-ble-multi")]
use crate::multi_transport::MultiUsbFrontend;
use esp_hal::usb::otg::embassy_usb_device::Driver;
use manekey::{
    boundary::mailbox::MailboxEndpoint,
    ctaphid::{
        descriptor::CtaphidUsbDeviceInfo,
        trusted::{TRUSTED_REQUEST_MAX, TRUSTED_RESPONSE_MAX},
    },
};

/// Cooperative HID/mailbox adapter; caller supplies authorized USB identity and serialized endpoint ownership.
pub async fn run_esp32s3_ctaphid_usb(
    driver: Driver<'static>,
    endpoint: &'static MailboxEndpoint<TRUSTED_REQUEST_MAX, TRUSTED_RESPONSE_MAX>,
    identity: &CtaphidUsbDeviceInfo,
) -> ! {
    crate::usb_hid::run_esp_usb_hid(driver, build_ctaphid_frontend(endpoint), identity).await
}

#[cfg(feature = "usb-ble-multi")]
pub async fn run_esp32s3_ctaphid_usb_multi(
    driver: Driver<'static>,
    app: &mut MultiUsbFrontend,
    identity: &CtaphidUsbDeviceInfo,
    #[cfg(feature = "usb-ccid-experimental")]
    buffers: &'static mut crate::usb_composite::CcidIoBuffers,
) -> ! {
    crate::usb_composite::run_esp_usb_ingress(
        driver,
        app,
        identity,
        cfg!(feature = "usb-ccid-experimental"),
        #[cfg(feature = "usb-ccid-experimental")]
        buffers,
    )
    .await
}
