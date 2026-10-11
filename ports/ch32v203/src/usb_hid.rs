use embassy_usb::class::hid::HidReaderWriter;
use manekey::ctaphid::{
    Response,
    descriptor::{
        CtaphidUsbDeviceInfo, REPORT_SIZE as CTAPHID_REPORT_SIZE,
        REPORT_SIZE_U8 as CTAPHID_REPORT_SIZE_U8,
    },
    framing::{message_reports, response_reports},
};

/// Caller supplies authorized USB identity; this does not initialize or own the physical USB driver.
pub fn ctaphid_usb_config(
    product: &'static str,
    serial_number: &'static str,
) -> embassy_usb::Config<'static> {
    let identity = CtaphidUsbDeviceInfo::new(product, serial_number);
    let mut config = embassy_usb::Config::new(identity.vendor_id, identity.product_id);
    config.manufacturer = Some(identity.manufacturer);
    config.product = Some(identity.product);
    config.serial_number = identity.serial_number;
    config.max_power = 100;
    config.max_packet_size_0 = CTAPHID_REPORT_SIZE_U8;
    config
}

/// Sequential report writes; transport acceptance is not peer delivery acknowledgment.
pub async fn write_response<'d, D: embassy_usb::driver::Driver<'d>>(
    hid: &mut HidReaderWriter<'d, D, CTAPHID_REPORT_SIZE, CTAPHID_REPORT_SIZE>,
    response: Response<'_>,
) -> Result<(), ()> {
    for report in response_reports(response) {
        hid.write(&report).await.map_err(|_| ())?;
    }

    Ok(())
}

/// Sequential report writes; failure can leave a partially sent message.
pub async fn write_message<'d, D: embassy_usb::driver::Driver<'d>>(
    hid: &mut HidReaderWriter<'d, D, CTAPHID_REPORT_SIZE, CTAPHID_REPORT_SIZE>,
    cid: u32,
    cmd: u8,
    data: &[u8],
) -> Result<(), ()> {
    for report in message_reports(cid, cmd, data) {
        hid.write(&report).await.map_err(|_| ())?;
    }

    Ok(())
}
