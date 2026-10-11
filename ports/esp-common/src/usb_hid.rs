use embassy_futures::{
    join::join,
    select::{Either, select},
};
use embassy_time::Timer;
use embassy_usb::{
    Builder,
    class::hid::{Config as HidConfig, HidReaderWriter, ReadError, State as HidState},
};
use esp_hal::usb::otg::embassy_usb_device::Driver;
use esp_println::println;
use manekey::{
    ctaphid::HidCtaphidApp,
    ctaphid::Response,
    ctaphid::descriptor::{
        CtaphidUsbDeviceInfo, POLL_MS as CTAPHID_POLL_MS,
        REPORT_DESCRIPTOR as CTAPHID_REPORT_DESCRIPTOR, REPORT_SIZE as CTAPHID_REPORT_SIZE,
    },
    ctaphid::framing::response_reports,
};

const CTAPHID_POLL_INTERVAL_MS: u64 = 100;

/// Caller supplies authorized USB identity and app; failed report writes stop that response without delivery acknowledgment.
pub async fn run_esp_usb_hid<A: HidCtaphidApp>(
    driver: Driver<'static>,
    mut app: A,
    identity: &CtaphidUsbDeviceInfo,
) -> ! {
    let mut config = embassy_usb::Config::new(identity.vendor_id, identity.product_id);
    config.manufacturer = Some(identity.manufacturer);
    config.product = Some(identity.product);
    config.serial_number = identity.serial_number;

    let mut config_descriptor = [0; 256];
    let mut bos_descriptor = [0; 256];
    let mut control_buf = [0; 128];
    let mut hid_state = HidState::new();
    let mut builder = Builder::new(
        driver,
        config,
        &mut config_descriptor,
        &mut bos_descriptor,
        &mut [],
        &mut control_buf,
    );
    let hid = HidReaderWriter::<_, CTAPHID_REPORT_SIZE, CTAPHID_REPORT_SIZE>::new(
        &mut builder,
        &mut hid_state,
        HidConfig {
            report_descriptor: CTAPHID_REPORT_DESCRIPTOR,
            request_handler: None,
            poll_ms: CTAPHID_POLL_MS,
            max_packet_size: CTAPHID_REPORT_SIZE as u16,
            hid_subclass: embassy_usb::class::hid::HidSubclass::No,
            hid_boot_protocol: embassy_usb::class::hid::HidBootProtocol::None,
        },
    );
    let mut usb = builder.build();
    join(usb.run(), run_hid_loop(hid, &mut app)).await;
    unreachable!()
}

async fn run_hid_loop<'d, D, A>(
    mut hid: HidReaderWriter<'d, D, CTAPHID_REPORT_SIZE, CTAPHID_REPORT_SIZE>,
    app: &mut A,
) -> !
where
    D: embassy_usb::driver::Driver<'d>,
    A: HidCtaphidApp,
{
    let mut report = [0u8; CTAPHID_REPORT_SIZE];
    loop {
        hid.ready().await;
        let response = match select(
            hid.read(&mut report),
            Timer::after_millis(CTAPHID_POLL_INTERVAL_MS),
        )
        .await
        {
            Either::First(Ok(CTAPHID_REPORT_SIZE)) => {
                println!("hid out report len={CTAPHID_REPORT_SIZE}");
                app.handle_hid_report(report)
            }
            Either::First(Ok(_)) | Either::First(Err(ReadError::Disabled)) => continue,
            Either::First(Err(_)) => continue,
            Either::Second(()) => app.poll_hid(),
        };
        if let Some(response) = response {
            write_response(&mut hid, response).await;
        }
    }
}

async fn write_response<'d, D>(
    hid: &mut HidReaderWriter<'d, D, CTAPHID_REPORT_SIZE, CTAPHID_REPORT_SIZE>,
    response: Response<'_>,
) where
    D: embassy_usb::driver::Driver<'d>,
{
    for report in response_reports(response) {
        if hid.write(&report).await.is_err() {
            break;
        }
    }
}
