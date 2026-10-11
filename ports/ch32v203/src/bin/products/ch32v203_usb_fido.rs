#![no_std]
#![no_main]

use ch32_hal as hal;
use embassy_futures::join::join;
#[cfg(feature = "dual-task")]
use embassy_futures::select::{Either, select};
#[cfg(feature = "dual-task")]
use embassy_time::Timer;
use embassy_usb::Builder;
use embassy_usb::class::hid::{Config as HidConfig, HidReaderWriter, ReadError, State as HidState};
#[cfg(feature = "up-gpio-pa0")]
use hal::gpio::{Input, Pull};
use hal::rcc;
use hal::usbd::Driver;
use hal::{bind_interrupts, peripherals};
use manekey::ctaphid::{
    HidCtaphidApp,
    descriptor::{
        POLL_MS as CTAPHID_POLL_MS, REPORT_DESCRIPTOR as CTAPHID_REPORT_DESCRIPTOR,
        REPORT_SIZE as CTAPHID_REPORT_SIZE, REPORT_SIZE_U16 as CTAPHID_REPORT_SIZE_U16,
    },
};
#[cfg(feature = "dual-task")]
use manekey_ch32v203::fido::{
    Ch32LocalTrustedWorker, Ch32MailboxEndpoint, SelectedCtaphid, selected_ctaphid,
    selected_dispatcher,
};
#[cfg(not(feature = "dual-task"))]
use manekey_ch32v203::fido::{SelectedCtaphid, selected_ctaphid};
use manekey_ch32v203::product::{selected_product_string, selected_serial_string};
use manekey_ch32v203::usb_hid::{ctaphid_usb_config, write_response};
use panic_halt as _;

#[cfg(feature = "dual-task")]
static MAILBOX_ENDPOINT: Ch32MailboxEndpoint = Ch32MailboxEndpoint::new();

#[cfg(not(feature = "dual-task"))]
static mut CTAPHID: SelectedCtaphid = selected_ctaphid();

#[cfg(feature = "dual-task")]
static mut TRUSTED_WORKER: Ch32LocalTrustedWorker =
    Ch32LocalTrustedWorker::new(selected_dispatcher());

#[cfg(feature = "dual-task")]
static mut CTAPHID: SelectedCtaphid = selected_ctaphid(&MAILBOX_ENDPOINT);

bind_interrupts!(struct Irqs {
    USB_LP_CAN1_RX0 => hal::usbd::InterruptHandler<peripherals::USBD>;
});

#[embassy_executor::main(entry = "qingke_rt::entry")]
/// Cooperative HID/worker product, not hardware isolation; exclusively own static frontend/worker and IRQ state.
/// Entropy remains experimental; caller supplies authorized USB identity.
async fn main(_spawner: embassy_executor::Spawner) {
    let mut rcc_config = rcc::Config::SYSCLK_FREQ_144MHZ_HSI;
    #[cfg(feature = "experimental-adc-entropy")]
    {
        rcc_config.apb2_pre = hal::pac::rcc::vals::Ppre::DIV2;
    }
    let p = hal::init(hal::Config {
        rcc: rcc_config,
        ..Default::default()
    });
    #[cfg(feature = "experimental-adc-entropy")]
    let _adc_owner = manekey_ch32v203::entropy::initialize(p.ADC1).unwrap();

    #[cfg(feature = "up-gpio-pa0")]
    let _pa0_button = Input::new(p.PA0, Pull::Up);

    let driver = Driver::new(p.USBD, Irqs, p.PA12, p.PA11);

    let config = ctaphid_usb_config(selected_product_string(), selected_serial_string());

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

    let hid_config = HidConfig {
        hid_subclass: embassy_usb::class::hid::HidSubclass::No,
        hid_boot_protocol: embassy_usb::class::hid::HidBootProtocol::None,
        report_descriptor: CTAPHID_REPORT_DESCRIPTOR,
        request_handler: None,
        poll_ms: CTAPHID_POLL_MS,
        max_packet_size: CTAPHID_REPORT_SIZE_U16,
    };
    let hid = HidReaderWriter::<_, CTAPHID_REPORT_SIZE, CTAPHID_REPORT_SIZE>::new(
        &mut builder,
        &mut hid_state,
        hid_config,
    );
    let mut usb = builder.build();

    let usb_fut = usb.run();
    #[cfg(not(feature = "dual-task"))]
    let hid_fut = async {
        let mut hid = hid;
        let mut report = [0u8; CTAPHID_REPORT_SIZE];
        loop {
            hid.ready().await;
            match hid.read(&mut report).await {
                Ok(CTAPHID_REPORT_SIZE) => {
                    let ctaphid = unsafe { &mut *core::ptr::addr_of_mut!(CTAPHID) };
                    if let Some(response) = ctaphid.handle_hid_report(report) {
                        let _ = write_response(&mut hid, response).await;
                    }
                    if let Some(response) = ctaphid.poll_hid() {
                        let _ = write_response(&mut hid, response).await;
                    }
                }
                Ok(_) => {}
                Err(ReadError::Disabled) => {}
                Err(_) => {}
            }
        }
    };
    #[cfg(feature = "dual-task")]
    let hid_fut = async {
        let mut hid = hid;
        let mut report = [0u8; CTAPHID_REPORT_SIZE];
        loop {
            hid.ready().await;
            let response = match select(hid.read(&mut report), Timer::after_millis(100)).await {
                Either::First(Ok(CTAPHID_REPORT_SIZE)) => {
                    let ctaphid = unsafe { &mut *core::ptr::addr_of_mut!(CTAPHID) };
                    ctaphid.handle_hid_report(report)
                }
                Either::First(Ok(_)) | Either::First(Err(ReadError::Disabled)) => continue,
                Either::First(Err(_)) => continue,
                Either::Second(()) => {
                    let ctaphid = unsafe { &mut *core::ptr::addr_of_mut!(CTAPHID) };
                    ctaphid.poll_hid()
                }
            };

            if let Some(response) = response {
                let _ = write_response(&mut hid, response).await;
            }
        }
    };
    #[cfg(feature = "dual-task")]
    let trusted_fut = async {
        loop {
            pump_trusted_worker();
            Timer::after_millis(5).await;
        }
    };

    #[cfg(not(feature = "dual-task"))]
    join(usb_fut, hid_fut).await;
    #[cfg(feature = "dual-task")]
    join(usb_fut, join(hid_fut, trusted_fut)).await;
}

#[cfg(feature = "dual-task")]
fn pump_trusted_worker() {
    unsafe { &mut *core::ptr::addr_of_mut!(TRUSTED_WORKER) }.pump(&MAILBOX_ENDPOINT);
}
