#![no_std]
#![no_main]

use cortex_m_rt::entry;
use defmt_rtt as _;
use manekey::ctaphid::{
    CtaphidFrontend, HidCtaphidApp,
    descriptor::{
        CtaphidUsbDeviceInfo, POLL_MS as CTAPHID_POLL_MS, REPORT_SIZE as CTAPHID_REPORT_SIZE,
    },
    entropy::{EntropyError, HmacDrbgEntropy},
    trusted::TrustedDispatcher,
    user_verification::UnavailableUserVerification,
};
use manekey::presence::TextPresenceObserver;
use manekey::transport;
use nrf_usbd::Usbd;
#[cfg(feature = "client-pin-volatile")]
use nrf52840::board::start_lfclk;
use nrf52840::board::{
    blink_stage, bootloader_settle_delay, init_led, led_off, start_hfclk, uart_init,
    uart_write_str, uart_write_u32,
};
use nrf52840::entropy::NrfRngEntropy;
#[cfg(not(feature = "nrf-dual-task"))]
use nrf52840::fido::NrfCtaphid;
#[cfg(feature = "nrf-dual-task")]
use nrf52840::fido::{NRF_MAILBOX, NrfCtaphid, NrfLocalTrustedWorker, local_mailbox_backend};
use nrf52840::fido::{NrfDispatcher, selected_crypto_backends};
use nrf52840::presence::{
    SelectedUserPresence, USB_UP_TIMEOUT_POLLS, configure_selected_user_presence,
    selected_user_presence,
};

use nrf52840::storage::selected_storage;
use nrf52840::usb_hid::{CtapHidClass, NrfUsbd, write_response};
use nrf52840_pac::{FICR, NVMC, Peripherals, RNG, RTC1};
use panic_halt as _;
use static_cell::StaticCell;
use usb_device::{
    UsbError,
    bus::UsbBusAllocator,
    device::{StringDescriptors, UsbDeviceBuilder, UsbVidPid},
};

const CTAPHID_POLL_INTERVAL_LOOPS: u32 = 10_000;

fn build_dispatcher(
    nvmc: NVMC,
    rng: RNG,
    ficr: FICR,
    rtc1: RTC1,
) -> Result<NrfDispatcher<SelectedUserPresence, TextPresenceObserver>, EntropyError> {
    let mut entropy = HmacDrbgEntropy::new(NrfRngEntropy::new(rng))?;
    let mut records = selected_storage(nvmc, uart_write_str);
    let (key_store, pin_uv_auth) =
        selected_crypto_backends(ficr, rtc1, uart_write_str, &mut records, &mut entropy);
    Ok(
        TrustedDispatcher::new_with_transports_and_presence_observer(
            records,
            selected_user_presence(uart_write_str, true, USB_UP_TIMEOUT_POLLS),
            UnavailableUserVerification,
            pin_uv_auth,
            key_store,
            entropy,
            transport::USB_TRANSPORTS,
            TextPresenceObserver::new(uart_write_str),
        ),
    )
}

#[entry]
/// Single-owner HID product with direct peripheral ownership; SoftDevice must remain disabled.
/// Local worker selection is not hardware isolation; loop-based polling is not a wall-clock deadline.
fn main() -> ! {
    let peripherals = Peripherals::take().unwrap();
    init_led(&peripherals);
    uart_init();
    uart_write_str("nrf52840 usb fido boot\r\n");
    configure_selected_user_presence(uart_write_str);
    blink_stage(1);

    start_hfclk(&peripherals);
    uart_write_str("hfclk started\r\n");
    #[cfg(feature = "client-pin-volatile")]
    {
        start_lfclk(&peripherals);
        uart_write_str("lfclk started for client-pin token clock\r\n");
    }
    blink_stage(2);
    bootloader_settle_delay();

    static USB_BUS: StaticCell<UsbBusAllocator<Usbd<NrfUsbd>>> = StaticCell::new();
    let usb_bus = USB_BUS.init(UsbBusAllocator::new(Usbd::new(NrfUsbd(peripherals.USBD))));
    let mut hid = CtapHidClass::new_with_logger(usb_bus, CTAPHID_POLL_MS, uart_write_str);
    let identity = CtaphidUsbDeviceInfo::new("ManeKey nRF52840 USB FIDO", "nrf52840-usb-fido");
    let mut usb_dev =
        UsbDeviceBuilder::new(usb_bus, UsbVidPid(identity.vendor_id, identity.product_id))
            .strings(&[StringDescriptors::default()
                .manufacturer(identity.manufacturer)
                .product(identity.product)
                .serial_number(identity.serial_number.unwrap_or(""))])
            .unwrap()
            .build();
    let _ = usb_dev.force_reset();

    #[cfg(not(feature = "nrf-dual-task"))]
    static CTAPHID: StaticCell<NrfCtaphid<SelectedUserPresence, TextPresenceObserver>> =
        StaticCell::new();
    #[cfg(feature = "nrf-dual-task")]
    static CTAPHID: StaticCell<NrfCtaphid> = StaticCell::new();
    let dispatcher = match build_dispatcher(
        peripherals.NVMC,
        peripherals.RNG,
        peripherals.FICR,
        peripherals.RTC1,
    ) {
        Ok(dispatcher) => dispatcher,
        Err(_) => {
            uart_write_str("rng init failed\r\n");
            loop {
                blink_stage(9);
            }
        }
    };

    #[cfg(feature = "nrf-dual-task")]
    static WORKER: StaticCell<
        NrfLocalTrustedWorker<NrfDispatcher<SelectedUserPresence, TextPresenceObserver>>,
    > = StaticCell::new();
    #[cfg(feature = "nrf-dual-task")]
    let worker = WORKER.init(NrfLocalTrustedWorker::new(dispatcher));

    #[cfg(not(feature = "nrf-dual-task"))]
    let ctaphid = CTAPHID.init(CtaphidFrontend::with_trusted_backend(dispatcher));

    #[cfg(feature = "nrf-dual-task")]
    let ctaphid = CTAPHID.init(CtaphidFrontend::with_trusted_backend(
        local_mailbox_backend(),
    ));

    uart_write_str("usb fido built; entering poll loop\r\n");
    #[cfg(feature = "nrf-dual-task")]
    uart_write_str("boundary=nrf-local-mailbox\r\n");
    blink_stage(3);
    led_off();

    let mut report = [0u8; CTAPHID_REPORT_SIZE];
    let mut poll_countdown = CTAPHID_POLL_INTERVAL_LOOPS;
    loop {
        if usb_dev.poll(&mut [&mut hid]) {
            match hid.read(&mut report) {
                Ok(CTAPHID_REPORT_SIZE) => {
                    uart_write_str("hid out\r\n");
                    if let Some(response) = ctaphid.handle_hid_report(report) {
                        write_response(&mut usb_dev, &mut hid, response);
                    }
                    #[cfg(feature = "nrf-dual-task")]
                    let _ = worker.pump_once(&NRF_MAILBOX);
                }
                Ok(len) => {
                    uart_write_str("hid short=");
                    uart_write_u32(len as u32);
                    uart_write_str("\r\n");
                }
                Err(UsbError::WouldBlock) => {}
                Err(_) => {
                    uart_write_str("hid read error\r\n");
                }
            }
        }

        poll_countdown = poll_countdown.saturating_sub(1);
        if poll_countdown == 0 {
            poll_countdown = CTAPHID_POLL_INTERVAL_LOOPS;
            #[cfg(feature = "nrf-dual-task")]
            let _ = worker.pump_once(&NRF_MAILBOX);
            if let Some(response) = ctaphid.poll_hid() {
                uart_write_str("ctaphid poll response\r\n");
                write_response(&mut usb_dev, &mut hid, response);
            }
            #[cfg(feature = "nrf-dual-task")]
            let _ = worker.pump_once(&NRF_MAILBOX);
        }
    }
}
