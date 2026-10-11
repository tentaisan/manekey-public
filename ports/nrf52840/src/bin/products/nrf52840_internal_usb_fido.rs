#![no_std]
#![no_main]
use cortex_m_rt::entry;
use manekey::{
    ctaphid::{
        entropy::HmacDrbgEntropy,
        trusted::{TRUSTED_RESPONSE_MAX, TrustedDispatcher},
        user_verification::UnavailableUserVerification,
    },
    frontend::{
        ingress::IngressArbiter,
        internal::{InterconnectCtap2Frontend, InterconnectCtap2Outcome},
    },
    presence::NoPresenceObserver,
    transport,
};
use nrf_usbd::Usbd;
use nrf52840::{
    board,
    entropy::NrfRngEntropy,
    fido::selected_crypto_backends,
    internal_uart,
    presence::{configure_selected_user_presence, selected_user_presence},
    storage::selected_storage,
    usb_ccid::CcidUsbClass,
    usb_hid::{CtapHidClass, NrfUsbd},
    usb_ingress,
};
use static_cell::StaticCell;
use usb_device::{
    bus::UsbBusAllocator,
    device::{StringDescriptors, UsbDeviceBuilder, UsbVidPid},
};
type Dispatcher = nrf52840::fido::NrfDispatcher<nrf52840::presence::SelectedUserPresence>;
#[cfg(not(feature = "nrf-dual-task"))]
type Backend = Dispatcher;
#[cfg(feature = "nrf-dual-task")]
type Backend = nrf52840::fido::NrfLocalMailboxBackend;
#[cfg(feature = "nrf-dual-task")]
static WORKER: StaticCell<nrf52840::fido::NrfLocalTrustedWorker<Dispatcher>> = StaticCell::new();
struct Runtime {
    arbiter: &'static mut IngressArbiter<Backend>,
    #[cfg(feature = "nrf-dual-task")]
    worker: &'static mut nrf52840::fido::NrfLocalTrustedWorker<Dispatcher>,
}

#[inline(never)]
fn initialize_backend(
    nvmc: nrf52840_pac::NVMC,
    rng: nrf52840_pac::RNG,
    ficr: nrf52840_pac::FICR,
    rtc1: nrf52840_pac::RTC1,
) -> Runtime {
    let mut records = selected_storage(nvmc, board::uart_write_str);
    let mut entropy = HmacDrbgEntropy::new(NrfRngEntropy::new(rng)).unwrap();
    let (keys, pin) = selected_crypto_backends(
        ficr,
        rtc1,
        board::uart_write_str,
        &mut records,
        &mut entropy,
    );
    let dispatcher = TrustedDispatcher::new_with_transports_and_presence_observer(
        records,
        selected_user_presence(board::uart_write_str, true, 480),
        UnavailableUserVerification,
        pin,
        keys,
        entropy,
        transport::USB_TRANSPORTS,
        NoPresenceObserver,
    );
    #[cfg(feature = "nrf-dual-task")]
    let worker = WORKER.init(nrf52840::fido::NrfLocalTrustedWorker::new(dispatcher));
    #[cfg(feature = "nrf-dual-task")]
    let backend = nrf52840::fido::local_mailbox_backend();
    #[cfg(not(feature = "nrf-dual-task"))]
    let backend = dispatcher;
    static ARBITER: StaticCell<IngressArbiter<Backend>> = StaticCell::new();
    Runtime {
        arbiter: ARBITER.init(IngressArbiter::new(backend)),
        #[cfg(feature = "nrf-dual-task")]
        worker,
    }
}
#[inline(never)]
fn initialize_frontend() -> (
    &'static mut usb_ingress::UsbIngress,
    &'static mut [u8; TRUSTED_RESPONSE_MAX + 32],
) {
    static FRONTEND: StaticCell<usb_ingress::UsbIngress> = StaticCell::new();
    static RESPONSE: StaticCell<[u8; TRUSTED_RESPONSE_MAX + 32]> = StaticCell::new();
    (
        FRONTEND.init(usb_ingress::UsbIngress::new()),
        RESPONSE.init([0; TRUSTED_RESPONSE_MAX + 32]),
    )
}
#[entry]
/// Single-owner UART/HID/CCID product; initialize static state once and reserve peripheral/IRQ ownership.
/// Local worker selection is cooperative, not hardware isolation; supply authorized USB identity.
fn main() -> ! {
    unsafe {
        (*cortex_m::peripheral::SCB::PTR)
            .vtor
            .write(board::BOARD.app_flash_origin);
    }
    let p = nrf52840_pac::Peripherals::take().unwrap();
    board::init_led(&p);
    board::uart_init();
    board::start_hfclk(&p);
    board::start_lfclk(&p);
    board::uart_write_str("nRF52840 Internal/HID/CCID boot\r\n");
    configure_selected_user_presence(board::uart_write_str);
    usb_ingress::start_clock(p.RTC2);
    let runtime = initialize_backend(p.NVMC, p.RNG, p.FICR, p.RTC1);
    let arbiter = runtime.arbiter;
    #[cfg(feature = "nrf-dual-task")]
    let worker = runtime.worker;
    static BUS: StaticCell<UsbBusAllocator<Usbd<NrfUsbd>>> = StaticCell::new();
    nrf52840::usb_hid::release_bootloader_usb(&p.USBD);
    let bus = BUS.init(UsbBusAllocator::new(Usbd::new(NrfUsbd(p.USBD))));
    let mut hid = CtapHidClass::new(bus, 5);
    let mut ccid = CcidUsbClass::new(bus, manekey::frontend::ccid::CCID_RESPONSE_MAX as u32);
    let mut usb = UsbDeviceBuilder::new(bus, UsbVidPid(0xcafe, 0x4011))
        .strings(&[StringDescriptors::default()
            .manufacturer("ManeKey")
            .product("ManeKey nRF52840 Internal")
            .serial_number("nrf52840-internal")])
        .unwrap()
        .build();
    let _ = usb.force_reset();
    let (front, response) = initialize_frontend();
    let mut internal = InterconnectCtap2Frontend::<{ TRUSTED_RESPONSE_MAX + 32 }>::new(0);

    board::uart_write_str("Internal binary ready\r\n");
    internal_uart::start();

    loop {
        #[cfg(feature = "nrf-dual-task")]
        let _ = worker.pump_once(&nrf52840::fido::NRF_MAILBOX);
        front.poll(
            arbiter,
            &mut usb,
            &mut hid,
            &mut ccid,
            usb_ingress::now_ms(),
        );
        let _ = internal.poll_cancel(arbiter);
        if internal_uart::take_overflow() {
            internal.disconnect(arbiter);
        }
        for _ in 0..64 {
            let Some(byte) = internal_uart::read() else {
                break;
            };
            if !internal.is_receiving() {}
            match internal.push_byte(arbiter, byte, response) {
                Ok(Some(InterconnectCtap2Outcome::Response { len })) => {
                    internal_uart::write(&response[..len])
                }
                Err(_) => internal.disconnect(arbiter),
                _ => {}
            }
        }
    }
}
#[panic_handler]
fn panic(_: &core::panic::PanicInfo<'_>) -> ! {
    loop {
        cortex_m::interrupt::disable();
        cortex_m::asm::wfi();
    }
}

#[cortex_m_rt::exception]
unsafe fn HardFault(frame: &cortex_m_rt::ExceptionFrame) -> ! {
    {
        let _ = frame;
        loop {
            cortex_m::interrupt::disable();
            cortex_m::asm::wfi();
        }
    }
}
