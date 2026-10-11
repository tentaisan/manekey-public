#![no_std]
#![no_main]

use core::cell::RefCell;

use defmt::*;
use defmt_rtt as _;
use embassy_executor::Spawner;
#[cfg(feature = "dual-core-transport")]
use embassy_rp::multicore::Stack;
use embassy_rp::usb::{Driver, InterruptHandler};
use embassy_rp::{bind_interrupts, peripherals};
use embassy_sync::blocking_mutex::Mutex;
#[cfg(feature = "single-core-task-transport")]
use manekey::boundary::mailbox::LocalMailboxTransport;
#[cfg(any(
    feature = "single-core-task-transport",
    feature = "dual-core-transport"
))]
use manekey::boundary::mailbox::MailboxEndpoint;
#[cfg(any(
    feature = "single-core-task-transport",
    feature = "dual-core-transport"
))]
use manekey::boundary::mailbox_backend::MailboxTrustedBackend;
#[cfg(feature = "dual-core-transport")]
use manekey::boundary::storage_mailbox::{
    CORE0_FLASH_REQUEST_MAX, CORE0_FLASH_RESPONSE_MAX, Core0FlashService,
};
use manekey::ctaphid::trusted::TrustedDispatcher;
#[cfg(any(
    feature = "single-core-task-transport",
    feature = "dual-core-transport"
))]
use manekey::ctaphid::trusted::{TRUSTED_REQUEST_MAX, TRUSTED_RESPONSE_MAX};
use manekey::frontend::ingress::IngressArbiter;
#[cfg(feature = "dual-core-transport")]
use manekey_rp::platform::rp::mailbox::PollingMailboxTransport;
use manekey_rp::platform::rp::storage::SharedRpFlash;
#[cfg(feature = "dual-core-transport")]
use manekey_rp::platform::rp::storage::{SharedFlashStorage, SharedPinUvAuthFlashStorage};
#[cfg(feature = "dual-core-transport")]
use manekey_rp::platform::rp::storage_mailbox::Core0FlashServiceExt;
use panic_probe as _;
use static_cell::StaticCell;

#[cfg(feature = "rp-ml-dsa-credential-experimental")]
#[path = "rp_ml_dsa_experimental.rs"]
mod rp_ml_dsa_experimental;
#[path = "rp_usb_fido_common.rs"]
mod rp_usb_fido_common;

#[cfg(feature = "rp-internal-uart")]
mod rp_internal_uart;
#[cfg(feature = "rp-internal-uart")]
type InternalUart = embassy_rp::uart::BufferedUart;
#[cfg(all(
    feature = "rp-internal-uart",
    not(any(
        feature = "single-core-task-transport",
        feature = "dual-core-transport"
    ))
))]
type SharedArbiter = rp_usb_fido_common::SharedDirectIngressArbiter;
#[cfg(all(
    feature = "rp-internal-uart",
    any(
        feature = "single-core-task-transport",
        feature = "dual-core-transport"
    )
))]
type SharedArbiter = rp_usb_fido_common::SharedMailboxIngressArbiter;

bind_interrupts!(struct Irqs {
    USBCTRL_IRQ => InterruptHandler<peripherals::USB>;
    #[cfg(feature = "chip-rp235xa")]
    TRNG_IRQ => embassy_rp::trng::InterruptHandler<peripherals::TRNG>;
    #[cfg(feature = "rp-internal-uart")]
    UART0_IRQ => embassy_rp::uart::BufferedInterruptHandler<peripherals::UART0>;
});

#[cfg(not(any(
    feature = "single-core-task-transport",
    feature = "dual-core-transport"
)))]
static ARBITER: StaticCell<rp_usb_fido_common::SharedDirectIngressArbiter> = StaticCell::new();
#[cfg(any(
    feature = "single-core-task-transport",
    feature = "dual-core-transport"
))]
static ENDPOINT: MailboxEndpoint<TRUSTED_REQUEST_MAX, TRUSTED_RESPONSE_MAX> =
    MailboxEndpoint::new();
#[cfg(feature = "dual-core-transport")]
static FLASH_ENDPOINT: MailboxEndpoint<CORE0_FLASH_REQUEST_MAX, CORE0_FLASH_RESPONSE_MAX> =
    MailboxEndpoint::new();
#[cfg(any(
    feature = "single-core-task-transport",
    feature = "dual-core-transport"
))]
static DISPATCHER: StaticCell<rp_usb_fido_common::SelectedTrustedDispatcher> = StaticCell::new();
#[cfg(any(
    feature = "single-core-task-transport",
    feature = "dual-core-transport"
))]
static ARBITER: StaticCell<rp_usb_fido_common::SharedMailboxIngressArbiter> = StaticCell::new();
#[cfg(feature = "dual-core-transport")]
const CORE1_STACK_SIZE: usize = rp_usb_fido_common::DUAL_CORE_WORKER_STACK_SIZE;
#[cfg(feature = "dual-core-transport")]
static mut CORE1_STACK: Stack<CORE1_STACK_SIZE> = Stack::new();

#[embassy_executor::main]
/// Initialize once with reserved journals and exclusive USB/UART/Flash ownership.
/// Start the core0 Flash service before core1 opens managed keys; local/dual workers alone are not memory isolation.
async fn main(spawner: Spawner) {
    #[cfg(feature = "rp-ml-dsa-credential-experimental")]
    rp_ml_dsa_experimental::initialize();
    #[cfg(feature = "chip-rp235xa")]
    manekey_rp::platform::rp2350::arm_security::configure_rp2350_normal_access();
    let p = embassy_rp::init(Default::default());
    #[cfg(feature = "rp-internal-uart")]
    let uart = {
        static TX: StaticCell<[u8; 256]> = StaticCell::new();
        static RX: StaticCell<[u8; 1024]> = StaticCell::new();
        embassy_rp::uart::BufferedUart::new(
            p.UART0,
            p.PIN_0,
            p.PIN_1,
            Irqs,
            TX.init([0; 256]),
            RX.init([0; 1024]),
            Default::default(),
        )
    };
    let driver = Driver::new(p.USB, Irqs);
    let flash = embassy_rp::flash::Flash::new_blocking(p.FLASH);
    static FLASH: StaticCell<SharedRpFlash<'static>> = StaticCell::new();
    let flash: &'static SharedRpFlash<'static> =
        FLASH.init(SharedRpFlash::new(RefCell::new(flash)));
    #[cfg(all(feature = "dual-core-transport", feature = "up-bootsel-experimental"))]
    spawner.spawn(
        manekey_rp::platform::rp::user_interface::sample_bootsel_on_core0(p.BOOTSEL).unwrap(),
    );
    #[cfg(all(feature = "board-ui-experimental", feature = "dual-core-transport"))]
    spawner.spawn(rp_usb_fido_common::core0_gpio25_ui_task(p.PIN_25).unwrap());

    let make_dispatcher = move || {
        #[cfg(not(feature = "dual-core-transport"))]
        #[allow(unused_mut)]
        let mut storage = rp_usb_fido_common::selected_storage(flash);
        #[cfg(feature = "dual-core-transport")]
        #[allow(unused_mut)]
        let mut storage = rp_usb_fido_common::selected_storage(&FLASH_ENDPOINT);
        #[cfg(not(feature = "dual-core-transport"))]
        let pin_uv_auth = rp_usb_fido_common::selected_pin_uv_auth(flash);
        #[cfg(feature = "dual-core-transport")]
        let pin_uv_auth = rp_usb_fido_common::selected_core0_pin_uv_auth(&FLASH_ENDPOINT);
        #[cfg(feature = "chip-rp2040")]
        let entropy = rp_usb_fido_common::selected_entropy();
        #[cfg(feature = "chip-rp235xa")]
        let entropy = rp_usb_fido_common::selected_entropy(p.TRNG, Irqs);
        #[cfg(all(feature = "dual-core-transport", feature = "up-bootsel-experimental"))]
        let presence = rp_usb_fido_common::selected_dual_core_bootsel_presence();
        #[cfg(all(
            not(feature = "dual-core-transport"),
            feature = "up-bootsel-experimental"
        ))]
        let presence = rp_usb_fido_common::selected_user_presence(p.BOOTSEL);
        #[cfg(any(feature = "up-always-present", feature = "up-gpio15"))]
        let presence = rp_usb_fido_common::selected_user_presence(p.PIN_15);
        #[cfg(all(feature = "board-ui-experimental", feature = "dual-core-transport"))]
        let observer = rp_usb_fido_common::selected_dual_core_presence_observer();
        #[cfg(all(
            feature = "board-ui-experimental",
            not(feature = "dual-core-transport")
        ))]
        let observer = rp_usb_fido_common::selected_presence_observer(p.PIN_25);
        #[cfg(not(feature = "board-ui-experimental"))]
        let observer = rp_usb_fido_common::selected_presence_observer();
        #[allow(unused_mut)]
        let mut entropy = entropy;
        #[cfg(not(feature = "rp-flash-managed-keys"))]
        let key_store = rp_usb_fido_common::selected_private_key_store();
        #[cfg(feature = "rp-flash-managed-keys")]
        let key_store = rp_usb_fido_common::selected_managed_private_key_store(
            {
                #[cfg(not(feature = "dual-core-transport"))]
                {
                    flash
                }
                #[cfg(feature = "dual-core-transport")]
                {
                    &FLASH_ENDPOINT
                }
            },
            &mut storage,
            &mut entropy,
        );
        TrustedDispatcher::new_with_transports_and_presence_observer(
            storage,
            presence,
            rp_usb_fido_common::selected_user_verification(),
            pin_uv_auth,
            key_store,
            entropy,
            manekey::transport::USB_TRANSPORTS,
            observer,
        )
    };
    #[cfg(not(feature = "dual-core-transport"))]
    let dispatcher = make_dispatcher();
    #[cfg(not(any(
        feature = "single-core-task-transport",
        feature = "dual-core-transport"
    )))]
    let arbiter = ARBITER.init(Mutex::new(RefCell::new(IngressArbiter::new(dispatcher))));
    #[cfg(feature = "single-core-task-transport")]
    let dispatcher = DISPATCHER.init(dispatcher);
    #[cfg(feature = "single-core-task-transport")]
    let arbiter = ARBITER.init(Mutex::new(RefCell::new(IngressArbiter::new(
        MailboxTrustedBackend::new(LocalMailboxTransport::new(&ENDPOINT)),
    ))));
    #[cfg(feature = "dual-core-transport")]
    let arbiter = ARBITER.init(Mutex::new(RefCell::new(IngressArbiter::new(
        MailboxTrustedBackend::new(PollingMailboxTransport::new(&ENDPOINT)),
    ))));

    #[cfg(feature = "dual-core-transport")]
    spawner.spawn(core0_flash_service_task(flash).unwrap());
    #[cfg(feature = "dual-core-transport")]
    embassy_rp::multicore::spawn_core1(
        p.CORE1,
        unsafe { &mut *core::ptr::addr_of_mut!(CORE1_STACK) },
        move || core1_trusted_task(DISPATCHER.init(make_dispatcher())),
    );

    #[cfg(all(feature = "chip-rp235xa", feature = "rp-internal-uart"))]
    let product = "RP2350 UART + HID + CCID";
    #[cfg(all(feature = "chip-rp235xa", not(feature = "rp-internal-uart")))]
    let product = "RP2350 HID + CCID";
    #[cfg(all(feature = "chip-rp2040", feature = "rp-ml-dsa-credential-experimental"))]
    let product = "RP2040 HID + CCID ML-DSA";
    #[cfg(all(
        feature = "chip-rp2040",
        not(feature = "rp-ml-dsa-credential-experimental")
    ))]
    let product = "RP2040 HID + CCID";
    let usb = rp_usb_fido_common::build_ctaphid_ccid_usb(driver, product);
    info!("USB HID + CCID ready");
    #[cfg(feature = "rp-internal-uart")]
    spawner.spawn(rp_internal_uart::multi_internal_task(uart, arbiter).unwrap());
    spawner.spawn(rp_usb_fido_common::usb_task(usb.device).unwrap());
    #[cfg(feature = "single-core-task-transport")]
    spawner.spawn(rp_usb_fido_common::single_core_trusted_task(dispatcher, &ENDPOINT).unwrap());
    #[cfg(not(any(
        feature = "single-core-task-transport",
        feature = "dual-core-transport"
    )))]
    spawner.spawn(rp_usb_fido_common::hid_direct_shared_frontend_task(usb.hid, arbiter).unwrap());
    #[cfg(any(
        feature = "single-core-task-transport",
        feature = "dual-core-transport"
    ))]
    spawner.spawn(rp_usb_fido_common::hid_mailbox_shared_frontend_task(usb.hid, arbiter).unwrap());
    #[cfg(not(any(
        feature = "single-core-task-transport",
        feature = "dual-core-transport"
    )))]
    spawner.spawn(rp_usb_fido_common::ccid_direct_frontend_task(usb.ccid, arbiter).unwrap());
    #[cfg(any(
        feature = "single-core-task-transport",
        feature = "dual-core-transport"
    ))]
    spawner.spawn(rp_usb_fido_common::ccid_mailbox_frontend_task(usb.ccid, arbiter).unwrap());
}

#[cfg(feature = "dual-core-transport")]
/// Sole core1 dispatcher/endpoint owner with dedicated stack and live core0 Flash service.
fn core1_trusted_task(dispatcher: &'static mut rp_usb_fido_common::SelectedTrustedDispatcher) -> ! {
    let mut request = [0; TRUSTED_REQUEST_MAX];
    let mut response = [0; TRUSTED_RESPONSE_MAX];

    loop {
        match ENDPOINT.pump_operation_once(dispatcher, &mut request, &mut response) {
            Ok(true) => cortex_m::asm::sev(),
            Ok(false) | Err(_) => cortex_m::asm::wfe(),
        }
    }
}

#[cfg(feature = "dual-core-transport")]
#[embassy_executor::task]
/// Sole core0 journal/key media worker; preserve HAL cross-core XIP exclusion for mutations.
async fn core0_flash_service_task(flash: &'static SharedRpFlash<'static>) {
    #[cfg(not(feature = "rp-flash-managed-keys"))]
    let mut service = Core0FlashService::with_pin_backend(
        SharedFlashStorage::new(flash),
        SharedPinUvAuthFlashStorage::new(flash),
    );
    #[cfg(feature = "rp-flash-managed-keys")]
    let mut service = Core0FlashService::with_key_backend(
        SharedFlashStorage::new(flash),
        SharedPinUvAuthFlashStorage::new(flash),
        manekey_rp::platform::rp::managed_flash::SharedManagedKeyFlashStorage::new(flash),
    );
    loop {
        if !service.pump_once(&FLASH_ENDPOINT) {
            embassy_futures::yield_now().await;
        }
    }
}
