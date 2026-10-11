#![no_std]
#![no_main]

#[cfg(feature = "pin-storage-flash")]
use core::cell::RefCell;

use defmt::*;
use defmt_rtt as _;
use panic_probe as _;

use embassy_executor::Spawner;
#[cfg(feature = "dual-core-transport")]
use embassy_rp::multicore::Stack;
use embassy_rp::usb::{Driver, InterruptHandler};
use embassy_rp::{bind_interrupts, peripherals};

#[cfg(any(
    feature = "pin-storage-flash",
    feature = "dual-core-transport",
    feature = "single-core-task-transport"
))]
use static_cell::StaticCell;

#[cfg(any(
    feature = "dual-core-transport",
    feature = "single-core-task-transport"
))]
use manekey::boundary::mailbox::MailboxEndpoint;
#[cfg(feature = "dual-core-core0-flash-service")]
use manekey::boundary::storage_mailbox::{
    CORE0_FLASH_REQUEST_MAX, CORE0_FLASH_RESPONSE_MAX, Core0FlashService,
};
#[cfg(all(
    not(feature = "pin-storage-flash"),
    not(feature = "dual-core-core0-flash-service")
))]
use manekey::ctaphid::storage;
#[cfg(any(
    feature = "dual-core-transport",
    feature = "single-core-task-transport"
))]
use manekey::ctaphid::trusted::{TRUSTED_REQUEST_MAX, TRUSTED_RESPONSE_MAX};
#[cfg(not(feature = "pin-storage-flash"))]
use manekey_rp::platform::rp::storage::FlashStorage;
#[cfg(feature = "pin-storage-flash")]
use manekey_rp::platform::rp::storage::SharedRpFlash;
#[cfg(all(
    feature = "pin-storage-flash",
    feature = "dual-core-core0-flash-service"
))]
use manekey_rp::platform::rp::storage::{SharedFlashStorage, SharedPinUvAuthFlashStorage};
#[cfg(feature = "dual-core-core0-flash-service")]
use manekey_rp::platform::rp::storage_mailbox::Core0FlashServiceExt;
#[cfg(any(
    feature = "dual-core-transport",
    feature = "single-core-task-transport"
))]
use rp_usb_fido_common::SelectedTrustedDispatcher;

#[cfg(feature = "rp-ml-dsa-credential-experimental")]
#[path = "rp_ml_dsa_experimental.rs"]
mod rp_ml_dsa_experimental;
#[path = "rp_usb_fido_common.rs"]
mod rp_usb_fido_common;

#[cfg(any(
    feature = "dual-core-transport",
    feature = "single-core-task-transport"
))]
static DUAL_CORE_ENDPOINT: MailboxEndpoint<TRUSTED_REQUEST_MAX, TRUSTED_RESPONSE_MAX> =
    MailboxEndpoint::new();

#[cfg(feature = "dual-core-core0-flash-service")]
static CORE0_FLASH_ENDPOINT: MailboxEndpoint<CORE0_FLASH_REQUEST_MAX, CORE0_FLASH_RESPONSE_MAX> =
    MailboxEndpoint::new();

#[cfg(any(
    feature = "dual-core-transport",
    feature = "single-core-task-transport"
))]
static DUAL_CORE_DISPATCHER: StaticCell<SelectedTrustedDispatcher> = StaticCell::new();

#[cfg(feature = "dual-core-transport")]
const DUAL_CORE_STACK_SIZE: usize = rp_usb_fido_common::DUAL_CORE_WORKER_STACK_SIZE;

#[cfg(feature = "dual-core-transport")]
static mut DUAL_CORE_STACK: Stack<DUAL_CORE_STACK_SIZE> = Stack::new();

#[cfg(feature = "chip-rp2040")]
bind_interrupts!(struct Irqs {
    USBCTRL_IRQ => InterruptHandler<peripherals::USB>;
});

#[cfg(feature = "chip-rp235xa")]
bind_interrupts!(struct Irqs {
    USBCTRL_IRQ => InterruptHandler<peripherals::USB>;
    TRNG_IRQ => embassy_rp::trng::InterruptHandler<peripherals::TRNG>;
});

#[embassy_executor::main]
/// Initialize once with exclusive USB/Flash ownership and the selected storage geometry.
/// Local tasks or dual cores alone do not provide memory isolation.
async fn main(_spawner: Spawner) {
    #[cfg(feature = "rp-ml-dsa-credential-experimental")]
    rp_ml_dsa_experimental::initialize();
    #[cfg(feature = "chip-rp235xa")]
    manekey_rp::platform::rp2350::arm_security::configure_rp2350_normal_access();
    let p = embassy_rp::init(Default::default());

    let driver = Driver::new(p.USB, Irqs);

    #[cfg(all(
        not(all(any(), feature = "chip-rp2040")),
        any(
            feature = "pin-storage-flash",
            feature = "dual-core-core0-flash-service",
            all(
                not(feature = "pin-storage-flash"),
                not(feature = "dual-core-core0-flash-service")
            )
        )
    ))]
    let flash = embassy_rp::flash::Flash::new_blocking(p.FLASH);

    #[cfg(all(feature = "key-storage-flash", not(feature = "rp-flash-managed-keys")))]
    let key_store = rp_usb_fido_common::selected_private_key_store();

    #[cfg(feature = "pin-storage-flash")]
    static FLASH: StaticCell<SharedRpFlash<'static>> = StaticCell::new();

    #[cfg(feature = "pin-storage-flash")]
    let flash = FLASH.init(SharedRpFlash::new(RefCell::new(flash)));

    #[cfg(all(
        feature = "pin-storage-flash",
        not(feature = "dual-core-core0-flash-service")
    ))]
    let mut storage = rp_usb_fido_common::selected_storage(flash);

    #[cfg(all(
        not(feature = "pin-storage-flash"),
        not(feature = "dual-core-core0-flash-service")
    ))]
    let mut storage = storage::Storage::new(FlashStorage::new(flash));

    #[cfg(feature = "dual-core-core0-flash-service")]
    let mut storage = rp_usb_fido_common::selected_storage(&CORE0_FLASH_ENDPOINT);

    #[cfg(feature = "chip-rp2040")]
    let mut entropy = rp_usb_fido_common::selected_entropy();

    #[cfg(feature = "chip-rp235xa")]
    let mut entropy = rp_usb_fido_common::selected_entropy(p.TRNG, Irqs);

    #[cfg(feature = "rp-flash-managed-keys")]
    let key_store = rp_usb_fido_common::selected_managed_private_key_store(
        {
            #[cfg(not(feature = "dual-core-transport"))]
            {
                flash
            }
            #[cfg(feature = "dual-core-transport")]
            {
                &CORE0_FLASH_ENDPOINT
            }
        },
        &mut storage,
        &mut entropy,
    );

    #[cfg(all(
        feature = "pin-storage-flash",
        feature = "dual-core-core0-flash-service"
    ))]
    let pin_uv_auth = rp_usb_fido_common::selected_core0_pin_uv_auth(&CORE0_FLASH_ENDPOINT);

    #[cfg(all(
        feature = "pin-storage-flash",
        not(feature = "dual-core-core0-flash-service")
    ))]
    let pin_uv_auth = rp_usb_fido_common::selected_pin_uv_auth(flash);

    #[cfg(all(not(feature = "pin-storage-flash"), feature = "pin-storage-volatile"))]
    let pin_uv_auth = rp_usb_fido_common::selected_pin_uv_auth();

    #[cfg(not(any(feature = "pin-storage-flash", feature = "pin-storage-volatile")))]
    let pin_uv_auth = rp_usb_fido_common::selected_pin_uv_auth();

    let verification = rp_usb_fido_common::selected_user_verification();
    #[cfg(all(feature = "up-bootsel-experimental", feature = "dual-core-transport"))]
    _spawner.spawn(
        manekey_rp::platform::rp::user_interface::sample_bootsel_on_core0(p.BOOTSEL)
            .expect("allocate core0 BOOTSEL sampler task"),
    );
    #[cfg(all(feature = "board-ui-experimental", feature = "dual-core-transport"))]
    _spawner.spawn(
        rp_usb_fido_common::core0_gpio25_ui_task(p.PIN_25).expect("allocate core0 GPIO25 UI task"),
    );
    #[cfg(all(feature = "up-bootsel-experimental", feature = "dual-core-transport"))]
    let presence = rp_usb_fido_common::selected_dual_core_bootsel_presence();
    #[cfg(all(
        feature = "up-bootsel-experimental",
        not(feature = "dual-core-transport")
    ))]
    let presence = rp_usb_fido_common::selected_user_presence(p.BOOTSEL);
    #[cfg(not(feature = "up-bootsel-experimental"))]
    let presence = rp_usb_fido_common::selected_user_presence(p.PIN_15);
    #[cfg(all(feature = "board-ui-experimental", feature = "dual-core-transport"))]
    let presence_observer = rp_usb_fido_common::selected_dual_core_presence_observer();
    #[cfg(all(
        feature = "board-ui-experimental",
        not(feature = "dual-core-transport")
    ))]
    let presence_observer = rp_usb_fido_common::selected_presence_observer(p.PIN_25);
    #[cfg(not(feature = "board-ui-experimental"))]
    let presence_observer = rp_usb_fido_common::selected_presence_observer();

    #[cfg(any(
        feature = "dual-core-transport",
        feature = "single-core-task-transport"
    ))]
    let dispatcher = DUAL_CORE_DISPATCHER.init(
        SelectedTrustedDispatcher::new_with_transports_and_presence_observer(
            storage,
            presence,
            verification,
            pin_uv_auth,
            key_store,
            entropy,
            manekey::transport::USB_TRANSPORTS,
            presence_observer,
        ),
    );

    #[cfg(feature = "dual-core-transport")]
    {
        embassy_rp::multicore::spawn_core1(
            p.CORE1,
            unsafe { &mut *core::ptr::addr_of_mut!(DUAL_CORE_STACK) },
            move || dual_core_trusted_task(dispatcher),
        );
    }

    #[cfg(feature = "single-core-task-transport")]
    _spawner.spawn(single_core_trusted_task(dispatcher).unwrap());

    #[cfg(all(
        feature = "dual-core-core0-flash-service",
        feature = "pin-storage-flash"
    ))]
    _spawner.spawn(core0_flash_service_task(flash).unwrap());
    #[cfg(all(
        feature = "dual-core-core0-flash-service",
        not(feature = "pin-storage-flash")
    ))]
    _spawner.spawn(core0_flash_service_task(FlashStorage::new(flash)).unwrap());

    let (usb, hid) =
        rp_usb_fido_common::build_ctaphid_usb(driver, rp_usb_fido_common::PRODUCT_NAME);

    info!("USB HID ready");

    _spawner.spawn(rp_usb_fido_common::usb_task(usb).unwrap());
    #[cfg(not(any(
        feature = "dual-core-transport",
        feature = "single-core-task-transport"
    )))]
    _spawner.spawn(
        rp_usb_fido_common::hid_direct_task(
            hid,
            storage,
            presence,
            verification,
            pin_uv_auth,
            key_store,
            entropy,
            presence_observer,
        )
        .unwrap(),
    );
    #[cfg(any(
        feature = "dual-core-transport",
        feature = "single-core-task-transport"
    ))]
    _spawner.spawn(rp_usb_fido_common::hid_frontend_task(hid, &DUAL_CORE_ENDPOINT).unwrap());
}

#[cfg(feature = "dual-core-transport")]
/// Sole core1 dispatcher and endpoint worker; exclusively reserve its stack and cross-core Flash service.
fn dual_core_trusted_task(dispatcher: &'static mut SelectedTrustedDispatcher) -> ! {
    let mut request = [0; TRUSTED_REQUEST_MAX];
    let mut response = [0; TRUSTED_RESPONSE_MAX];

    loop {
        match DUAL_CORE_ENDPOINT.pump_operation_once(dispatcher, &mut request, &mut response) {
            Ok(true) => {
                cortex_m::asm::sev();
            }
            Ok(false) | Err(_) => cortex_m::asm::wfe(),
        }
    }
}

#[cfg(feature = "single-core-task-transport")]
#[embassy_executor::task]
/// Sole local dispatcher worker; frontend clients must serialize endpoint access.
async fn single_core_trusted_task(dispatcher: &'static mut SelectedTrustedDispatcher) {
    let mut request = [0; TRUSTED_REQUEST_MAX];
    let mut response = [0; TRUSTED_RESPONSE_MAX];

    loop {
        match DUAL_CORE_ENDPOINT.pump_operation_once(dispatcher, &mut request, &mut response) {
            Ok(true) => {}
            Ok(false) | Err(_) => embassy_futures::yield_now().await,
        }
    }
}

#[cfg(all(
    feature = "dual-core-core0-flash-service",
    feature = "pin-storage-flash"
))]
#[embassy_executor::task]
/// Sole shared Flash service; maintain HAL cross-core XIP exclusion for every mutation.
async fn core0_flash_service_task(flash: &'static SharedRpFlash<'static>) {
    let mut service = Core0FlashService::with_pin_backend(
        SharedFlashStorage::new(flash),
        SharedPinUvAuthFlashStorage::new(flash),
    );
    loop {
        if !service.pump_once(&CORE0_FLASH_ENDPOINT) {
            embassy_futures::yield_now().await;
        }
    }
}

#[cfg(all(
    feature = "dual-core-core0-flash-service",
    not(feature = "pin-storage-flash")
))]
#[embassy_executor::task]
/// Sole credential Flash service with the same cross-core XIP exclusion requirement.
async fn core0_flash_service_task(backend: FlashStorage<'static>) {
    let mut service = Core0FlashService::new(backend);
    loop {
        if !service.pump_once(&CORE0_FLASH_ENDPOINT) {
            embassy_futures::yield_now().await;
        }
    }
}
