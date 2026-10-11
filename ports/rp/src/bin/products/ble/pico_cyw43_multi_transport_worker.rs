use super::{MultiBackend, MultiDispatcher};
use manekey::boundary::mailbox::{LocalMailboxWorker, MailboxEndpoint};
use manekey::boundary::mailbox_backend::MailboxTrustedBackend;
use manekey::ctaphid::trusted::{TRUSTED_REQUEST_MAX, TRUSTED_RESPONSE_MAX};
use static_cell::StaticCell;

static ENDPOINT: MailboxEndpoint<TRUSTED_REQUEST_MAX, TRUSTED_RESPONSE_MAX> =
    MailboxEndpoint::new();
static DISPATCHER: StaticCell<MultiDispatcher> = StaticCell::new();

#[cfg(feature = "single-core-task-transport")]
/// Start one dispatcher worker and one serialized client; local tasks do not provide hardware isolation.
pub(super) fn start_local(
    spawner: &embassy_executor::Spawner,
    dispatcher: MultiDispatcher,
) -> MultiBackend {
    spawner.spawn(local_worker(DISPATCHER.init(dispatcher)).unwrap());
    MailboxTrustedBackend::new(manekey::boundary::mailbox::LocalMailboxTransport::new(
        &ENDPOINT,
    ))
}

#[cfg(feature = "single-core-task-transport")]
#[embassy_executor::task]
async fn local_worker(dispatcher: &'static mut MultiDispatcher) -> ! {
    let mut worker = LocalMailboxWorker::from_ref(dispatcher);
    loop {
        let _ = worker.pump_once(&ENDPOINT);
        embassy_futures::yield_now().await;
    }
}

#[cfg(feature = "dual-core-transport")]
pub(super) static FLASH_ENDPOINT: MailboxEndpoint<
    { manekey::boundary::storage_mailbox::CORE0_FLASH_REQUEST_MAX },
    { manekey::boundary::storage_mailbox::CORE0_FLASH_RESPONSE_MAX },
> = MailboxEndpoint::new();

#[cfg(feature = "dual-core-transport")]
/// Initialize once with exclusive core1/stack ownership and the sole core0 Flash service.
/// All Flash operations require the HAL's cross-core XIP exclusion.
pub(super) fn start_dual<F: FnOnce() -> MultiDispatcher + Send + 'static>(
    spawner: &embassy_executor::Spawner,
    core1: embassy_rp::Peri<'static, embassy_rp::peripherals::CORE1>,
    make_dispatcher: F,
    flash: &'static manekey_rp::platform::rp::storage::SharedRpFlash<'static>,
) -> MultiBackend {
    #[cfg(feature = "chip-rp2040")]
    const STACK_SIZE: usize = 64 * 1024;
    #[cfg(feature = "chip-rp235xa")]
    const STACK_SIZE: usize = 256 * 1024;
    static mut STACK: embassy_rp::multicore::Stack<STACK_SIZE> =
        embassy_rp::multicore::Stack::new();

    spawner.spawn(flash_worker(flash).unwrap());

    manekey_rp::platform::rp::mailbox::spawn_core1_polling(
        core1,
        unsafe { &mut *core::ptr::addr_of_mut!(STACK) },
        move || {
            let dispatcher = DISPATCHER.init(make_dispatcher());
            let mut worker = LocalMailboxWorker::from_ref(dispatcher);
            loop {
                let result = worker.pump_once(&ENDPOINT);

                match result {
                    Ok(true) => cortex_m::asm::sev(),
                    _ => cortex_m::asm::wfe(),
                }
            }
        },
    );
    MailboxTrustedBackend::new(
        manekey_rp::platform::rp::mailbox::PollingMailboxTransport::new(&ENDPOINT),
    )
}

#[cfg(feature = "dual-core-transport")]
#[embassy_executor::task]
/// Sole core0 Flash service for the selected journals and endpoint; never add another worker for this endpoint.
async fn flash_worker(
    flash: &'static manekey_rp::platform::rp::storage::SharedRpFlash<'static>,
) -> ! {
    use manekey::boundary::storage_mailbox::Core0FlashService;
    use manekey_rp::platform::rp::storage::{SharedFlashStorage, SharedPinUvAuthFlashStorage};
    use manekey_rp::platform::rp::storage_mailbox::Core0FlashServiceExt;
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
        let _ = service.pump_once(&FLASH_ENDPOINT);
        embassy_time::Timer::after_millis(1).await;
    }
}
