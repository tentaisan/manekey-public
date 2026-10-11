#![no_std]
#![no_main]

use core::sync::atomic::{AtomicBool, Ordering};
use manekey::ctaphid::{
    entropy::HmacDrbgEntropy,
    pin_uv_auth::{JournaledPinUvAuthStorage, StoredPinUvAuthProvider},
    storage::Storage,
    trusted::TrustedDispatcher,
    user_verification::UnavailableUserVerification,
};
use manekey_stm32u575::crypto::ClientPinCrypto;
use manekey_stm32u575::key_store::Keys;
use manekey_stm32u575::{
    secure_hal::{PrivateFlash, SecureClock, SecureEntropy},
    storage::{Journal, SharedFlash},
    trustzone,
};
use static_cell::StaticCell;

#[cfg(feature = "physical-up")]
type Presence = manekey_stm32u575::secure_hal::PhysicalPresence;
#[cfg(not(feature = "physical-up"))]
type Presence = manekey::presence::AlwaysPresent;
type Dispatcher = TrustedDispatcher<
    Journal,
    Presence,
    UnavailableUserVerification,
    StoredPinUvAuthProvider<JournaledPinUvAuthStorage<Journal>, ClientPinCrypto, SecureClock>,
    Keys,
    HmacDrbgEntropy<SecureEntropy>,
    manekey::user_interface::UiPresenceObserver<
        manekey::presence::NoPresenceObserver,
        manekey::user_interface::TouchPromptLed,
    >,
>;
static DISPATCHER: StaticCell<Dispatcher> = StaticCell::new();
static mut BACKEND: *mut Dispatcher = core::ptr::null_mut();
static ENTERED: AtomicBool = AtomicBool::new(false);

core::arch::global_asm!(
    r#"
    .syntax unified
    .thumb
    .fpu fpv5-sp-d16
    .section .nsc,"ax",%progbits
    .balign 32
    .global stm32_product_gateway
    .type stm32_product_gateway,%function
    .thumb_func
stm32_product_gateway:
    sg
    b.w stm32_product_gateway_secure
    .balign 32, 0
    .section .text.stm32_product_gateway_secure,"ax",%progbits
    .thumb_func
stm32_product_gateway_secure:
    push {{r4, lr}}
    vmrs r4, fpscr
    vpush {{s0-s31}}
    bl stm32_product_dispatch
    vpop {{s0-s31}}
    vmsr fpscr, r4
    pop {{r4, lr}}
    movs r1, #0
    movs r2, #0
    movs r3, #0
    movs r12, #0
    msr APSR_nzcvq, r1
    bxns lr
"#
);

#[unsafe(no_mangle)]
/// Secure gateway dispatch with reentry rejection.
///
/// # Safety
/// Invoke through the matching gateway ABI after Secure initialization; preserve private backend ownership and validated shared memory.
unsafe extern "C" fn stm32_product_dispatch(pointer: u32) -> u32 {
    if ENTERED
        .compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
        .is_err()
    {
        return manekey::security::trusted_call_error_status(
            manekey::security::TrustedCallError::InvalidDescriptor,
        );
    }
    let backend = unsafe { BACKEND };
    let status = if backend.is_null() {
        manekey::security::trusted_call_error_status(
            manekey::security::TrustedCallError::InvalidDescriptor,
        )
    } else {
        unsafe {
            manekey::boundary::arm_trustzone::dispatch_trusted_call_in(
                trustzone::SHARED,
                pointer,
                &mut *backend,
            )
        }
    };
    ENTERED.store(false, Ordering::Release);
    status
}

#[cortex_m_rt::entry]
/// Secure product owner; requires preconfigured recoverable option-byte/layout state and a matching NS image.
fn main() -> ! {
    unsafe extern "C" {
        static _stack_end: u8;
    }
    let limit = (core::ptr::addr_of!(_stack_end) as u32 + 7) & !7;
    unsafe {
        core::arch::asm!("msr MSPLIM, {limit}", limit = in(reg) limit,
                         options(nostack, preserves_flags));
    }
    let mut core = cortex_m::Peripherals::take().unwrap();
    core.SCB
        .enable(cortex_m::peripheral::scb::Exception::SecureFault);
    unsafe {
        trustzone::configure_memory(&mut core.SAU);
        trustzone::configure_uart_runtime();
        manekey_stm32u575::secure_hal::initialize();
    }

    static FLASH: StaticCell<SharedFlash> = StaticCell::new();
    let flash = FLASH.init(critical_section::Mutex::new(core::cell::RefCell::new(
        PrivateFlash,
    )));
    let mut entropy = SecureEntropy;
    let mut records = Storage::new(Journal::credentials(flash));
    let keys =
        manekey_stm32u575::key_store::open(flash, &mut entropy, &mut records).expect("key store");
    #[cfg(feature = "physical-up")]
    let presence = manekey_stm32u575::secure_hal::physical_presence();
    #[cfg(not(feature = "physical-up"))]
    let presence = manekey::presence::AlwaysPresent;
    let backend = DISPATCHER.init(
        TrustedDispatcher::new_with_transports_and_presence_observer(
            records,
            presence,
            UnavailableUserVerification,
            StoredPinUvAuthProvider::new_with_crypto_and_clock(
                JournaledPinUvAuthStorage::new(Journal::pin(flash)),
                manekey_stm32u575::crypto::client_pin_crypto(),
                SecureClock::new(),
            ),
            keys,
            HmacDrbgEntropy::new(entropy).unwrap(),
            manekey::transport::USB_TRANSPORTS,
            manekey::user_interface::UiPresenceObserver::new(
                manekey::presence::NoPresenceObserver,
                manekey::user_interface::TouchPromptLed::new(
                    manekey_stm32u575::secure_hal::led_on,
                    manekey_stm32u575::secure_hal::led_off,
                ),
            ),
        ),
    );
    unsafe {
        BACKEND = backend;
    }

    unsafe { trustzone::handoff(core) }
}

#[cortex_m_rt::exception]
fn SecureFault() {
    fail(0x5346_4155)
}
#[panic_handler]
fn panic(_: &core::panic::PanicInfo<'_>) -> ! {
    fail(0xdead)
}
fn fail(_stage: u32) -> ! {
    loop {
        cortex_m::asm::wfi();
    }
}
