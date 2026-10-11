use super::SelectedObserver;

pub trait RuntimeObserver {
    fn before_crypto() {}
    fn after_crypto() {}
    fn ready() {}
    fn gateway_status(_status: u32) {}
}

impl RuntimeObserver for () {}

use core::{
    ptr,
    sync::atomic::{AtomicBool, Ordering},
};
use cortex_m::{
    Peripherals,
    peripheral::sau::{SauRegion, SauRegionAttribute},
};
use cortex_m_rt::entry;
#[cfg(feature = "trustzone-secure-uart-user-key")]
use embassy_nrf::gpio::{Level, Output, OutputDrive};
use embassy_nrf::{config, crypto::rng};
use manekey::{boundary::arm_trustzone::dispatch_trusted_call_in, security::SharedMemoryRegion};
#[cfg(feature = "trustzone-secure-uart-user-key")]
use nrf54l15::presence::UserKeyPresence;
#[cfg(feature = "trustzone-secure-uart-product")]
use nrf54l15::trustzone::{NS_P2_START, NS_UARTE21_END};
use nrf54l15::{
    entropy::{build_entropy, init_shared_rng},
    fido::{RramDispatcher, build_rram_virtual_hid_dispatcher},
    storage::init_shared_rram,
    trustzone::{
        NS_FLASH_END, NS_FLASH_START, NS_RAM_END, NS_RAM_START, NSC_FLASH_END, NSC_FLASH_START,
        configure_nonsecure_memory,
    },
    ui::USER_LED_STATUS,
};
use static_cell::StaticCell;
use {defmt_rtt as _, panic_probe as _};
const SHARED_MEMORY: SharedMemoryRegion = SharedMemoryRegion {
    start: nrf54l15::trustzone::NS_SHARED_START,
    end: nrf54l15::trustzone::NS_SHARED_END + 1,
};
#[cfg(feature = "trustzone-secure-uart-user-key")]
type ProductPresence = UserKeyPresence<'static>;
#[cfg(not(feature = "trustzone-secure-uart-user-key"))]
type ProductPresence = manekey::presence::AlwaysPresent;
static DISPATCHER: StaticCell<RramDispatcher<'static, ProductPresence>> = StaticCell::new();
static mut DISPATCHER_PTR: *mut RramDispatcher<'static, ProductPresence> = ptr::null_mut();
#[cfg(feature = "trustzone-secure-uart-user-key")]
static SECURE_LED: StaticCell<Output<'static>> = StaticCell::new();
#[cfg(feature = "trustzone-secure-uart-user-key")]
static mut SECURE_LED_PTR: *mut Output<'static> = ptr::null_mut();
static GATEWAY_ACTIVE: AtomicBool = AtomicBool::new(false);
core::arch::global_asm!(
    r#"
    .syntax unified
    .thumb
    .section .nsc, "ax", %progbits
    .balign 32
    .global nrf54l15_tz_p3_product_gateway
    .type nrf54l15_tz_p3_product_gateway,%function
    .thumb_func
nrf54l15_tz_p3_product_gateway:
    sg
    b.w nrf54l15_tz_p3_product_gateway_secure
    .balign 32, 0
    .size nrf54l15_tz_p3_product_gateway, . - nrf54l15_tz_p3_product_gateway
    .section .text.nrf54l15_tz_p3_product_gateway_secure, "ax", %progbits
    .balign 4
    .type nrf54l15_tz_p3_product_gateway_secure,%function
    .thumb_func
nrf54l15_tz_p3_product_gateway_secure:
    push {{r4, lr}}
    bl nrf54l15_tz_p3_product_gateway_impl
    pop {{r4, lr}}
    movs r1, #0
    movs r2, #0
    movs r3, #0
    movs r12, #0
    bxns lr
    .size nrf54l15_tz_p3_product_gateway_secure, . - nrf54l15_tz_p3_product_gateway_secure
"#
);
#[entry]
/// Initialize once with matched Secure/NS linker regions and reserved private crypto/RRAM/UP owners.
fn main() -> ! {
    let mut core = Peripherals::take().expect("take core peripherals once");
    assert!(core.SAU.region_numbers() >= 3);
    core.SAU
        .init(&[
            SauRegion {
                base_address: NSC_FLASH_START,
                limit_address: NSC_FLASH_END,
                attribute: SauRegionAttribute::NonSecureCallable,
            },
            SauRegion {
                base_address: NS_FLASH_START,
                limit_address: NS_FLASH_END,
                attribute: SauRegionAttribute::NonSecure,
            },
            SauRegion {
                base_address: NS_RAM_START,
                limit_address: NS_RAM_END,
                attribute: SauRegionAttribute::NonSecure,
            },
        ])
        .expect("configure nRF54L15 NS regions");
    #[cfg(feature = "trustzone-secure-uart-product")]
    core.SAU
        .init(&[
            SauRegion {
                base_address: NSC_FLASH_START,
                limit_address: NSC_FLASH_END,
                attribute: SauRegionAttribute::NonSecureCallable,
            },
            SauRegion {
                base_address: NS_FLASH_START,
                limit_address: NS_FLASH_END,
                attribute: SauRegionAttribute::NonSecure,
            },
            SauRegion {
                base_address: NS_RAM_START,
                limit_address: NS_RAM_END,
                attribute: SauRegionAttribute::NonSecure,
            },
            SauRegion {
                base_address: NS_P2_START,
                limit_address: NS_UARTE21_END,
                attribute: SauRegionAttribute::NonSecure,
            },
        ])
        .expect("configure nRF54L15 UART NS regions");
    let mut platform_config: config::Config = Default::default();
    platform_config.clock_speed = config::ClockSpeed::CK128;
    platform_config.hfclk_source = config::HfclkSource::ExternalXtal;
    platform_config.lfclk_source = config::LfclkSource::ExternalXtal;
    let p = embassy_nrf::init(platform_config);
    let shared_rng = init_shared_rng(rng::Rng::new_blocking(p.CRYPTO_RNG));
    SelectedObserver::before_crypto();
    #[cfg(feature = "cracen-sha256")]
    nrf54l15::crypto::init_symmetric(p.CRYPTO_SYMMETRIC);
    #[cfg(feature = "cracen-p256-experimental")]
    nrf54l15::crypto::init_pka(p.CRYPTO_PKA, shared_rng);
    SelectedObserver::after_crypto();
    let entropy = build_entropy(shared_rng).expect("secure entropy");
    let rram = init_shared_rram(embassy_nrf::rramc::Nvmc::new(p.RRAMC));
    #[cfg(feature = "trustzone-secure-uart-user-key")]
    let presence = {
        let led = SECURE_LED.init(Output::new(p.P2_00, Level::High, OutputDrive::Standard));
        unsafe { SECURE_LED_PTR = led as *mut _ };
        UserKeyPresence::new(p.P0_00)
    };
    #[cfg(not(feature = "trustzone-secure-uart-user-key"))]
    let presence = manekey::presence::AlwaysPresent;
    let dispatcher = DISPATCHER.init(build_rram_virtual_hid_dispatcher(
        presence,
        entropy,
        rram,
        &USER_LED_STATUS,
    ));
    unsafe { DISPATCHER_PTR = dispatcher as *mut _ };
    configure_nonsecure_memory();
    #[cfg(feature = "trustzone-secure-uart-product")]
    nrf54l15::trustzone::delegate_external_uart_to_nonsecure();
    cortex_m::asm::dsb();
    cortex_m::asm::isb();
    SelectedObserver::ready();
    unsafe { cortex_m::asm::bootload_ns(NS_FLASH_START as *const u32, core.SCBNS) }
}
#[unsafe(no_mangle)]
/// Secure gateway entry only; validated shared copies and a single active dispatcher turn.
extern "C" fn nrf54l15_tz_p3_product_gateway_impl(descriptor_ptr: u32) -> u32 {
    if GATEWAY_ACTIVE
        .compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
        .is_err()
    {
        return manekey::security::trusted_status::BUSY;
    }
    let status = {
        match unsafe { DISPATCHER_PTR.as_mut() } {
            Some(dispatcher) => unsafe {
                dispatch_trusted_call_in(SHARED_MEMORY, descriptor_ptr, dispatcher)
            },
            None => manekey::security::trusted_status::BUSY,
        }
    };
    SelectedObserver::gateway_status(status);
    #[cfg(feature = "trustzone-secure-uart-user-key")]
    apply_secure_led();
    GATEWAY_ACTIVE.store(false, Ordering::Release);
    status
}
#[cfg(feature = "trustzone-secure-uart-user-key")]
fn apply_secure_led() {
    use manekey::presence::PresenceUiHint;
    let Some(led) = (unsafe { SECURE_LED_PTR.as_mut() }) else {
        return;
    };
    let on = USER_LED_STATUS.get() == PresenceUiHint::TouchRequired;

    led.set_level(if on { Level::Low } else { Level::High });
}
