#![no_std]
#![no_main]

#[cfg(not(any(
    feature = "up-always-present",
    feature = "up-gpio15",
    feature = "up-bootsel-experimental"
)))]
compile_error!("select one TrustZone user-presence provider");

#[cfg(any(
    all(feature = "up-always-present", feature = "up-gpio15"),
    all(feature = "up-always-present", feature = "up-bootsel-experimental"),
    all(feature = "up-gpio15", feature = "up-bootsel-experimental")
))]
compile_error!("TrustZone user-presence providers are mutually exclusive");

#[cfg(all(feature = "rp-internal-uart", feature = "up-gpio15"))]
compile_error!("NS UART delegates IO_BANK0; use Secure BOOTSEL, not IO_BANK0 GPIO15 presence");

use core::cell::RefCell;

use core::sync::atomic::{AtomicBool, Ordering};

use cortex_m::peripheral::scb::Exception;
use cortex_m_rt::{entry, exception};
use defmt_rtt as _;
#[cfg(feature = "up-gpio15")]
use embassy_rp::gpio::{Input, Pull};
use embassy_rp::{bind_interrupts, peripherals};
use embassy_time::Instant;
use manekey::boundary::arm_trustzone;
#[cfg(feature = "trustzone-usb-ble-secure-experimental")]
use manekey::boundary::ble_bond_gateway;
use manekey::ctaphid::entropy::HmacDrbgEntropy;
#[cfg(feature = "trusted-boundary-ml-dsa-fips204-experimental")]
use manekey::ctaphid::key_store::AdditionalSignaturePrivateKeyStore;

use manekey::ctaphid::pin_uv_auth::{
    JournaledPinUvAuthStorage, PinUvAuthTokenClock, StoredPinUvAuthProvider,
};
use manekey::ctaphid::storage;
use manekey::ctaphid::trusted::TrustedDispatcher;
use manekey::ctaphid::user_verification::UnavailableUserVerification;
#[cfg(feature = "up-always-present")]
use manekey::presence::AlwaysPresent;
use manekey::presence::DefmtPresenceObserver;
#[cfg(any(
    feature = "trustzone-cyw43-ui",
    feature = "trustzone-usb-ble-secure-experimental"
))]
use manekey::security::layout;
#[cfg(feature = "board-ui-experimental")]
use manekey::user_interface::UiPresenceObserver;
#[cfg(feature = "trustzone-usb-ble-secure-experimental")]
use manekey_rp::platform::rp::storage::SharedBleBondFlashStorage;
use manekey_rp::platform::rp::storage::{
    SharedFlashStorage, SharedPinUvAuthFlashStorage, SharedRpFlash,
};
#[cfg(feature = "up-gpio15")]
use manekey_rp::platform::rp::user_interface::GpioUserPresence;
#[cfg(feature = "board-ui-experimental")]
use manekey_rp::platform::rp::user_interface::RpGpio25Led;
#[cfg(feature = "up-bootsel-experimental")]
use manekey_rp::platform::rp::user_interface::{RpBootselPresence, rp_bootsel_presence};
use manekey_rp::platform::rp2350::arm_security;
use manekey_rp::platform::rp2350::crypto::ClientPinCrypto;
use manekey_rp::platform::rp2350::entropy::Rp2350Trng;
use panic_probe as _;
use static_cell::StaticCell;

bind_interrupts!(struct SecureIrqs {
    TRNG_IRQ => embassy_rp::trng::InterruptHandler<peripherals::TRNG>;
});

#[cfg(feature = "up-always-present")]
type SecureUserPresence = AlwaysPresent;

#[cfg(feature = "up-gpio15")]
type SecureUserPresence = GpioUserPresence<'static>;

#[cfg(feature = "up-bootsel-experimental")]
type SecureUserPresence = RpBootselPresence;

#[derive(Clone, Copy)]
struct SecureTokenClock;

impl PinUvAuthTokenClock for SecureTokenClock {
    fn now_ms(&self) -> u64 {
        Instant::now().as_millis()
    }
}

#[cfg(not(feature = "trusted-boundary-ml-dsa-fips204-experimental"))]
type SecurePrivateKeyStore = SecureClassicalPrivateKeyStore;

#[cfg(feature = "trusted-boundary-ml-dsa-fips204-experimental")]
type SecurePrivateKeyStore = AdditionalSignaturePrivateKeyStore<
    SecureClassicalPrivateKeyStore,
    manekey_rp::platform::rp2350::crypto::MlDsa,
>;

#[cfg(all())]
type SecureClassicalPrivateKeyStore = manekey_rp::platform::rp2350::key_store::ClassicalKeys<
    manekey_rp::platform::rp2350::managed_flash::SharedManagedKeyFlashStorage<'static>,
>;

#[cfg(feature = "board-ui-experimental")]
type SecurePresenceObserver = UiPresenceObserver<DefmtPresenceObserver, RpGpio25Led>;

#[cfg(all(
    not(feature = "board-ui-experimental"),
    not(feature = "trustzone-cyw43-ui")
))]
type SecurePresenceObserver = DefmtPresenceObserver;

#[cfg(feature = "trustzone-cyw43-ui")]
struct SecurePresenceObserver;
#[cfg(feature = "trustzone-cyw43-ui")]
impl manekey::presence::PresenceObserver for SecurePresenceObserver {
    fn on_presence_event(&mut self, event: manekey::presence::PresenceEvent) {
        unsafe {
            core::ptr::write_volatile(
                layout::PRESENCE_UI_HINT_ADDRESS as *mut u32,
                event.ui_hint() as u32,
            );
        }
        manekey::presence::PresenceObserver::on_presence_event(&mut DefmtPresenceObserver, event);
    }
}
#[cfg(all(feature = "trustzone-cyw43-ui", feature = "board-ui-experimental"))]
compile_error!("CYW43 TrustZone UI must not claim GPIO25 as an onboard LED");

type SecureDispatcher = TrustedDispatcher<
    SharedFlashStorage<'static>,
    SecureUserPresence,
    UnavailableUserVerification,
    StoredPinUvAuthProvider<
        JournaledPinUvAuthStorage<SharedPinUvAuthFlashStorage<'static>>,
        ClientPinCrypto,
        SecureTokenClock,
    >,
    SecurePrivateKeyStore,
    HmacDrbgEntropy<Rp2350Trng<'static, peripherals::TRNG>>,
    SecurePresenceObserver,
>;

static DISPATCHER: StaticCell<SecureDispatcher> = StaticCell::new();
static mut DISPATCHER_PTR: *mut SecureDispatcher = core::ptr::null_mut();

static GATEWAY_ACTIVE: AtomicBool = AtomicBool::new(false);

struct SecureGatewayLease;

impl SecureGatewayLease {
    fn try_acquire() -> Option<Self> {
        GATEWAY_ACTIVE
            .compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
            .ok()
            .map(|_| Self)
    }
}

impl Drop for SecureGatewayLease {
    fn drop(&mut self) {
        GATEWAY_ACTIVE.store(false, Ordering::Release);
    }
}
#[cfg(feature = "trustzone-usb-ble-secure-experimental")]
static mut BLE_BOND_STORE_PTR: *mut SharedBleBondFlashStorage<'static> = core::ptr::null_mut();

fn fault_wait() -> ! {
    loop {
        #[cfg(feature = "trustzone-usb-ble-secure-experimental")]
        core::hint::spin_loop();
        #[cfg(not(feature = "trustzone-usb-ble-secure-experimental"))]
        cortex_m::asm::wfi();
    }
}

#[exception]
fn SecureFault() {
    fault_wait()
}
#[exception]
fn BusFault() {
    fault_wait()
}
#[exception]
unsafe fn HardFault(_frame: &cortex_m_rt::ExceptionFrame) -> ! {
    fault_wait()
}

macro_rules! gateway_entry_trace {
    () => {
        ""
    };
}

core::arch::global_asm!(concat!(
    r#"
    .syntax unified
    .thumb

    .section .nsc,"ax",%progbits
    .balign 32
    .global tz_gateway_probe
    .type tz_gateway_probe,%function
    .thumb_func
tz_gateway_probe:
    sg
    b.w tz_gateway_probe_secure
    .balign 32, 0
    .size tz_gateway_probe, . - tz_gateway_probe


    .section .text.tz_gateway_probe_secure,"ax",%progbits
    .balign 4
    .type tz_gateway_probe_secure,%function
    .thumb_func
tz_gateway_probe_secure:
    push {{r4, lr}}
"#,
    gateway_entry_trace!(),
    r#"
    bl tz_gateway_probe_dispatch
    pop {{r4, lr}}
    movs r1, #0
    movs r2, #0
    movs r3, #0
    movs r12, #0
    bxns lr
    .size tz_gateway_probe_secure, . - tz_gateway_probe_secure
"#
));

#[cfg(feature = "trustzone-usb-ble-secure-experimental")]
core::arch::global_asm!(
    r#"
    .syntax unified
    .thumb
    .section .nsc,"ax",%progbits
    .balign 32
    .global tz_ble_bond_gateway
    .type tz_ble_bond_gateway,%function
    .thumb_func
tz_ble_bond_gateway:
    sg
    b.w tz_ble_bond_gateway_secure
    .balign 32, 0
    .size tz_ble_bond_gateway, . - tz_ble_bond_gateway

    .section .text.tz_ble_bond_gateway_secure,"ax",%progbits
    .balign 4
    .type tz_ble_bond_gateway_secure,%function
    .thumb_func
tz_ble_bond_gateway_secure:
    push {{r4, lr}}
    bl tz_ble_bond_gateway_dispatch
    pop {{r4, lr}}
    movs r1, #0
    movs r2, #0
    movs r3, #0
    movs r12, #0
    bxns lr
    .size tz_ble_bond_gateway_secure, . - tz_ble_bond_gateway_secure
"#
);

#[unsafe(no_mangle)]
/// # Safety
/// Enter through the matching NSC veneer with a live dispatcher; keep shared buffers stable against NS/DMA mutation.
/// All other Secure storage/crypto users must participate in the same serialization policy.
unsafe extern "C" fn tz_gateway_probe_dispatch(descriptor_ptr: u32) -> u32 {
    let Some(_lease) = SecureGatewayLease::try_acquire() else {
        return trusted_boundary::status::BUSY;
    };
    let Some(dispatcher) = (unsafe { DISPATCHER_PTR.as_mut() }) else {
        return trusted_boundary::status::BUSY;
    };
    let status = unsafe { arm_trustzone::dispatch_trusted_call(descriptor_ptr, dispatcher) };

    status
}

#[cfg(feature = "trustzone-usb-ble-secure-experimental")]
#[unsafe(no_mangle)]
/// # Safety
/// Enter through the matching NSC veneer with stable validated NS buffers and initialized bond/Flash state.
/// Both gateways share an exclusive lease; other Flash users must use the same serialization policy.
unsafe extern "C" fn tz_ble_bond_gateway_dispatch(operation: u32, buffer_ptr: u32) -> u32 {
    use cortex_m::cmse::{AccessType, TestTarget};
    use manekey::transport::ble::{BLE_BOND_RECORD_LEN, BleBondStore, StoredBleBond};

    let Some(_lease) = SecureGatewayLease::try_acquire() else {
        return ble_bond_gateway::STATUS_FAILED;
    };
    let Some(store) = (unsafe { BLE_BOND_STORE_PTR.as_mut() }) else {
        return ble_bond_gateway::STATUS_FAILED;
    };
    if operation == ble_bond_gateway::OP_CLEAR {
        return if buffer_ptr == 0 && store.clear_bonds() {
            ble_bond_gateway::STATUS_OK
        } else {
            ble_bond_gateway::STATUS_INVALID
        };
    }
    if !matches!(
        operation,
        ble_bond_gateway::OP_LOAD | ble_bond_gateway::OP_STORE
    ) {
        return ble_bond_gateway::STATUS_DENIED;
    }
    let Some(end) = buffer_ptr.checked_add(BLE_BOND_RECORD_LEN as u32) else {
        return ble_bond_gateway::STATUS_INVALID;
    };
    if buffer_ptr < layout::NONSECURE_RAM_START || end > layout::NONSECURE_RAM_END + 1 {
        return ble_bond_gateway::STATUS_INVALID;
    }
    let Some(target) = TestTarget::check_range(
        buffer_ptr as *mut u32,
        BLE_BOND_RECORD_LEN,
        AccessType::NonSecure,
    ) else {
        return ble_bond_gateway::STATUS_INVALID;
    };
    if !target.ns_read_and_writable() {
        return ble_bond_gateway::STATUS_INVALID;
    }

    if operation == ble_bond_gateway::OP_LOAD {
        let mut found = None;
        store.load_bonds(|bond| found = Some(bond));
        let Some(bond) = found else {
            return ble_bond_gateway::STATUS_NOT_FOUND;
        };
        let encoded = bond.encode();
        unsafe {
            core::ptr::copy_nonoverlapping(encoded.as_ptr(), buffer_ptr as *mut u8, encoded.len())
        };
        ble_bond_gateway::STATUS_OK
    } else {
        let mut encoded = [0u8; BLE_BOND_RECORD_LEN];
        unsafe {
            core::ptr::copy_nonoverlapping(
                buffer_ptr as *const u8,
                encoded.as_mut_ptr(),
                encoded.len(),
            )
        };
        let Some(bond) = StoredBleBond::decode(&encoded) else {
            return ble_bond_gateway::STATUS_INVALID;
        };
        if bond.is_bonded && store.store_bond(bond) {
            ble_bond_gateway::STATUS_OK
        } else {
            ble_bond_gateway::STATUS_FAILED
        }
    }
}

#[unsafe(link_section = ".start_block")]
#[used]
static RP2350_IMAGE_DEF: embassy_rp::block::Block<3> = {
    use embassy_rp::block::{
        Architecture, Block, Security, item_image_type_exe, item_vector_table,
    };

    let vector_table = item_vector_table(0x1000_0100);
    Block::new([
        item_image_type_exe(Security::Secure, Architecture::Arm),
        vector_table[0],
        vector_table[1],
    ])
};

#[entry]
/// Secure startup only with matching split-image linker layout and reserved journals.
/// Complete gateway/peripheral/IRQ attribution before NS handoff; fixed-ID keys are insecure legacy options.
fn main() -> ! {
    let p = embassy_rp::init(Default::default());
    #[cfg(feature = "rp-internal-uart")]
    {
        let mut config = embassy_rp::uart::Config::default();
        config.baudrate = 115_200;

        core::mem::forget(embassy_rp::uart::Uart::new_blocking(
            p.UART0, p.PIN_0, p.PIN_1, config,
        ));
    }
    static FLASH: StaticCell<SharedRpFlash<'static>> = StaticCell::new();
    let flash = FLASH.init(SharedRpFlash::new(RefCell::new(
        embassy_rp::flash::Flash::new_blocking(p.FLASH),
    )));
    #[cfg(feature = "trustzone-usb-ble-secure-experimental")]
    {
        static BLE_BOND_STORE: StaticCell<SharedBleBondFlashStorage<'static>> = StaticCell::new();
        let store = BLE_BOND_STORE.init(SharedBleBondFlashStorage::new(flash));
        unsafe { BLE_BOND_STORE_PTR = store };
    }
    #[allow(unused_mut)]
    let mut storage = storage::Storage::new(SharedFlashStorage::new(flash));
    #[cfg(feature = "rp2350-sha256-accelerator")]
    assert!(unsafe { manekey_rp::platform::rp2350::crypto::sha256_known_answers() });
    let pin_uv_auth = StoredPinUvAuthProvider::new_with_crypto_and_clock(
        JournaledPinUvAuthStorage::new(SharedPinUvAuthFlashStorage::new(flash)),
        unsafe { manekey_rp::platform::rp2350::crypto::client_pin_crypto() },
        SecureTokenClock,
    );
    #[cfg(feature = "up-always-present")]
    let presence = AlwaysPresent;
    #[cfg(feature = "up-gpio15")]
    let presence = GpioUserPresence::new(Input::new(p.PIN_15, Pull::Up));
    #[cfg(feature = "up-bootsel-experimental")]
    let presence = rp_bootsel_presence(p.BOOTSEL);
    let trng = Rp2350Trng::new(embassy_rp::trng::Trng::new(
        p.TRNG,
        SecureIrqs,
        Default::default(),
    ));
    #[allow(unused_mut)]
    let mut entropy = HmacDrbgEntropy::new(trng).expect("seed Secure HMAC-DRBG from RP2350 TRNG");

    #[cfg(all())]
    let key_store = unsafe {
        manekey_rp::platform::rp2350::key_store::open_classical(
            manekey_rp::platform::rp2350::managed_flash::SharedManagedKeyFlashStorage::new(flash),
            &mut storage,
            &mut entropy,
        )
    }
    .expect("RP Secure managed keys");
    #[cfg(feature = "trusted-boundary-ml-dsa-fips204-experimental")]
    let key_store = AdditionalSignaturePrivateKeyStore::new(
        key_store,
        manekey_rp::platform::rp2350::crypto::ml_dsa(),
    );
    #[cfg(feature = "board-ui-experimental")]
    let presence_observer =
        UiPresenceObserver::new(DefmtPresenceObserver, RpGpio25Led::new(p.PIN_25));
    #[cfg(all(
        not(feature = "board-ui-experimental"),
        not(feature = "trustzone-cyw43-ui")
    ))]
    let presence_observer = DefmtPresenceObserver;
    #[cfg(feature = "trustzone-cyw43-ui")]
    let presence_observer = SecurePresenceObserver;
    let dispatcher = DISPATCHER.init_with(|| {
        TrustedDispatcher::new_with_transports_and_presence_observer(
            storage,
            presence,
            UnavailableUserVerification,
            pin_uv_auth,
            key_store,
            entropy,
            if cfg!(feature = "trustzone-usb-ble-secure-experimental") {
                manekey::transport::USB_BLE_TRANSPORTS
            } else {
                manekey::transport::USB_TRANSPORTS
            },
            presence_observer,
        )
    });
    unsafe {
        DISPATCHER_PTR = dispatcher;
    }
    let mut core = cortex_m::Peripherals::take().expect("take Cortex-M peripherals");
    core.SCB.enable(Exception::SecureFault);
    core.SCB.enable(Exception::BusFault);

    arm_security::grant_arm_fpu_to_nonsecure();

    unsafe {
        #[cfg(feature = "trustzone-cyw43-ui")]
        core::ptr::write_volatile(layout::PRESENCE_UI_HINT_ADDRESS as *mut u32, 0);
        let vector = arm_security::read_nonsecure_vector();

        arm_security::configure_rp2350_memory_access();

        arm_security::grant_rp2350_usb_to_nonsecure();

        arm_security::grant_rp2350_timer0_alarm0_to_nonsecure();

        #[cfg(feature = "trustzone-usb-ble-secure-experimental")]
        arm_security::grant_rp2350_cyw43_to_nonsecure();
        #[cfg(feature = "rp-internal-uart")]
        arm_security::grant_rp2350_uart0_to_nonsecure();

        arm_security::handoff_arm_nonsecure(&mut core.SAU, vector)
    }
}

#[cfg(not(feature = "rp2350-flash-managed-keys"))]
compile_error!("Public products require rp2350-flash-managed-keys");
