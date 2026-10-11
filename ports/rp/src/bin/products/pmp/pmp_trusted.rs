#[cfg(feature = "riscv-pmp-trusted-trng")]
use manekey::ctaphid::entropy::HmacDrbgEntropy;

#[cfg(all(not(feature = "riscv-pmp-trusted-trng"), not(any())))]
compile_error!("PMP products require real TRNG; deterministic entropy is diagnostic-only");

#[cfg(not(feature = "riscv-pmp-trusted-pin-uv"))]
use manekey::ctaphid::pin_uv_auth::UnconfiguredPinUvAuth;
#[cfg(feature = "riscv-pmp-trusted-pin-uv")]
use manekey::ctaphid::pin_uv_auth::{JournaledPinUvAuthStorage, StoredPinUvAuthProvider};
#[cfg(not(feature = "riscv-pmp-trusted-flash-storage"))]
use manekey::ctaphid::storage::StubStorage;
use manekey::ctaphid::{
    storage::Storage, trusted::TrustedDispatcher, user_verification::UnavailableUserVerification,
};
#[cfg(all(
    not(any()),
    any(
        feature = "up-always-present",
        all(
            not(feature = "riscv-pmp-trusted-gpio15-presence"),
            not(feature = "riscv-pmp-trusted-bootsel-presence")
        )
    )
))]
use manekey::presence::AlwaysPresent;
#[cfg(not(feature = "riscv-pmp-ble-monitor-frontend-io"))]
use manekey::presence::NoPresenceObserver;

#[cfg(feature = "riscv-pmp-board-ui-experimental")]
use manekey::user_interface::UiPresenceObserver;
#[cfg(feature = "riscv-pmp-ble-monitor-bond-storage")]
use manekey_rp::platform::rp::storage::RiscvBleBondFlashStorage;
#[cfg(feature = "riscv-pmp-trusted-flash-storage")]
use manekey_rp::platform::rp::storage::RiscvFlashStorage;
#[cfg(feature = "riscv-pmp-trusted-pin-uv")]
use manekey_rp::platform::rp::storage::RiscvPinUvAuthFlashStorage;
#[cfg(all(
    feature = "riscv-pmp-trusted-bootsel-presence",
    not(feature = "up-always-present")
))]
use manekey_rp::platform::rp::user_interface::RiscvPmpBootselPresence;
#[cfg(feature = "riscv-pmp-board-ui-experimental")]
use manekey_rp::platform::rp::user_interface::RiscvSioGpio25Led;
#[cfg(feature = "riscv-pmp-trusted-trng")]
use manekey_rp::platform::rp2350::entropy::{RiscvTrng, riscv_entropy_error};
#[cfg(all(
    feature = "riscv-pmp-trusted-gpio15-presence",
    not(feature = "up-always-present")
))]
use manekey_rp::platform::rp2350::riscv_dual_core::RawGpio15UserPresence;
#[cfg(feature = "riscv-pmp-trusted-pin-uv")]
use manekey_rp::platform::rp2350::riscv_token_clock::Rp2350RiscvTokenClock;

use static_cell::StaticCell;
use trusted_boundary::status;

#[cfg(feature = "riscv-pmp-ble-monitor-bond-storage")]
use manekey::transport::ble::{BLE_BOND_RECORD_LEN, BleBondStore, StoredBleBond};

#[cfg(not(feature = "riscv-pmp-ble-monitor-image"))]
use super::pmp_memory::{__pmp_shared_end, __pmp_shared_start};

type PmpTrustedDispatcher = TrustedDispatcher<
    PmpStorageBackend,
    PmpUserPresence,
    UnavailableUserVerification,
    PmpPinUvAuthProvider,
    PmpPrivateKeyStore,
    PmpEntropy,
    PmpPresenceObserver,
>;
#[cfg(feature = "riscv-pmp-board-ui-experimental")]
type PmpPresenceObserver = UiPresenceObserver<NoPresenceObserver, RiscvSioGpio25Led>;
#[cfg(all(
    not(feature = "riscv-pmp-board-ui-experimental"),
    not(feature = "riscv-pmp-ble-monitor-frontend-io")
))]
type PmpPresenceObserver = NoPresenceObserver;
#[cfg(feature = "riscv-pmp-ble-monitor-frontend-io")]
type PmpPresenceObserver = manekey_rp::platform::rp2350::riscv_ui::PresenceObserver;

#[cfg(all(
    feature = "riscv-pmp-board-ui-experimental",
    feature = "riscv-pmp-ble-monitor-frontend-io"
))]
compile_error!("select GPIO25 UI or split CYW43 UI, not both");

#[cfg(feature = "riscv-pmp-ble-monitor-frontend-io")]
pub(super) fn presence_pending() -> bool {
    manekey_rp::platform::rp2350::riscv_ui::PRESENCE_UI.get()
        == manekey::presence::PresenceUiHint::TouchRequired
}
#[cfg(feature = "riscv-pmp-trusted-flash-storage")]
type PmpStorageBackend = RiscvFlashStorage;
#[cfg(not(feature = "riscv-pmp-trusted-flash-storage"))]
type PmpStorageBackend = StubStorage;
#[cfg(feature = "riscv-pmp-trusted-pin-uv")]
type PmpPinUvAuthProvider = StoredPinUvAuthProvider<
    JournaledPinUvAuthStorage<RiscvPinUvAuthFlashStorage>,
    manekey_rp::platform::rp2350::riscv_crypto::ClientPinCrypto,
    Rp2350RiscvTokenClock,
>;
#[cfg(not(feature = "riscv-pmp-trusted-pin-uv"))]
type PmpPinUvAuthProvider = UnconfiguredPinUvAuth;

#[cfg(all())]
type PmpPrivateKeyStore = manekey_rp::platform::rp2350::key_store::Keys<
    manekey_rp::platform::rp::storage::RiscvManagedKeyFlashStorage,
>;
#[cfg(all(
    all(),
    not(all(
        feature = "riscv-pmp-trusted-trng",
        feature = "riscv-pmp-trusted-flash-storage"
    ))
))]
compile_error!("PMP managed keys require real TRNG and trusted Flash storage");

#[cfg(all(
    not(any()),
    not(feature = "up-always-present"),
    feature = "riscv-pmp-trusted-gpio15-presence"
))]
type PmpUserPresence = RawGpio15UserPresence;
#[cfg(all(
    not(any()),
    not(feature = "up-always-present"),
    feature = "riscv-pmp-trusted-bootsel-presence"
))]
type PmpUserPresence = RiscvPmpBootselPresence;
#[cfg(all(
    not(any()),
    any(
        feature = "up-always-present",
        all(
            not(feature = "riscv-pmp-trusted-gpio15-presence"),
            not(feature = "riscv-pmp-trusted-bootsel-presence")
        )
    )
))]
type PmpUserPresence = AlwaysPresent;
#[cfg(feature = "riscv-pmp-trusted-trng")]
type PmpEntropy = HmacDrbgEntropy<RiscvTrng>;

static PMP_TRUSTED_DISPATCHER: StaticCell<PmpTrustedDispatcher> = StaticCell::new();
static mut PMP_TRUSTED_DISPATCHER_PTR: *mut PmpTrustedDispatcher = core::ptr::null_mut();

#[inline(never)]
/// Initialize once in M-mode with exclusive TRNG/SHA/Flash and reserved journals before accepting user calls.
/// Managed keys require real entropy; non-TRNG fallback is diagnostic-only, while fixed-ID keys are insecure legacy options.
pub(super) fn init_pmp_trusted_dispatcher(
    #[cfg(feature = "riscv-pmp-trusted-trng")] trng: rp235x_hal::pac::TRNG,
) -> Result<(), u32> {
    #[cfg(feature = "riscv-pmp-trusted-trng")]
    #[allow(unused_mut)]
    let mut entropy =
        HmacDrbgEntropy::new(RiscvTrng::new(trng)).map_err(|_| riscv_entropy_error())?;

    #[allow(unused_mut)]
    let mut records = pmp_storage();
    #[cfg(all())]
    let keys = unsafe {
        manekey_rp::platform::rp2350::key_store::open(
            manekey_rp::platform::rp::storage::RiscvManagedKeyFlashStorage,
            &mut records,
            &mut entropy,
        )
    }
    .map_err(|_| 0xffff_fff9_u32)?;

    #[cfg(feature = "riscv-pmp-board-ui-experimental")]
    let presence_observer = UiPresenceObserver::new(NoPresenceObserver, RiscvSioGpio25Led::new());
    #[cfg(all(
        not(feature = "riscv-pmp-board-ui-experimental"),
        not(feature = "riscv-pmp-ble-monitor-frontend-io")
    ))]
    let presence_observer = NoPresenceObserver;
    #[cfg(feature = "riscv-pmp-ble-monitor-frontend-io")]
    let presence_observer = manekey_rp::platform::rp2350::riscv_ui::presence_observer();
    #[cfg(feature = "riscv-pmp-ble-monitor-multi-transport-ml-dsa-fips204-experimental")]
    let dispatcher = TrustedDispatcher::new_with_transports_and_presence_observer(
        records,
        pmp_user_presence(),
        UnavailableUserVerification,
        pmp_pin_uv_auth(),
        keys,
        entropy,
        manekey::transport::USB_BLE_TRANSPORTS,
        presence_observer,
    );
    #[cfg(all(
        feature = "riscv-pmp-ble-monitor-image",
        not(feature = "riscv-pmp-ble-monitor-multi-transport-ml-dsa-fips204-experimental")
    ))]
    let dispatcher = TrustedDispatcher::new_with_transports_and_presence_observer(
        records,
        pmp_user_presence(),
        UnavailableUserVerification,
        pmp_pin_uv_auth(),
        keys,
        entropy,
        manekey::transport::BLE_TRANSPORTS,
        presence_observer,
    );
    #[cfg(not(feature = "riscv-pmp-ble-monitor-image"))]
    let dispatcher = TrustedDispatcher::new_with_transports_and_presence_observer(
        records,
        pmp_user_presence(),
        UnavailableUserVerification,
        pmp_pin_uv_auth(),
        keys,
        entropy,
        manekey::transport::USB_TRANSPORTS,
        presence_observer,
    );
    let pmp_trusted_dispatcher = PMP_TRUSTED_DISPATCHER.init(dispatcher);
    unsafe {
        PMP_TRUSTED_DISPATCHER_PTR = pmp_trusted_dispatcher as *mut PmpTrustedDispatcher;
    }
    Ok(())
}

#[cfg(feature = "riscv-pmp-trusted-flash-storage")]
fn pmp_storage() -> Storage<PmpStorageBackend> {
    Storage::new(RiscvFlashStorage::new())
}

#[cfg(feature = "riscv-pmp-trusted-pin-uv")]
fn pmp_pin_uv_auth() -> PmpPinUvAuthProvider {
    StoredPinUvAuthProvider::new_with_crypto_and_clock(
        JournaledPinUvAuthStorage::new(RiscvPinUvAuthFlashStorage::new()),
        unsafe { manekey_rp::platform::rp2350::riscv_crypto::client_pin_crypto() },
        Rp2350RiscvTokenClock,
    )
}

#[cfg(not(feature = "riscv-pmp-trusted-pin-uv"))]
fn pmp_pin_uv_auth() -> PmpPinUvAuthProvider {
    UnconfiguredPinUvAuth::new()
}

#[cfg(not(feature = "riscv-pmp-trusted-flash-storage"))]
fn pmp_storage() -> Storage<PmpStorageBackend> {
    Storage::new(StubStorage::new())
}

fn pmp_user_presence() -> PmpUserPresence {
    #[cfg(feature = "up-always-present")]
    return AlwaysPresent;
    #[cfg(all(
        feature = "riscv-pmp-trusted-gpio15-presence",
        not(feature = "up-always-present")
    ))]
    return RawGpio15UserPresence::new();
    #[cfg(all(
        feature = "riscv-pmp-trusted-bootsel-presence",
        not(feature = "up-always-present")
    ))]
    return RiscvPmpBootselPresence::new();
    #[cfg(all(
        not(feature = "up-always-present"),
        not(any(
            feature = "riscv-pmp-trusted-gpio15-presence",
            feature = "riscv-pmp-trusted-bootsel-presence"
        ))
    ))]
    AlwaysPresent
}

/// # Safety
/// M-mode trap context only, with a live exclusively owned dispatcher and matching shared-memory policy.
/// Exclude concurrent user/DMA mutation throughout descriptor validation and dispatch.
pub unsafe fn dispatch_pmp_trusted_call(descriptor_ptr: u32) -> u32 {
    #[cfg(feature = "riscv-pmp-ble-monitor-image")]
    let shared_memory = trusted_boundary::SharedMemoryRegion {
        start: manekey_rp::platform::rp2350::pmp::PMP_BLE_USER_WRITABLE_RAM_BASE as u32,
        end: manekey_rp::platform::rp2350::pmp::PMP_BLE_USER_WRITABLE_RAM_END as u32,
    };
    #[cfg(not(feature = "riscv-pmp-ble-monitor-image"))]
    let shared_memory = trusted_boundary::SharedMemoryRegion {
        start: (&raw const __pmp_shared_start) as u32,
        end: (&raw const __pmp_shared_end) as u32,
    };
    let backend = unsafe {
        let ptr = PMP_TRUSTED_DISPATCHER_PTR;
        if ptr.is_null() {
            return status::BUSY;
        }
        &mut *ptr
    };
    unsafe {
        manekey::security::dispatch_trusted_call_from_shared(shared_memory, descriptor_ptr, backend)
    }
}

/// # Safety
/// M-mode trap context only; exclusively own bond Flash and validated user buffers during copies.
/// Exclude concurrent DMA/user mutation; bond storage is transport-owned, not private-key isolation.
pub unsafe fn dispatch_pmp_ble_bond(operation: u32, buffer_ptr: u32) -> u32 {
    use manekey::boundary::riscv_pmp::BLE_BOND_STATUS_DENIED;
    #[cfg(feature = "riscv-pmp-ble-monitor-bond-storage")]
    use manekey::boundary::riscv_pmp::{
        BLE_BOND_OP_CLEAR, BLE_BOND_OP_LOAD, BLE_BOND_OP_STORE, BLE_BOND_STATUS_FAILED,
        BLE_BOND_STATUS_INVALID, BLE_BOND_STATUS_NOT_FOUND, BLE_BOND_STATUS_OK,
    };

    #[cfg(not(feature = "riscv-pmp-ble-monitor-bond-storage"))]
    {
        let _ = (operation, buffer_ptr);
        return BLE_BOND_STATUS_DENIED;
    }

    #[cfg(feature = "riscv-pmp-ble-monitor-bond-storage")]
    {
        let mut storage = RiscvBleBondFlashStorage::new();
        match operation {
            BLE_BOND_OP_LOAD | BLE_BOND_OP_STORE => {
                if !manekey::boundary::riscv_pmp::fixed_buffer_is_in_region(
                    buffer_ptr,
                    BLE_BOND_RECORD_LEN,
                    manekey_rp::platform::rp2350::pmp::PMP_BLE_USER_WRITABLE_RAM_BASE,
                    manekey_rp::platform::rp2350::pmp::PMP_BLE_USER_WRITABLE_RAM_END,
                ) {
                    return BLE_BOND_STATUS_INVALID;
                }

                if operation == BLE_BOND_OP_LOAD {
                    let mut loaded = None;
                    storage.load_bonds(|bond| loaded = Some(bond));
                    let Some(bond) = loaded else {
                        return BLE_BOND_STATUS_NOT_FOUND;
                    };
                    let encoded = bond.encode();
                    unsafe {
                        core::ptr::copy_nonoverlapping(
                            encoded.as_ptr(),
                            buffer_ptr as *mut u8,
                            encoded.len(),
                        );
                    }
                    BLE_BOND_STATUS_OK
                } else {
                    let mut encoded = [0u8; BLE_BOND_RECORD_LEN];
                    unsafe {
                        core::ptr::copy_nonoverlapping(
                            buffer_ptr as *const u8,
                            encoded.as_mut_ptr(),
                            encoded.len(),
                        );
                    }
                    let Some(bond) = StoredBleBond::decode(&encoded).filter(|bond| bond.is_bonded)
                    else {
                        return BLE_BOND_STATUS_INVALID;
                    };
                    if storage.store_bond(bond) {
                        BLE_BOND_STATUS_OK
                    } else {
                        BLE_BOND_STATUS_FAILED
                    }
                }
            }
            BLE_BOND_OP_CLEAR if buffer_ptr == 0 => {
                if storage.clear_bonds() {
                    BLE_BOND_STATUS_OK
                } else {
                    BLE_BOND_STATUS_FAILED
                }
            }
            BLE_BOND_OP_CLEAR => BLE_BOND_STATUS_INVALID,
            _ => BLE_BOND_STATUS_DENIED,
        }
    }
}

#[cfg(not(feature = "riscv-flash-managed-keys"))]
compile_error!("Public products require riscv-flash-managed-keys");
