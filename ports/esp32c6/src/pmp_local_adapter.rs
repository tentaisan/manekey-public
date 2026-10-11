use manekey::{
    boundary::{
        local_trusted_call::{LocalTrustedCallBackend, SharedTrustedCallState},
        riscv_ecall::RiscvPmpEcallBackend,
    },
    transport::ble::BleFidoFrontend,
};

pub const TRUSTED_CALL_ECALL_ID: u32 = 0x4336_ec10;

pub const BLE_FRAGMENT_LEN: usize = 20;

pub type C6PmpEcallBackend = RiscvPmpEcallBackend;
pub type C6PmpBleFrontend = BleFidoFrontend<C6PmpEcallBackend>;

const _: () = assert!(
    core::mem::size_of::<C6PmpEcallBackend>()
        <= manekey::boundary::riscv_pmp::SHARED_CALL_REGION_SOFT_LIMIT
);

/// Requires the matching M-mode monitor, shared allocation and installed PMP/trap policy.
pub const fn new_ecall_backend() -> C6PmpEcallBackend {
    C6PmpEcallBackend::new(TRUSTED_CALL_ECALL_ID)
}

/// Protocol composition only; does not provide a U-mode BLE peripheral runtime.
pub const fn new_ble_frontend() -> C6PmpBleFrontend {
    C6PmpBleFrontend::new(BLE_FRAGMENT_LEN, new_ecall_backend())
}

pub type C6PmpSharedCallState = SharedTrustedCallState;
pub type C6PmpMonitorBackend<'a, T> = LocalTrustedCallBackend<'a, T>;
