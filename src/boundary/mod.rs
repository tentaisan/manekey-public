#[cfg(all(target_arch = "arm", target_os = "none", feature = "arm-m-frontend"))]
pub mod arm_m_frontend;
pub mod arm_m_mpu;
#[cfg(all(target_arch = "arm", target_os = "none", feature = "arm-m-thread-once"))]
pub mod arm_m_thread_once;
pub mod armv7_m_mpu;

#[cfg(all(
    target_arch = "arm",
    target_os = "none",
    feature = "trustzone-nonsecure-image"
))]
pub mod arm_gateway;
#[cfg(all(
    target_arch = "arm",
    target_os = "none",
    feature = "trustzone-secure-layout"
))]
pub mod arm_trustzone;
pub mod ble_bond_gateway;
pub mod copied_mailbox;
pub mod gateway;
pub mod local_trusted_call;
pub mod mailbox;
pub mod mailbox_backend;
pub mod pmp_stack;
#[cfg(all(
    target_arch = "riscv32",
    target_os = "none",
    feature = "riscv-ecall-backend"
))]
pub mod riscv_ecall;
#[cfg(feature = "riscv-pmp-event-mailbox")]
pub mod riscv_event_mailbox;
pub mod riscv_pmp;
pub mod storage_mailbox;
