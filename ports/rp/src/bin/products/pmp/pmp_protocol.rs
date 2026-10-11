use manekey::boundary::riscv_pmp;

pub const PMP_ECALL_TRUSTED_CALL_ID: u32 = riscv_pmp::TRUSTED_CALL_ECALL_ID;
pub const PMP_ECALL_BYTE_IO_ID: u32 = riscv_pmp::BYTE_IO_ECALL_ID;
pub const PMP_ECALL_PRESENCE_PENDING_ID: u32 = riscv_pmp::PRESENCE_PENDING_ECALL_ID;
pub const PMP_ECALL_BLE_BOND_ID: u32 = riscv_pmp::BLE_BOND_ECALL_ID;

pub const PMP_ECALL_BLE_SPLIT_ENTRY_ID: u32 = riscv_pmp::BLE_SPLIT_ENTRY_ECALL_ID;
pub const PMP_ECALL_CYW43_GPIO_ID: u32 = riscv_pmp::CYW43_GPIO_ECALL_ID;
pub const PMP_ECALL_TIMER_STATUS_ID: u32 = riscv_pmp::TIMER_STATUS_ECALL_ID;
pub const PMP_ECALL_TIMER_ARM_ID: u32 = riscv_pmp::TIMER_ARM_ECALL_ID;
pub const PMP_ECALL_TIMER_REARM_ID: u32 = riscv_pmp::TIMER_REARM_ECALL_ID;
pub const PMP_ECALL_DMA_IRQ_STATUS_ID: u32 = riscv_pmp::DMA_IRQ_STATUS_ECALL_ID;
