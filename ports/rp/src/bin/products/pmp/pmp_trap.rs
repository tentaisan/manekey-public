use super::pmp_csr::emulate_privileged_csr;
#[cfg(feature = "riscv-pmp-ble-mmio-runtime")]
use super::pmp_gpio;
use super::pmp_protocol::*;
use super::pmp_trap_frame::TrapFrame;
use super::pmp_trusted;

const MCAUSE_INSTRUCTION_ACCESS_FAULT: usize = 1;
const MCAUSE_LOAD_ACCESS_FAULT: usize = 5;
const MCAUSE_STORE_ACCESS_FAULT: usize = 7;
const MCAUSE_USER_ECALL: usize = 8;
const MCAUSE_MACHINE_EXTERNAL_INTERRUPT: usize = (1usize << (usize::BITS - 1)) | 11;

#[derive(Clone, Copy)]
pub(super) enum TrapPolicy {
    Kill,
    UnsupportedEcall,
    ExpectedTerminalEcall,
    EmulatePrivilegedCsr,

    ResumeCyw43Gpio,
    ResumeTimerArm,
    ResumeTimerRearm,
    ResumeTimerStatus,
    ResumeDmaIrqStatus,
    ResumeTimerInterrupt,
    ResumeTrustedCall,
    ResumeBleBond,
    ResumeByteIo,
    ResumePresencePending,
}

impl TrapPolicy {}

/// Monitor-internal policy selection; frame must be the valid exclusive snapshot saved by trap assembly.
pub(super) fn trap_policy(
    mcause: usize,
    frame: *const TrapFrame,
    can_emulate_privileged_csr: bool,
) -> TrapPolicy {
    match mcause {
        MCAUSE_USER_ECALL => unsafe {
            match frame.as_ref().map(|frame| frame.x[10]) {
                Some(PMP_ECALL_CYW43_GPIO_ID) if cfg!(feature = "riscv-pmp-ble-mmio-runtime") => {
                    TrapPolicy::ResumeCyw43Gpio
                }
                Some(PMP_ECALL_TIMER_STATUS_ID) if cfg!(feature = "riscv-pmp-ble-mmio-runtime") => {
                    TrapPolicy::ResumeTimerStatus
                }
                Some(PMP_ECALL_TIMER_ARM_ID) if cfg!(feature = "riscv-pmp-ble-mmio-runtime") => {
                    TrapPolicy::ResumeTimerArm
                }
                Some(PMP_ECALL_TIMER_REARM_ID) if cfg!(feature = "riscv-pmp-ble-mmio-runtime") => {
                    TrapPolicy::ResumeTimerRearm
                }
                Some(PMP_ECALL_DMA_IRQ_STATUS_ID)
                    if cfg!(feature = "riscv-pmp-ble-monitor-dma-irq") =>
                {
                    TrapPolicy::ResumeDmaIrqStatus
                }
                Some(PMP_ECALL_TRUSTED_CALL_ID) => TrapPolicy::ResumeTrustedCall,
                Some(PMP_ECALL_BYTE_IO_ID)
                    if cfg!(any(
                        feature = "riscv-pmp-ble-monitor-frontend-io",
                        feature = "riscv-pmp-usb-internal-ccid"
                    )) =>
                {
                    TrapPolicy::ResumeByteIo
                }
                Some(PMP_ECALL_PRESENCE_PENDING_ID)
                    if cfg!(feature = "riscv-pmp-ble-monitor-frontend-io") =>
                {
                    TrapPolicy::ResumePresencePending
                }
                Some(PMP_ECALL_BLE_BOND_ID)
                    if cfg!(feature = "riscv-pmp-ble-monitor-bond-storage") =>
                {
                    TrapPolicy::ResumeBleBond
                }

                Some(PMP_ECALL_BLE_SPLIT_ENTRY_ID) => TrapPolicy::ExpectedTerminalEcall,
                _ => TrapPolicy::UnsupportedEcall,
            }
        },
        MCAUSE_INSTRUCTION_ACCESS_FAULT | MCAUSE_LOAD_ACCESS_FAULT | MCAUSE_STORE_ACCESS_FAULT => {
            TrapPolicy::Kill
        }
        MCAUSE_MACHINE_EXTERNAL_INTERRUPT if cfg!(feature = "riscv-pmp-ble-mmio-runtime") => {
            TrapPolicy::ResumeTimerInterrupt
        }
        2 if cfg!(feature = "riscv-pmp-usb-frontend") && can_emulate_privileged_csr => {
            TrapPolicy::EmulatePrivilegedCsr
        }
        _ => TrapPolicy::Kill,
    }
}

#[derive(Clone, Copy)]
pub(super) enum TrapAction {
    Halt,
    Resume { next_mepc: usize },
}

impl TrapAction {
    pub fn next_mepc(self) -> Option<usize> {
        match self {
            TrapAction::Halt => None,
            TrapAction::Resume { next_mepc } => Some(next_mepc),
        }
    }
}

/// Apply only in M-mode to a valid saved frame and a checked instruction address; IRQ resume preserves PC.
pub(super) fn trap_action(policy: TrapPolicy, mepc: usize, frame: *mut TrapFrame) -> TrapAction {
    match policy {
        TrapPolicy::EmulatePrivilegedCsr => {
            if unsafe { emulate_privileged_csr(mepc, frame) } {
                TrapAction::Resume {
                    next_mepc: mepc + 4,
                }
            } else {
                TrapAction::Halt
            }
        }

        TrapPolicy::ResumeCyw43Gpio => {
            unsafe {
                if let Some(frame) = frame.as_mut() {
                    #[cfg(feature = "riscv-pmp-ble-mmio-runtime")]
                    {
                        frame.x[10] = pmp_gpio::dispatch_cyw43_gpio(frame.x[11]);
                    }
                    #[cfg(not(feature = "riscv-pmp-ble-mmio-runtime"))]
                    {
                        frame.x[10] = manekey::boundary::riscv_pmp::CYW43_GPIO_STATUS_DENIED;
                    }
                }
            }
            TrapAction::Resume {
                next_mepc: mepc + 4,
            }
        }
        TrapPolicy::ResumeTimerStatus => {
            unsafe {
                if let Some(frame) = frame.as_mut() {
                    #[cfg(feature = "riscv-pmp-ble-mmio-runtime")]
                    {
                        frame.x[10] = super::pmp_timer::timer_generation();
                    }
                    #[cfg(not(feature = "riscv-pmp-ble-mmio-runtime"))]
                    {
                        frame.x[10] = 0;
                    }
                }
            }
            TrapAction::Resume {
                next_mepc: mepc + 4,
            }
        }
        TrapPolicy::ResumeTimerArm => {
            unsafe {
                if let Some(frame) = frame.as_mut() {
                    #[cfg(feature = "riscv-pmp-ble-mmio-runtime")]
                    {
                        frame.x[10] = super::pmp_timer::arm_timer(frame.x[11], frame.x[12]);
                    }
                    #[cfg(not(feature = "riscv-pmp-ble-mmio-runtime"))]
                    {
                        frame.x[10] = manekey::boundary::riscv_pmp::TIMER_STATUS_DENIED;
                    }
                }
            }
            TrapAction::Resume {
                next_mepc: mepc + 4,
            }
        }
        TrapPolicy::ResumeTimerRearm => {
            unsafe {
                if let Some(frame) = frame.as_mut() {
                    #[cfg(feature = "riscv-pmp-ble-mmio-runtime")]
                    {
                        frame.x[10] = super::pmp_timer::rearm_timer(frame.x[11], frame.x[12]);
                    }
                    #[cfg(not(feature = "riscv-pmp-ble-mmio-runtime"))]
                    {
                        frame.x[10] = manekey::boundary::riscv_pmp::TIMER_STATUS_DENIED;
                    }
                }
            }
            TrapAction::Resume {
                next_mepc: mepc + 4,
            }
        }
        TrapPolicy::ResumeDmaIrqStatus => {
            unsafe {
                if let Some(frame) = frame.as_mut() {
                    #[cfg(feature = "riscv-pmp-ble-monitor-dma-irq")]
                    {
                        if frame.x[11] == 1 {
                            manekey_rp::platform::rp2350::pmp_dma::rearm_dma_irq0();
                        }
                        frame.x[10] = manekey_rp::platform::rp2350::pmp_dma::dma_irq_generation();
                    }
                    #[cfg(not(feature = "riscv-pmp-ble-monitor-dma-irq"))]
                    {
                        frame.x[10] = 0;
                    }
                }
            }
            TrapAction::Resume {
                next_mepc: mepc + 4,
            }
        }
        TrapPolicy::ResumeTimerInterrupt => {
            #[cfg(feature = "riscv-pmp-ble-mmio-runtime")]
            if super::pmp_timer::handle_machine_external() {
                return TrapAction::Resume { next_mepc: mepc };
            }
            TrapAction::Halt
        }
        TrapPolicy::ResumeTrustedCall => {
            unsafe {
                if let Some(frame) = frame.as_mut() {
                    let descriptor_ptr = frame.x[11];
                    frame.x[10] = pmp_trusted::dispatch_pmp_trusted_call(descriptor_ptr);
                }
            }
            TrapAction::Resume {
                next_mepc: mepc + 4,
            }
        }
        TrapPolicy::ResumeByteIo => {
            unsafe {
                if let Some(frame) = frame.as_mut() {
                    #[cfg(any(
                        feature = "riscv-pmp-ble-monitor-frontend-io",
                        feature = "riscv-pmp-usb-internal-ccid"
                    ))]
                    {
                        frame.x[10] = super::pmp_uart::dispatch_byte_io(frame.x[11], frame.x[12]);
                    }
                    #[cfg(not(any(
                        feature = "riscv-pmp-ble-monitor-frontend-io",
                        feature = "riscv-pmp-usb-internal-ccid"
                    )))]
                    {
                        frame.x[10] = manekey::boundary::riscv_pmp::BYTE_IO_DENIED;
                    }
                }
            }
            TrapAction::Resume {
                next_mepc: mepc + 4,
            }
        }
        TrapPolicy::ResumePresencePending => {
            unsafe {
                if let Some(frame) = frame.as_mut() {
                    #[cfg(feature = "riscv-pmp-ble-monitor-frontend-io")]
                    {
                        frame.x[10] = if frame.x[11] == 0 && frame.x[12] == 0 {
                            pmp_trusted::presence_pending() as u32
                        } else {
                            manekey::boundary::riscv_pmp::BYTE_IO_DENIED
                        };
                    }
                    #[cfg(not(feature = "riscv-pmp-ble-monitor-frontend-io"))]
                    {
                        frame.x[10] = manekey::boundary::riscv_pmp::BYTE_IO_DENIED;
                    }
                }
            }
            TrapAction::Resume {
                next_mepc: mepc + 4,
            }
        }
        TrapPolicy::ResumeBleBond => {
            unsafe {
                if let Some(frame) = frame.as_mut() {
                    frame.x[10] = pmp_trusted::dispatch_pmp_ble_bond(frame.x[11], frame.x[12]);
                }
            }
            TrapAction::Resume {
                next_mepc: mepc + 4,
            }
        }
        TrapPolicy::Kill | TrapPolicy::UnsupportedEcall | TrapPolicy::ExpectedTerminalEcall => {
            TrapAction::Halt
        }
    }
}
