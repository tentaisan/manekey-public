use manekey_rp::platform::rp2350::pmp::EcallIslandPmpConfig;

use super::pmp_trap_frame::TrapFrame;

const CSR_MSTATUS: u32 = 0x300;
const CSR_MIE: u32 = 0x304;

#[inline]
pub fn read_mstatus() -> usize {
    let value: usize;
    unsafe {
        core::arch::asm!("csrr {value}, mstatus", value = lateout(reg) value, options(nomem, nostack));
    }
    value
}

#[inline]
pub fn read_mie() -> usize {
    let value: usize;
    unsafe {
        core::arch::asm!("csrr {value}, mie", value = lateout(reg) value, options(nomem, nostack));
    }
    value
}

/// # Safety
/// Execute in M-mode with a configuration matching the active linker and exclusively owned PMP registers.
pub unsafe fn write_ecall_island_config(config: EcallIslandPmpConfig) {
    unsafe {
        core::arch::asm!(
            "csrw pmpaddr0, {user_text}",
            "csrw pmpaddr1, {shared}",
            "csrw pmpaddr2, {user_stack}",
            "csrw pmpaddr3, {usb_regs}",
            "csrw pmpaddr4, {usb_dpram}",
            "csrw pmpaddr5, {timer0}",
            "csrw pmpaddr6, {sio}",
            "csrw pmpcfg0, {cfg}",
            "csrw pmpcfg1, {cfg1}",
            "csrw 0xbd0, zero",
            "fence.i",
            user_text = in(reg) config.pmpaddr0,
            shared = in(reg) config.pmpaddr1,
            user_stack = in(reg) config.pmpaddr2,
            usb_regs = in(reg) config.pmpaddr3,
            usb_dpram = in(reg) config.pmpaddr4,
            timer0 = in(reg) config.pmpaddr5,
            sio = in(reg) config.pmpaddr6,
            cfg = in(reg) config.pmpcfg0,
            cfg1 = in(reg) config.pmpcfg1,
            options(nostack),
        );
    }
}

/// # Safety
/// The instruction address must cover four readable, stable bytes without address overflow.
pub unsafe fn can_emulate_privileged_csr(mepc: usize) -> bool {
    unsafe { decode_privileged_csr_instruction(mepc) }.is_some()
}

/// # Safety
/// Require four readable stable instruction bytes and a valid exclusively owned saved trap frame.
pub unsafe fn emulate_privileged_csr(mepc: usize, frame: *mut TrapFrame) -> bool {
    let Some(instruction) = (unsafe { decode_privileged_csr_instruction(mepc) }) else {
        return false;
    };
    let old_value = match instruction.csr {
        CSR_MSTATUS => read_mstatus() as u32,
        CSR_MIE => read_mie() as u32,
        _ => return false,
    };
    unsafe {
        if let Some(frame) = frame.as_mut() {
            if instruction.rd != 0 {
                frame.x[instruction.rd as usize] = old_value;
            }
        } else {
            return false;
        }
    }
    true
}

#[derive(Clone, Copy)]
struct CsrInstruction {
    csr: u32,
    rd: u8,
}

unsafe fn decode_privileged_csr_instruction(mepc: usize) -> Option<CsrInstruction> {
    if mepc & 1 != 0 {
        return None;
    }

    let low = unsafe { core::ptr::read_volatile(mepc as *const u16) } as u32;
    let high = unsafe { core::ptr::read_volatile((mepc + 2) as *const u16) } as u32;
    let raw = low | (high << 16);
    if raw & 0x7f != 0x73 {
        return None;
    }
    let funct3 = (raw >> 12) & 0x7;
    if funct3 == 0 {
        return None;
    }
    let csr = (raw >> 20) & 0xfff;
    if csr != CSR_MSTATUS && csr != CSR_MIE {
        return None;
    }
    Some(CsrInstruction {
        csr,
        rd: ((raw >> 7) & 0x1f) as u8,
    })
}
