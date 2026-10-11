use super::pmp_memory::{MachineTrapStack, RISCV_PMP_M_TRAP_STACK, RISCV_PMP_U_STACK, UserStack};
use manekey::boundary::pmp_stack::MachineTrapStack as CommonMachineTrapStack;

const MSTATUS_MPP_MASK: usize = 0x3 << 11;
const M_TRAP_STACK_GUARD_WORDS: usize = 8;

fn machine_trap_stack_view() -> CommonMachineTrapStack {
    unsafe {
        CommonMachineTrapStack::new(
            core::ptr::addr_of_mut!(RISCV_PMP_M_TRAP_STACK).cast(),
            core::mem::size_of::<MachineTrapStack>(),
            M_TRAP_STACK_GUARD_WORDS,
        )
    }
}

/// # Safety
/// M-mode startup only; reserve valid aligned monitor stack and match the assembly mscratch convention.
pub unsafe fn install_machine_trap_stack() {
    let stack = unsafe { m_trap_stack_top() };
    unsafe {
        core::arch::asm!(
            "csrw mscratch, {stack}",
            stack = in(reg) stack,
            options(nomem, nostack),
        );
    }
}

unsafe fn m_trap_stack_top() -> usize {
    let stack = (&raw const RISCV_PMP_M_TRAP_STACK) as usize;
    stack + core::mem::size_of::<MachineTrapStack>()
}

/// # Safety
/// Initialize before the stack is active, with exclusive ownership of its reserved guard region.
pub unsafe fn init_machine_trap_stack_guard() {
    unsafe { machine_trap_stack_view().initialize_guard() };
}

pub fn machine_trap_stack_guard_ok() -> bool {
    machine_trap_stack_view().guard_ok()
}

/// # Safety
/// Install a valid aligned monitor vector before enabling traps or entering user mode.
pub unsafe fn install_trap_vector() {
    unsafe extern "C" {
        fn _pmp_trap_entry();
    }
    let trap = _pmp_trap_entry as *const () as usize;

    unsafe {
        core::arch::asm!(
            "csrw mtvec, {trap}",
            "fence.i",
            trap = in(reg) trap,
            options(nomem, nostack),
        );
    }
}

pub unsafe fn u_stack_top() -> usize {
    let stack = (&raw const RISCV_PMP_U_STACK) as usize;
    stack + core::mem::size_of::<UserStack>()
}

/// # Safety
/// Require checked executable user entry, final protection policy and initialized monitor trap state.
pub unsafe fn prepare_u_mode_entry(entry: usize) -> usize {
    let mstatus: usize;
    unsafe {
        core::arch::asm!(
            "csrw mepc, {entry}",
            "li t0, {mpp_mask}",
            "csrc mstatus, t0",
            "csrr {mstatus}, mstatus",
            "and {mstatus}, {mstatus}, t0",
            entry = in(reg) entry,
            mstatus = lateout(reg) mstatus,
            mpp_mask = const MSTATUS_MPP_MASK,
            options(nostack),
        );
    }
    mstatus
}

/// # Safety
/// Require prepared user context and an aligned exclusively owned user stack under the final policy.
pub unsafe fn enter_u_mode_prepared(stack: usize) -> ! {
    unsafe {
        core::arch::asm!(
            "mv sp, {stack}",
            "fence.i",
            "mret",
            stack = in(reg) stack,
            options(noreturn),
        );
    }
}
