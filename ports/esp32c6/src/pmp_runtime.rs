use core::arch::asm;

use esp_hal::riscv::register::mstatus;
use manekey::boundary::pmp_stack::MachineTrapStack;

pub const MACHINE_TRAP_STACK_GUARD_WORDS: usize = 8;

/// Install the private M-mode trap stack before enabling U-mode traps.
///
/// # Safety
/// Supply a writable, word-aligned, word-sized allocation larger than the guard, with nonoverflowing bounds.
/// Keep it M-mode-only for U-mode execution; trap entry must swap sp/mscratch before Rust and no other owner may reuse mscratch.
pub unsafe fn install_machine_trap_stack(stack: *mut u32, bytes: usize) {
    let view = unsafe { MachineTrapStack::new(stack, bytes, MACHINE_TRAP_STACK_GUARD_WORDS) };
    unsafe { view.initialize_guard() };

    let top = stack as usize + bytes;
    unsafe {
        asm!(
            "csrw mscratch, {top}",
            top = in(reg) top,
            options(nomem, nostack),
        );
    }
}

/// Return the installed trap-stack view.
///
/// # Safety
/// Preserve the allocation, alignment, bounds and exclusive-access requirements of install_machine_trap_stack.
pub const unsafe fn machine_trap_stack(stack: *mut u32, bytes: usize) -> MachineTrapStack {
    unsafe { MachineTrapStack::new(stack, bytes, MACHINE_TRAP_STACK_GUARD_WORDS) }
}

/// Install a direct M-mode trap vector.
///
/// # Safety
/// Supply an aligned executable entry handling every enabled trap and preserve exclusive vector ownership.
pub unsafe fn install_direct_trap_vector(trap: usize) {
    unsafe {
        asm!(
            "csrw mtvec, {trap}",
            "fence.i",
            trap = in(reg) trap,
            options(nomem, nostack),
        );
    }
}

/// Enter the prepared U-mode entry.
///
/// # Safety
/// Install a working trap vector, private trap stack and PMP policy first.
/// Entry and aligned stack must be permitted by that policy; preserve the port interrupt contract.
pub unsafe fn enter_user_mode(entry: usize, stack_top: usize) -> ! {
    unsafe {
        asm!("csrw mepc, {entry}", entry = in(reg) entry, options(nostack));
        mstatus::set_mpp(mstatus::MPP::User);
        asm!(
            "mv sp, {stack_top}",
            "fence.i",
            "mret",
            stack_top = in(reg) stack_top,
            options(noreturn),
        );
    }
}
