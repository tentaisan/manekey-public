use super::pmp_csr::can_emulate_privileged_csr;

use super::pmp_machine::machine_trap_stack_guard_ok;

use super::pmp_trap::TrapAction;

use super::pmp_trap_frame::TrapFrame;

#[unsafe(no_mangle)]
/// Assembly-only monitor entry; require the matching valid saved frame and instruction address context.
extern "C" fn pmp_trap_report(
    mcause: usize,
    mepc: usize,
    _mtval: usize,
    frame: *mut TrapFrame,
) -> usize {
    if !machine_trap_stack_guard_ok() {
        return 0;
    }

    let can_emulate = mcause == 2
        && cfg!(feature = "riscv-pmp-usb-frontend")
        && unsafe { can_emulate_privileged_csr(mepc) };
    let policy = super::pmp_trap::trap_policy(mcause, frame, can_emulate);

    let trap_stack_guard_ok = machine_trap_stack_guard_ok();
    let action = if trap_stack_guard_ok {
        super::pmp_trap::trap_action(policy, mepc, frame)
    } else {
        TrapAction::Halt
    };

    action.next_mepc().unwrap_or(0)
}

fn is_pmp32_aligned(start: usize, size: usize) -> bool {
    start % 32 == 0 && size != 0 && size % 32 == 0
}

pub(super) fn is_napot_region(start: usize, size: usize) -> bool {
    is_pmp32_aligned(start, size) && size.is_power_of_two() && start % size == 0
}
