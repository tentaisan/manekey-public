

pub const PRIVILEGED_MSP_RETURN: u32 = 0xffff_fff9;
pub const UNPRIVILEGED_PSP_RETURN: u32 = 0xffff_fffd;

// Runs a fresh non-floating-point U context, not a resumable task scheduler.
// Safety: caller is privileged Thread/MSP with CONTROL=0, no active FP context,
// and serialized invocations. Entry must never return normally. The port owns MPU
// maps, an aligned writable PSP stack, and an SVC handler that clears CONTROL
// and selects PRIVILEGED_MSP_RETURN only for a validated outstanding invocation.
// The port must deny U access to FP registers; this primitive does not save FP state.
// Interrupts remain enabled; their handlers must preserve the normal Cortex ABI.
pub unsafe fn run(entry: unsafe extern "C" fn(u32, u32) -> !, top: u32, a: u32, b: u32) {
    let ipsr: u32;
    let control: u32;
    unsafe {
        core::arch::asm!("mrs {ipsr},ipsr", "mrs {control},control",
            ipsr = out(reg) ipsr, control = out(reg) control, options(nomem, nostack));
    }
    assert_eq!(ipsr, 0);
    assert_eq!(control, 0);
    assert_eq!(top & 7, 0);
    unsafe { enter(entry as usize as u32, top, a, b) }
}

#[unsafe(naked)]
unsafe extern "C" fn enter(_entry: u32, _top: u32, _a: u32, _b: u32) {
    core::arch::naked_asm!(
        "push.w {{r4-r11,lr}}",
        "sub sp,#4",
        // Private synthetic exception frame consumed by the validated U yield.
        "sub sp,#32",
        "movs r4,#0",
        "str r4,[sp,#0]",
        "str r4,[sp,#4]",
        "str r4,[sp,#8]",
        "str r4,[sp,#12]",
        "str r4,[sp,#16]",
        "str r4,[sp,#20]",
        "adr r4,2f",
        "str r4,[sp,#24]",
        "mov.w r4,#0x01000000",
        "str r4,[sp,#28]",
        "msr psp,r1",
        "mov r4,r0",
        "mov r0,r2",
        "mov r1,r3",
        // Kernel callee-saved registers must not be exposed to the U callback.
        "mov.w r5,#0",
        "mov.w r6,#0",
        "mov.w r7,#0",
        "mov.w r8,#0",
        "mov.w r9,#0",
        "mov.w r10,#0",
        "mov.w r11,#0",
        "mov.w r12,#0",
        "mov lr,r4",
        "movs r3,#0",
        "msr APSR_nzcvq,r12",
        "movs r2,#3",
        "msr control,r2",
        "isb",
        "bx r4",
        "2:",
        "add sp,#4",
        "pop.w {{r4-r11,pc}}"
    );
}
