#[repr(align(32))]
#[allow(dead_code)]
/// User stack reserved by the active linker; initialize before user entry.
pub(super) struct UserStack(pub [u8; USER_STACK_SIZE]);

#[cfg(feature = "riscv-pmp-usb-internal-ccid")]
const USER_STACK_SIZE: usize = 64 * 1024;
#[cfg(not(feature = "riscv-pmp-usb-internal-ccid"))]
const USER_STACK_SIZE: usize = 8192;

#[cfg(all(
    feature = "riscv-pmp-large-machine-stack",
    feature = "riscv-flash-managed-keys",
    feature = "experimental-ml-dsa-mldsa-native"
))]
const MACHINE_TRAP_STACK_SIZE: usize = 128 * 1024;
#[cfg(all(
    feature = "riscv-pmp-large-machine-stack",
    not(all(
        feature = "riscv-flash-managed-keys",
        feature = "experimental-ml-dsa-mldsa-native"
    ))
))]
const MACHINE_TRAP_STACK_SIZE: usize = 180 * 1024;
#[cfg(not(feature = "riscv-pmp-large-machine-stack"))]
const MACHINE_TRAP_STACK_SIZE: usize = 16 * 1024;

#[allow(dead_code)]
/// Dedicated monitor stack; trap assembly and mscratch must match this storage.
pub(super) struct MachineTrapStack(pub [u8; MACHINE_TRAP_STACK_SIZE]);

#[unsafe(no_mangle)]
#[unsafe(link_section = ".bss.pmp_user_stack")]
pub(super) static mut RISCV_PMP_U_STACK: UserStack = UserStack([0; USER_STACK_SIZE]);

#[unsafe(no_mangle)]
#[unsafe(link_section = ".bss.pmp_machine_trap_stack")]
pub(super) static mut RISCV_PMP_M_TRAP_STACK: MachineTrapStack =
    MachineTrapStack([0; MACHINE_TRAP_STACK_SIZE]);

unsafe extern "C" {
    pub(super) static __pmp_machine_text_start: u8;
    pub(super) static __pmp_machine_text_end: u8;
    pub(super) static __pmp_user_text_start: u8;
    pub(super) static __pmp_user_text_end: u8;
    pub(super) static __pmp_machine_data_start: u8;
    pub(super) static __pmp_machine_data_end: u8;
    pub(super) static __pmp_shared_start: u8;
    pub(super) static __pmp_shared_end: u8;
    pub(super) static __pmp_user_stack_start: u8;
    pub(super) static __pmp_user_stack_end: u8;
    pub(super) static __pmp_user_async_start: u8;
    pub(super) static __pmp_user_async_end: u8;
    pub(super) static __pmp_machine_trap_stack_start: u8;
    pub(super) static __pmp_machine_trap_stack_end: u8;
}
