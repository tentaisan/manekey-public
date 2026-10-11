#[cfg(any(feature = "riscv-pmp-ble-mmio-runtime", any()))]
use core::arch::global_asm;

#[cfg(feature = "riscv-pmp-ble-mmio-runtime")]
global_asm!(
    r#"
    .section .text.pmp_user_ble_mmio, "ax"
    .option push
    .option norvc
    # Keep the continuation after mret as a 32-bit instruction for the timer ABI.
    .global _pmp_u_timer_ecall
    .align 2
_pmp_u_timer_ecall:
    ecall
    ret

    .option pop

    "#
);
