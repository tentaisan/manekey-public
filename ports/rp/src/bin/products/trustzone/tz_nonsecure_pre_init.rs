core::arch::global_asm!(
    r#"
    .syntax unified
    .thumb
    .section .text.__wrap___pre_init,"ax",%progbits
    .global __wrap___pre_init
    .type __wrap___pre_init,%function
    .thumb_func
__wrap___pre_init:
    bx lr
    .size __wrap___pre_init, . - __wrap___pre_init
"#
);
