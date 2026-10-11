ENTRY(__pmp_user_entry);

MEMORY {
    FLASH : ORIGIN = 0x10100000, LENGTH = 1M
    RAM   : ORIGIN = 0x20040000, LENGTH = 256K
}

PROVIDE(_stack_start = ORIGIN(RAM) + LENGTH(RAM));
PROVIDE(__global_pointer$ = ORIGIN(RAM) + 0x800);

SECTIONS {
  .text ORIGIN(FLASH) : ALIGN(4) {
    __pmp_user_image_start = .;
    KEEP(*(.init.pmp_user));
    *(.text .text.*);
    . = ALIGN(4);
  } > FLASH

  .rodata : ALIGN(4) {
    *(.srodata .srodata.*);
    *(.rodata .rodata.*);
    . = ALIGN(4);
  } > FLASH

  .shared_abi ORIGIN(RAM) (NOLOAD) : ALIGN(4096) {
    __pmp_shared_abi_start = .;
    . += 4096;
    __pmp_shared_abi_end = .;
  } > RAM

  .data : ALIGN(32) {
    _sidata = LOADADDR(.data);
    _sdata = .;
    *(.sdata .sdata.* .sdata2 .sdata2.*);
    *(.data .data.*);
    . = ALIGN(32);
    _edata = .;
  } > RAM AT > FLASH

  .bss (NOLOAD) : ALIGN(32) {
    _sbss = .;
    *(.sbss .sbss.* .bss .bss.*);
    . = ALIGN(32);
    _ebss = .;
  } > RAM

  .stack (NOLOAD) : {
    . = ALIGN(16);
    _stack_limit = .;
    . = ABSOLUTE(_stack_start);
  } > RAM

  .got (INFO) : { KEEP(*(.got .got.*)); }

  __pmp_user_image_end = LOADADDR(.data) + SIZEOF(.data);
  /DISCARD/ : { *(.eh_frame .eh_frame_hdr) }
}

ASSERT(ORIGIN(FLASH) == 0x10100000, "PMP user FLASH origin changed");
ASSERT(ORIGIN(FLASH) + LENGTH(FLASH) == 0x10200000, "PMP user FLASH partition changed");
ASSERT(ORIGIN(RAM) == 0x20040000, "PMP user RAM origin changed");
ASSERT(ORIGIN(RAM) + LENGTH(RAM) == 0x20080000, "PMP user RAM partition changed");
ASSERT(__pmp_shared_abi_start == 0x20040000, "PMP shared ABI origin changed");
ASSERT(__pmp_shared_abi_end == 0x20041000, "PMP shared ABI size changed");
ASSERT(_sdata >= __pmp_shared_abi_end, "PMP user data overlaps shared ABI");
ASSERT(_sdata % 32 == 0 && _edata % 32 == 0, "PMP user .data must be 32-byte aligned");
ASSERT(_sbss % 32 == 0 && _ebss % 32 == 0, "PMP user .bss must be 32-byte aligned");
ASSERT(SIZEOF(.got) == 0, ".got section detected");
