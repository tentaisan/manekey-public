SECTIONS {
  .c5_pmp_user_data : ALIGN(65536) {
    __c5_pmp_public_constants_start = .;
    *(.rodata..Lswitch.table.*)
    *(.rodata.cst*)
    __c5_pmp_public_constants_end = .;
    . = ALIGN(4096);
    __c5_pmp_product_shared_start = .;
    KEEP(*(.c5_pmp_product_shared .c5_pmp_product_shared.*));
    __c5_pmp_product_shared_end = .;
    . = ALIGN(32768);
    __c5_pmp_user_stack_start = .;
    KEEP(*(.c5_pmp_user_stack .c5_pmp_user_stack.*));
    . = ALIGN(32768);
    __c5_pmp_user_stack_end = .;
  } > RWDATA
} INSERT BEFORE .trap;

INCLUDE "linker/linkall-no-memory.x"

_dram_data_start = ADDR(.data);
ASSERT(__c5_pmp_user_text_end <= 0x42080000, "C5 PMP app exceeds public flash window");
ASSERT(__c5_pmp_product_shared_end <= __c5_pmp_user_stack_start, "C5 PMP shared/stack overlap");
ASSERT(__c5_pmp_public_constants_end - __c5_pmp_public_constants_start <= 4096,
       "C5 PMP public constants exceed read-only reservation");
ASSERT(!DEFINED(__c5_managed_pmp_ram) || _stack_start - _stack_end >= 0x10000,
       "managed PMP startup stack below 64 KiB");
