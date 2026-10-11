MEMORY {
  ml_dsa_app_ram (RW) : ORIGIN = ORIGIN(RAM), LENGTH = LENGTH(RAM) + LENGTH(dram2_seg) - 0x8000
  ml_dsa_heap_ram (RW) : ORIGIN = ORIGIN(ml_dsa_app_ram) + LENGTH(ml_dsa_app_ram), LENGTH = 0x8000
}

REGION_ALIAS("ROTEXT", ROM);
REGION_ALIAS("RODATA", ROM);
REGION_ALIAS("RWTEXT", ml_dsa_app_ram);
REGION_ALIAS("RWDATA", ml_dsa_app_ram);
REGION_ALIAS("RTC_FAST_RWTEXT", RTC_FAST);
REGION_ALIAS("RTC_FAST_RWDATA", RTC_FAST);

INCLUDE "esp32c6.x"
INCLUDE "hal-defaults.x"

SECTIONS {
  .c6_pmp_user_text : ALIGN(4) {
    __c6_pmp_user_text_start = .;
    KEEP(*(.c6_pmp_user_text .c6_pmp_user_text*));
    . = ALIGN(4);
    __c6_pmp_user_text_end = .;
  } > ROTEXT
} INSERT AFTER .text;

SECTIONS {
  .c6_pmp_shared : ALIGN(8) {
    __c6_pmp_shared_start = .;
    KEEP(*(.c6_pmp_shared .c6_pmp_shared.*));
    . = ALIGN(8);
    __c6_pmp_shared_end = .;
  } > RWDATA
} INSERT AFTER .data;

SECTIONS {
  .c6_pmp_machine_private (NOLOAD) : ALIGN(8) {
    __c6_pmp_machine_private_start = .;
    KEEP(*(.c6_pmp_machine_private .c6_pmp_machine_private.*));
    __c6_pmp_machine_trap_stack_start = .;
    KEEP(*(.c6_pmp_machine_trap_stack .c6_pmp_machine_trap_stack.*));
    __c6_pmp_machine_trap_stack_end = .;
    . = ALIGN(8);
    __c6_pmp_machine_private_end = .;
  } > RWDATA
} INSERT AFTER .bss;

SECTIONS {
  .c6_pmp_user_stack (NOLOAD) : ALIGN(32) {
    __c6_pmp_user_stack_start = .;
    KEEP(*(.c6_pmp_user_stack .c6_pmp_user_stack.*));
    . = ALIGN(32);
    __c6_pmp_user_stack_end = .;
  } > RWDATA
} INSERT AFTER .c6_pmp_shared;

SECTIONS {
  .ml_dsa_heap (NOLOAD) : ALIGN(4) {
    KEEP(*(.ml_dsa_heap))
  } > ml_dsa_heap_ram
}

ASSERT(SIZEOF(.dram2_uninit) == 0, "integrated stack overlaps reclaimed RAM data");
ASSERT(SIZEOF(.ml_dsa_heap) == 0x8000, "integrated heap must be exactly 32 KiB");
