MEMORY {
  c5_app_ram (RW) : ORIGIN = ORIGIN(RAM),
    LENGTH = LENGTH(RAM) + (DEFINED(__c5_managed_pmp_ram) ? LENGTH(dram2_seg) : 0)
}

REGION_ALIAS("ROTEXT", ROM);
REGION_ALIAS("RODATA", ROM);

REGION_ALIAS("RWTEXT", c5_app_ram);
REGION_ALIAS("RWDATA", c5_app_ram);

REGION_ALIAS("RTC_FAST_RWTEXT", RTC_FAST);
REGION_ALIAS("RTC_FAST_RWDATA", RTC_FAST);

INCLUDE "esp32c5.x"
INCLUDE "hal-defaults.x"

ASSERT(!DEFINED(__c5_managed_pmp_ram) || SIZEOF(.dram2_uninit) == 0,
       "managed PMP RAM overlaps dram2 allocation");

SECTIONS {
  .flash_text_align (NOLOAD) : {
    . = ALIGN(0x10000);
  } > ROM
} INSERT BEFORE .text;

SECTIONS {
  .c5_pmp_user_text : ALIGN(4) {
    __c5_pmp_user_text_start = .;
    KEEP(*(.c5_pmp_user_text .c5_pmp_user_text.*));
    . = ALIGN(4);
    __c5_pmp_user_text_end = .;
  } > ROTEXT
} INSERT AFTER .text;

SECTIONS {
  .c5_pmp_shared : ALIGN(128) {
    __c5_pmp_shared_start = .;
    KEEP(*(.c5_pmp_shared .c5_pmp_shared.*));
    . = ALIGN(128);
    __c5_pmp_shared_end = .;
  } > RWDATA
} INSERT AFTER .data;

SECTIONS {
  .c5_pmp_machine_private (NOLOAD) : ALIGN(128) {
    __c5_pmp_machine_private_start = .;
    KEEP(*(.c5_pmp_machine_private .c5_pmp_machine_private.*));
    __c5_pmp_machine_trap_stack_start = .;
    KEEP(*(.c5_pmp_machine_trap_stack .c5_pmp_machine_trap_stack.*));
    __c5_pmp_machine_trap_stack_end = .;
    . = ALIGN(128);
    __c5_pmp_machine_private_end = .;
  } > RWDATA
} INSERT AFTER .bss;
