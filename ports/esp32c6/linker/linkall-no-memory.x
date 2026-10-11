REGION_ALIAS("ROTEXT", ROM);
REGION_ALIAS("RODATA", ROM);

REGION_ALIAS("RWTEXT", RAM);
REGION_ALIAS("RWDATA", RAM);

REGION_ALIAS("RTC_FAST_RWTEXT", RTC_FAST);
REGION_ALIAS("RTC_FAST_RWDATA", RTC_FAST);

INCLUDE "esp32c6.x"
INCLUDE "hal-defaults.x"

SECTIONS
{
  .c6_pmp_user_text : ALIGN(4)
  {
    __c6_pmp_user_text_start = .;
    KEEP(*(.c6_pmp_user_text .c6_pmp_user_text*));
    . = ALIGN(4);
    __c6_pmp_user_text_end = .;
  } > ROTEXT
} INSERT AFTER .text;

ASSERT(__c6_pmp_user_text_end <= 0x423e0000,
       "C6 U text overlaps the reserved private Flash tail");

SECTIONS
{
  .c6_pmp_shared : ALIGN(8)
  {
    __c6_pmp_shared_start = .;
    KEEP(*(.c6_pmp_shared .c6_pmp_shared.*));
    . = ALIGN(8);
    __c6_pmp_shared_end = .;
  } > RWDATA
} INSERT AFTER .data;

SECTIONS
{
  .c6_pmp_machine_private (NOLOAD) : ALIGN(8)
  {
    __c6_pmp_machine_private_start = .;
    KEEP(*(.c6_pmp_machine_private .c6_pmp_machine_private.*));
    __c6_pmp_machine_trap_stack_start = .;
    KEEP(*(.c6_pmp_machine_trap_stack .c6_pmp_machine_trap_stack.*));
    __c6_pmp_machine_trap_stack_end = .;
    . = ALIGN(8);
    __c6_pmp_machine_private_end = .;
  } > RWDATA
} INSERT AFTER .bss;

SECTIONS
{
  .c6_pmp_user_stack (NOLOAD) : ALIGN(32)
  {
    __c6_pmp_user_stack_start = .;
    KEEP(*(.c6_pmp_user_stack .c6_pmp_user_stack.*));
    . = ALIGN(32);
    __c6_pmp_user_stack_end = .;
  } > RWDATA
} INSERT AFTER .c6_pmp_shared;
