MEMORY
{
  FLASH : ORIGIN = 0x00004000, LENGTH = 240K
  RAM : ORIGIN = 0x20000000, LENGTH = 24K
  SHARED : ORIGIN = 0x20006000, LENGTH = 6K
  PSP : ORIGIN = 0x20007800, LENGTH = 0x7F0
}
/* Define at memory include time, before cortex-m-rt's PROVIDE and assertions. */
_stack_end = ADDR(.bss) + SIZEOF(.bss);
