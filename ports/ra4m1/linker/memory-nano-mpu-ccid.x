/* Preserve Arduino's top 256 RAM bytes; reuse the common 6 KiB frontend. */
MEMORY
{
  FLASH : ORIGIN = 0x00004000, LENGTH = 240K
  RAM : ORIGIN = 0x20000000, LENGTH = 24K
  SHARED : ORIGIN = 0x20006000, LENGTH = 6K
  PSP : ORIGIN = 0x20007800, LENGTH = 0x700
}
_stack_end = ADDR(.bss) + SIZEOF(.bss);
