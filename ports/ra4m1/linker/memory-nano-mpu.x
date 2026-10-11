/* Same privilege layout as XIAO, retaining Arduino's top 256 RAM bytes. */
MEMORY
{
  FLASH : ORIGIN = 0x00004000, LENGTH = 240K
  RAM : ORIGIN = 0x20000000, LENGTH = 24K
  SHARED : ORIGIN = 0x20006000, LENGTH = 4K
  PSP : ORIGIN = 0x20007000, LENGTH = 0xF00
}
_stack_end = ADDR(.bss) + SIZEOF(.bss);
