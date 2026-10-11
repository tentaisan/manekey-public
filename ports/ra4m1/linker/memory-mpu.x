/* CPU privilege split, preserving loader Flash and its top 16 RAM bytes. */
MEMORY
{
  FLASH : ORIGIN = 0x00004000, LENGTH = 240K
  RAM : ORIGIN = 0x20000000, LENGTH = 24K
  SHARED : ORIGIN = 0x20006000, LENGTH = 4K
  PSP : ORIGIN = 0x20007000, LENGTH = 0xFF0
}
/* Define before link.x evaluates assertions/PROVIDE after inserted U sections. */
_stack_end = ADDR(.bss) + SIZEOF(.bss);
