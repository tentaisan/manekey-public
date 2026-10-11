MEMORY
{
  FLASH : ORIGIN = 0x08000000, LENGTH = 512K
  RAM : ORIGIN = 0x20000000, LENGTH = 80K
  SHARED : ORIGIN = 0x20014000, LENGTH = 32K
  PSP : ORIGIN = 0x2001c000, LENGTH = 16K
}
_stext = 0x08040000;
SECTIONS
{
  .mpu_shared (NOLOAD) : { KEEP(*(.mpu_shared)); } > SHARED
  .mpu_psp (NOLOAD) : { KEEP(*(.mpu_psp)); } > PSP
}
INSERT AFTER .bss;
ASSERT(SIZEOF(.vector_table) <= 16K, "vector overlaps credential storage");
