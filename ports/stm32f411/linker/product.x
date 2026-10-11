MEMORY
{
  FLASH : ORIGIN = 0x08000000, LENGTH = 512K
  RAM : ORIGIN = 0x20000000, LENGTH = 128K
}
_stext = 0x08040000;
ASSERT(SIZEOF(.vector_table) <= 16K, "vector overlaps credential storage");
