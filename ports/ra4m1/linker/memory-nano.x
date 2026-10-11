/* Preserve Arduino loader Flash and its top 256-byte RAM vector reservation. */
MEMORY
{
  FLASH : ORIGIN = 0x00004000, LENGTH = 240K
  RAM : ORIGIN = 0x20000000, LENGTH = 0x7F00
}
