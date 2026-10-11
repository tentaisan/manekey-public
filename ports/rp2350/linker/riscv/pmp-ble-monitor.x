__pmp_flash_origin = 0x10000000;
__pmp_flash_length = 1M;
__pmp_ram_origin = 0x20000000;
__pmp_ram_length = 128K;

INCLUDE runtime-pmp.x

ASSERT(ORIGIN(FLASH) == 0x10000000, "PMP monitor FLASH origin changed");
ASSERT(ORIGIN(FLASH) + LENGTH(FLASH) == 0x10100000, "PMP monitor FLASH partition changed");
ASSERT(ORIGIN(RAM) == 0x20000000, "PMP monitor RAM origin changed");
ASSERT(ORIGIN(RAM) + LENGTH(RAM) == 0x20020000, "PMP monitor RAM partition changed");
