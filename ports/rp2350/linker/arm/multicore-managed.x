MEMORY {
    FLASH : ORIGIN = 0x10000000, LENGTH = 0x3F9000
    RAM   : ORIGIN = 0x20000000, LENGTH = 512K
    SRAM8 : ORIGIN = 0x20080000, LENGTH = 4K
    SRAM9 : ORIGIN = 0x20081000, LENGTH = 4K
}

SECTIONS {
    .start_block : ALIGN(4)
    {
        KEEP(*(.start_block));
        KEEP(*(.boot_info));
    } > FLASH
} INSERT AFTER .vector_table;

_stext = ADDR(.start_block) + SIZEOF(.start_block);

ASSERT(ORIGIN(FLASH) + LENGTH(FLASH) <= 0x103F9000, "managed key media overlaps image");
