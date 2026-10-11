MEMORY {
    BOOT2 : ORIGIN = 0x10000000, LENGTH = 0x100
    FLASH : ORIGIN = 0x10000100, LENGTH = 0x3F9000 - 0x100
    RAM   : ORIGIN = 0x20000000, LENGTH = 520K
}

SECTIONS {
    .start_block ORIGIN(BOOT2) :
    {
        KEEP(*(.start_block));
    } > BOOT2

    .boot2 :
    {
        KEEP(*(.boot2));
    } > BOOT2
} INSERT BEFORE .vector_table;

ASSERT(ORIGIN(FLASH) + LENGTH(FLASH) <= 0x103F9000, "managed key media overlaps image");
