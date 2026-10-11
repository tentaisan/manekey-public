MEMORY {
    BOOT2 : ORIGIN = 0x10000000, LENGTH = 0x100
    FLASH : ORIGIN = 0x10000100, LENGTH = 0xFEF00
    NSC   : ORIGIN = 0x100FF000, LENGTH = 4K
    RAM   : ORIGIN = 0x20000000, LENGTH = 256K
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

    .nsc : ALIGN(32)
    {
        KEEP(*(.nsc));
    } > NSC
} INSERT BEFORE .vector_table;
