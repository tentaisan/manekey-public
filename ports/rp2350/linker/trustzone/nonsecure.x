MEMORY {
    FLASH : ORIGIN = 0x10100000, LENGTH = 0x2FB000
    RAM   : ORIGIN = 0x20040000, LENGTH = 0x41FF0
    MARKER : ORIGIN = 0x20081FF0, LENGTH = 0x10
}

SECTIONS {
    .tz_marker (NOLOAD) :
    {
        KEEP(*(.tz_marker));
    } > MARKER
}
