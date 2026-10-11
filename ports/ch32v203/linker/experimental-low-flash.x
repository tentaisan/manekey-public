SECTIONS
{
    .low_flash : ALIGN(4)
    {
        __low_flash_start = .;
        *(.text.low_flash .text.low_flash.*)
        *(.text.OUTLINED_FUNCTION_* .text..OUTLINED_FUNCTION_*)
        *(.srodata .srodata.* .rodata .rodata.*)
        . = ALIGN(4);
        __low_flash_end = .;
    } >FLASH AT>FLASH
}
INSERT BEFORE .text;
ASSERT(__low_flash_end <= 0x10000, "low Flash constants/helpers exceed 64 KiB");
ASSERT(LOADADDR(.data) + SIZEOF(.data) <= 0x35e00, "image overlaps reserved storage");
