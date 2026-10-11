MEMORY {
    BOOT2 : ORIGIN = 0x10000000, LENGTH = 0x100
    FLASH : ORIGIN = 0x10000100, LENGTH = 0x1f9000 - 0x100
    RAM   : ORIGIN = 0x20000000, LENGTH = 160K
    MPU_USER : ORIGIN = 0x20028000, LENGTH = 96K
}

EXTERN(BOOT2_FIRMWARE)

SECTIONS {
    .boot2 ORIGIN(BOOT2) : { KEEP(*(.boot2)); } > BOOT2
} INSERT BEFORE .text;

SECTIONS {
    .mpu_user (NOLOAD) : {
        KEEP(*(.mpu_stack));
        KEEP(*(.mpu_shared));
    } > MPU_USER
} INSERT AFTER .uninit;

ASSERT(ADDR(.mpu_user) == ORIGIN(MPU_USER), "MPU U window start mismatch");
ASSERT(SIZEOF(.mpu_user) <= LENGTH(MPU_USER), "MPU U window overflow");
