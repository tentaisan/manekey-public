SECTIONS
{
  .mpu_shared (NOLOAD) : ALIGN(4096) { KEEP(*(.mpu_shared)); } > SHARED
  .mpu_psp (NOLOAD) : ALIGN(8) { KEEP(*(.mpu_psp)); } > PSP
}
INSERT AFTER .uninit;
/* INSERT moves the location counter; retain the private-RAM heap/stack boundary. */
ASSERT(SIZEOF(.uninit) == 0, "MPU profile requires explicit ownership for uninit memory");
ASSERT(SIZEOF(.mpu_shared) == 4096, "MPU shared workspace must fill 4 KiB");
ASSERT(SIZEOF(.mpu_psp) == LENGTH(PSP), "MPU PSP must preserve the board's loader RAM reservation");
