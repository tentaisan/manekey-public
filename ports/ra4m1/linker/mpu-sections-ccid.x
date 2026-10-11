SECTIONS
{
  .mpu_shared (NOLOAD) : ALIGN(4096) { KEEP(*(.mpu_shared)); } > SHARED
  .mpu_psp (NOLOAD) : ALIGN(8) { KEEP(*(.mpu_psp)); } > PSP
}
INSERT AFTER .uninit;
ASSERT(SIZEOF(.uninit) == 0, "MPU profile requires explicit ownership for uninit memory");
ASSERT(SIZEOF(.mpu_shared) <= LENGTH(SHARED), "MPU CCID shared workspace exceeds 6 KiB");
ASSERT(SIZEOF(.mpu_psp) == LENGTH(PSP), "MPU PSP must preserve loader RAM");
