SECTIONS {
  .kmu_product (NOLOAD) : ALIGN(16) {
    KEEP(*(.kmu_product));
  } > KMU_RAM
} INSERT AFTER .uninit;
ASSERT(ADDR(.kmu_product) == 0x20000000, "KMU persistent destination changed");
ASSERT(SIZEOF(.kmu_product) == 16, "KMU push area size changed");
