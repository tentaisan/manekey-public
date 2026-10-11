INCLUDE "memory.x"

MEMORY {
  ml_dsa_app_dram (RW) : ORIGIN = ORIGIN(DRAM), LENGTH = LENGTH(DRAM) + LENGTH(dram2_seg) - 0xc000
  ml_dsa_heap_ram (RW) : ORIGIN = ORIGIN(ml_dsa_app_dram) + LENGTH(ml_dsa_app_dram), LENGTH = 0xc000
}

REGION_ALIAS("ROTEXT", IROM);
REGION_ALIAS("RODATA", DROM);
REGION_ALIAS("RWDATA", ml_dsa_app_dram);
REGION_ALIAS("RWTEXT", IRAM);
REGION_ALIAS("RTC_FAST_RWTEXT", RTC_FAST);
REGION_ALIAS("RTC_FAST_RWDATA", RTC_FAST);

INCLUDE "esp32c3.x"
INCLUDE "hal-defaults.x"

SECTIONS {
  .ml_dsa_heap (NOLOAD) : ALIGN(4) {
    KEEP(*(.ml_dsa_heap))
  } > ml_dsa_heap_ram
}

ASSERT(SIZEOF(.dram2_uninit) == 0, "integrated stack overlaps reclaimed RAM data");
ASSERT(SIZEOF(.ml_dsa_heap) == 0xc000, "integrated heap must be exactly 48 KiB");
