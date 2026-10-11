INCLUDE "memory.x"

MEMORY {
  ml_dsa_app_dram (RW) : ORIGIN = ORIGIN(dram_seg), LENGTH = LENGTH(dram_seg) + LENGTH(dram2_seg) - 0x2000
  ml_dsa_heap_dram (RW) : ORIGIN = ORIGIN(ml_dsa_app_dram) + LENGTH(ml_dsa_app_dram), LENGTH = 0x2000
}

REGION_ALIAS("ROTEXT", irom_seg);
REGION_ALIAS("RWTEXT", iram_seg);
REGION_ALIAS("RODATA", drom_seg);
REGION_ALIAS("RWDATA", ml_dsa_app_dram);
REGION_ALIAS("RTC_FAST_RWTEXT", rtc_fast_iram_seg);
REGION_ALIAS("RTC_FAST_RWDATA", rtc_fast_dram_seg);

INCLUDE "esp32s2.x"
INCLUDE "hal-defaults.x"

SECTIONS {
  .ml_dsa_heap (NOLOAD) : ALIGN(4) {
    KEEP(*(.ml_dsa_heap))
  } > ml_dsa_heap_dram
}

ASSERT(SIZEOF(.dram2_uninit) == 0, "integrated stack overlaps reclaimed DRAM2 data");
ASSERT(SIZEOF(.ml_dsa_heap) == 0x2000, "integrated heap must be exactly 8 KiB");
ASSERT(_stack_start - _stack_end >= 0x20000, "integrated ML-DSA requires at least 128 KiB stack headroom");
