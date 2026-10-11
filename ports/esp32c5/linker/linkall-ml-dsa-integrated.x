MEMORY {
  ml_dsa_app_ram (RW) : ORIGIN = ORIGIN(RAM), LENGTH = LENGTH(RAM) + LENGTH(dram2_seg) - 0x8000
  ml_dsa_heap_ram (RW) : ORIGIN = ORIGIN(ml_dsa_app_ram) + LENGTH(ml_dsa_app_ram), LENGTH = 0x8000
}

REGION_ALIAS("ROTEXT", ROM);
REGION_ALIAS("RODATA", ROM);
REGION_ALIAS("RWTEXT", ml_dsa_app_ram);
REGION_ALIAS("RWDATA", ml_dsa_app_ram);
REGION_ALIAS("RTC_FAST_RWTEXT", RTC_FAST);
REGION_ALIAS("RTC_FAST_RWDATA", RTC_FAST);

INCLUDE "esp32c5.x"
INCLUDE "hal-defaults.x"

SECTIONS {
  .flash_text_align (NOLOAD) : {
    . = ALIGN(0x10000);
  } > ROM
} INSERT BEFORE .text;

SECTIONS {
  .ml_dsa_heap (NOLOAD) : ALIGN(4) {
    KEEP(*(.ml_dsa_heap))
  } > ml_dsa_heap_ram
}

ASSERT(SIZEOF(.dram2_uninit) == 0, "integrated stack overlaps reclaimed RAM data");
ASSERT(SIZEOF(.ml_dsa_heap) == 0x8000, "integrated heap must be exactly 32 KiB");
