MEMORY {
  FLASH : ORIGIN = 0x0c000000, LENGTH = 992K
  NSC   : ORIGIN = 0x0c0ff000, LENGTH = 4K
  RAM   : ORIGIN = 0x30000000, LENGTH = 256K
}
__managed_keys_start = 0x0c0f8000;
__managed_keys_end = 0x0c0fc000;
SECTIONS {
  .nsc : ALIGN(32) { KEEP(*(.nsc)); } > NSC
} INSERT BEFORE .vector_table;
