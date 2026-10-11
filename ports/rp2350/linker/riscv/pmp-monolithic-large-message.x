__pmp_shared_alignment = 16K;

INCLUDE runtime-pmp.x

ASSERT(__pmp_shared_start % 16K == 0, "PMP large shared region is not 16 KiB aligned");
ASSERT(__pmp_shared_end - __pmp_shared_start <= 16K, "PMP large shared region exceeds 16 KiB");
