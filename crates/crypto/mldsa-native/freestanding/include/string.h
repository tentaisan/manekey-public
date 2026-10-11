#ifndef MANEKEY_MLDSA_FREESTANDING_STRING_H
#define MANEKEY_MLDSA_FREESTANDING_STRING_H

/*
 * Minimal C99 declarations for bare-metal builds without a libc sysroot.
 * Implementations resolve to Rust compiler_builtins at the final link.
 */
typedef __SIZE_TYPE__ size_t;

void *memcpy(void *restrict destination, const void *restrict source, size_t count);
void *memset(void *destination, int value, size_t count);

#endif
