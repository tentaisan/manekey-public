#include <stddef.h>
#include "microcode_binary.h"

const uint32_t *manekey_cracen_microcode(size_t *words) {
    *words = BA414EP_UCODE_SIZE;
    return ba414ep_ucode;
}
