#include "hw_sce_ra_private.h"

uint32_t S_RAM[32];

uint32_t change_endian_long(uint32_t data) {
    return __builtin_bswap32(data);
}

uint32_t manekey_sce5_init(void) {
    /* Module ownership/power is acquired in Rust before this call. */
    HW_SCE_SoftwareResetSub();
    fsp_err_t status = HW_SCE_SelfCheck1Sub();
    if (status != FSP_SUCCESS) return status;
    SCE->REG_1D4H = 0x0000ffff;
    status = HW_SCE_SelfCheck2Sub();
    return status;
}

uint32_t manekey_sce5_read(uint32_t output[4]) {
    fsp_err_t status = HW_SCE_GenerateRandomNumberSub(output);
    return status;
}

static void wipe_words(uint32_t *data, uint32_t count) {
    volatile uint32_t *p = data;
    while (count--) *p++ = 0;
}

/* Caller owns private aligned buffers. The index is an opaque SCE asset;
 * persistence is evaluated separately, never inferred from its size. */
uint32_t manekey_sce5_wrap256(uint32_t key[8], uint32_t index[16]) {
    uint32_t key_type = 1;
    uint32_t shared_index = 0;
    uint32_t zero[8] = {0};
    fsp_err_t status = HW_SCE_GenerateAes256PlainKeyIndexSub(
        &key_type, &shared_index, zero, zero, key, index);
    wipe_words(S_RAM, 32);
    if (status != FSP_SUCCESS) wipe_words(index, 16);
    return status;
}

uint32_t manekey_sce5_wrapped256(uint32_t index[16], uint32_t input[4], uint32_t output[4], uint32_t decrypt) {
    uint32_t key_type = 0;
    uint32_t cmd = change_endian_long(decrypt ? 1 : 0);
    uint32_t zero[4] = {0};
    fsp_err_t status = HW_SCE_Aes256EncryptDecryptInitSub(&key_type, &cmd, index, zero);
    if (status == FSP_SUCCESS) {
        HW_SCE_Aes256EncryptDecryptUpdateSub(input, output, 4);
        status = HW_SCE_Aes256EncryptDecryptFinalSub();
    }
    wipe_words(S_RAM, 32);
    if (status != FSP_SUCCESS) wipe_words(output, 4);
    return status;
}

/* Plain ephemeral ClientPIN key -> hardware key index -> one ECB block.
 * Rust owns serialization and the independent IRQ watchdog. No persistent
 * provisioning, option settings, or wrapped key caching is performed. */
uint32_t manekey_sce5_aes256(uint32_t key[8], uint32_t input[4], uint32_t output[4], uint32_t decrypt) {
    uint32_t key_type = 1; /* SCE_OEM_KEY_TYPE_PLAIN */
    uint32_t shared_index = 0;
    uint32_t zero[8] = {0};
    uint32_t index[16] = {0};
    uint32_t cmd = change_endian_long(decrypt ? 1 : 0);
    fsp_err_t status = HW_SCE_GenerateAes256PlainKeyIndexSub(
        &key_type, &shared_index, zero, zero, key, index);
    if (status == FSP_SUCCESS) {
        key_type = 0;
        status = HW_SCE_Aes256EncryptDecryptInitSub(&key_type, &cmd, index, zero);
        if (status == FSP_SUCCESS) {
            HW_SCE_Aes256EncryptDecryptUpdateSub(input, output, 4);
            status = HW_SCE_Aes256EncryptDecryptFinalSub();
        }
    }
    wipe_words(index, 16);
    wipe_words(S_RAM, 32);
    if (status != FSP_SUCCESS) wipe_words(output, 4);
    return status;
}
