/*
 * Compatibility declarations for selected Renesas FSP SCE5 primitives.
 * Source: renesas/fsp, revision 6e2675336b37fbd805f0c01d5134adfdab4bf294,
 * ra/fsp/src/r_sce/crypto_procedures/src/sce5/plainkey/primitive/.
 * Copyright (c) 2020 - 2026 Renesas Electronics Corporation and/or its affiliates.
 * Referenced primitive interfaces retain BSD-3-Clause; conditions/disclaimer:
 * ../../vendor/renesas-sce5/LICENSE.md, section "BSD 3-Clause License".
 * Original ManeKey compatibility scaffolding retains the port license.
 * This header declares the selected ABI only; it does not copy primitive bodies.
 */
#ifndef MANEKEY_SCE5_PRIVATE_H
#define MANEKEY_SCE5_PRIVATE_H
#include "r_sce_if.h"
#include "SCE_ProcCommon.h"
/* Selected SCE5 RNG, self-test and AES dependencies. */
extern uint32_t S_RAM[32];
extern uint32_t const S_FLASH[];
void HW_SCE_func206(void);
fsp_err_t HW_SCE_GenerateAes256PlainKeyIndexSub(uint32_t *, uint32_t *, uint32_t *, uint32_t *, uint32_t *, uint32_t *);
fsp_err_t HW_SCE_Aes256EncryptDecryptInitSub(const uint32_t *, const uint32_t *, const uint32_t *, const uint32_t *);
void HW_SCE_Aes256EncryptDecryptUpdateSub(const uint32_t *, uint32_t *, uint32_t);
fsp_err_t HW_SCE_Aes256EncryptDecryptFinalSub(void);
void HW_SCE_SoftwareResetSub(void);
fsp_err_t HW_SCE_SelfCheck1Sub(void);
fsp_err_t HW_SCE_SelfCheck2Sub(void);
void HW_SCE_SelfCheck1SubSub(void);
void HW_SCE_SelfCheck2SubSub(void);
fsp_err_t HW_SCE_GenerateRandomNumberSub(uint32_t *output);
uint32_t change_endian_long(uint32_t data);
void HW_SCE_func001(uint32_t, uint32_t, uint32_t, uint32_t);
void HW_SCE_func002(uint32_t, uint32_t, uint32_t, uint32_t);
void HW_SCE_func003(uint32_t, uint32_t, uint32_t, uint32_t);
#endif
