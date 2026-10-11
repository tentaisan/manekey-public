/*
 * Status definitions adapted from Renesas FSP fsp_common_api.h:
 * Copyright (c) 2020 - 2026 Renesas Electronics Corporation and/or its affiliates
 * SPDX-License-Identifier: BSD-3-Clause
 * Source: renesas/fsp, revision 6e2675336b37fbd805f0c01d5134adfdab4bf294,
 * ra/fsp/inc/api/fsp_common_api.h. Only the required status subset is retained.
 * BSD conditions and disclaimer: ../../vendor/renesas-sce5/LICENSE.md,
 * section "BSD 3-Clause License". This attribution applies to the adapted definitions;
 * original ManeKey compatibility scaffolding retains the port license.
 */
#ifndef MANEKEY_SCE5_BSP_API_H
#define MANEKEY_SCE5_BSP_API_H
#include <stdint.h>
#define __IOM volatile
/* Status subset for RNG, self-test and AES key setup. */
typedef enum {
    FSP_SUCCESS = 0,
    FSP_ERR_CRYPTO_SCE_RESOURCE_CONFLICT = 0x10001,
    FSP_ERR_CRYPTO_SCE_FAIL = 0x10002,
    FSP_ERR_CRYPTO_SCE_RETRY = 0x10004,
    FSP_ERR_CRYPTO_SCE_KEY_SET_FAIL = 0x10012
} fsp_err_t;
#endif
