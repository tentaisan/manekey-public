#include <stddef.h>
#include <stdint.h>

#include "crys_ecpki_build.h"
#include "crys_ecpki_dh.h"
#include "crys_ecpki_domain.h"
#include "crys_ecpki_kg.h"
#include "crys_rnd.h"
#include "sns_silib.h"

#define NRF_CRYPTOCELL_ENABLE (*(volatile uint32_t *)0x5002A500u)

enum {
    MANEKEY_CC310_OK = 0,
    MANEKEY_CC310_INVALID_KEY = 1,
    MANEKEY_CC310_FAILURE = 2,
};

static CRYS_RND_State_t rnd_state;
static CRYS_RND_WorkBuff_t rnd_work;
static CRYS_ECPKI_UserPrivKey_t private_key;
static CRYS_ECPKI_UserPublKey_t public_key;
static CRYS_ECPKI_KG_TempData_t keygen_temp;
static CRYS_ECPKI_KG_FipsContext_t keygen_fips;
static CRYS_ECPKI_BUILD_TempData_t build_temp;
static CRYS_ECDH_TempData_t ecdh_temp;
static int initialized;
static int private_key_loaded;

static void manekey_cc310_p256_clear_private(void) {
    volatile uint8_t *bytes = (volatile uint8_t *)&private_key;
    size_t index;

    for (index = 0; index < sizeof(private_key); index++) {
        bytes[index] = 0;
    }
    private_key_loaded = 0;
}

uint32_t manekey_cc310_p256_init(void) {
    if (initialized) {
        return MANEKEY_CC310_OK;
    }

    NRF_CRYPTOCELL_ENABLE = 1;
    if (SaSi_LibInit() != SA_SILIB_RET_OK) {
        return MANEKEY_CC310_FAILURE;
    }
    if (CRYS_RndInit(&rnd_state, &rnd_work) != SA_SILIB_RET_OK) {
        return MANEKEY_CC310_FAILURE;
    }
    initialized = 1;
    return MANEKEY_CC310_OK;
}

static uint32_t manekey_cc310_p256_generate_internal(uint8_t *private_out,
                                                     uint8_t public_out[65]) {
    const CRYS_ECPKI_Domain_t *domain =
        CRYS_ECPKI_GetEcDomain(CRYS_ECPKI_DomainID_secp256r1);
    uint32_t private_size = 32;
    uint32_t public_size = 65;

    if (!initialized || domain == NULL) {
        return MANEKEY_CC310_FAILURE;
    }
    if (CRYS_ECPKI_GenKeyPair(&rnd_state, CRYS_RND_GenerateVector, domain,
                              &private_key, &public_key, &keygen_temp,
                              &keygen_fips) != SA_SILIB_RET_OK) {
        return MANEKEY_CC310_FAILURE;
    }
    private_key_loaded = 1;
    if (private_out != NULL) {
        if (CRYS_ECPKI_ExportPrivKey(&private_key, private_out, &private_size) !=
                SA_SILIB_RET_OK ||
            private_size != 32) {
            return MANEKEY_CC310_FAILURE;
        }
    }
    if (CRYS_ECPKI_ExportPublKey(&public_key, CRYS_EC_PointUncompressed,
                                 public_out, &public_size) != SA_SILIB_RET_OK ||
        public_size != 65 || public_out[0] != 0x04) {
        return MANEKEY_CC310_FAILURE;
    }
    return MANEKEY_CC310_OK;
}

uint32_t manekey_cc310_p256_generate(uint8_t private_out[32],
                                     uint8_t public_out[65]) {
    return manekey_cc310_p256_generate_internal(private_out, public_out);
}

uint32_t manekey_cc310_p256_generate_opaque(uint8_t public_out[65]) {
    return manekey_cc310_p256_generate_internal(NULL, public_out);
}

uint32_t manekey_cc310_p256_import_private(const uint8_t private_in[32]) {
    const CRYS_ECPKI_Domain_t *domain =
        CRYS_ECPKI_GetEcDomain(CRYS_ECPKI_DomainID_secp256r1);

    if (!initialized || domain == NULL) {
        return MANEKEY_CC310_FAILURE;
    }
    if (CRYS_ECPKI_BuildPrivKey(domain, private_in, 32, &private_key) !=
        SA_SILIB_RET_OK) {
        return MANEKEY_CC310_INVALID_KEY;
    }
    private_key_loaded = 1;
    return MANEKEY_CC310_OK;
}

uint32_t manekey_cc310_p256_ecdh_loaded(uint8_t peer_public[65],
                                        uint8_t shared_secret[32]) {
    const CRYS_ECPKI_Domain_t *domain =
        CRYS_ECPKI_GetEcDomain(CRYS_ECPKI_DomainID_secp256r1);
    uint32_t shared_size = 32;

    if (!initialized || !private_key_loaded || domain == NULL) {
        return MANEKEY_CC310_FAILURE;
    }
    if (CRYS_ECPKI_BuildPublKeyFullCheck(domain, peer_public, 65, &public_key,
                                         &build_temp) != SA_SILIB_RET_OK) {
        return MANEKEY_CC310_INVALID_KEY;
    }
    if (CRYS_ECDH_SVDP_DH(&public_key, &private_key, shared_secret,
                          &shared_size, &ecdh_temp) != SA_SILIB_RET_OK ||
        shared_size != 32) {
        return MANEKEY_CC310_FAILURE;
    }
    return MANEKEY_CC310_OK;
}

uint32_t manekey_cc310_p256_ecdh_current(uint8_t peer_public[65],
                                         uint8_t shared_secret[32]) {
    uint32_t status =
        manekey_cc310_p256_ecdh_loaded(peer_public, shared_secret);
    manekey_cc310_p256_clear_private();
    return status;
}

uint32_t manekey_cc310_p256_ecdh(const uint8_t private_in[32],
                                 uint8_t peer_public[65],
                                 uint8_t shared_secret[32]) {
    uint32_t status = manekey_cc310_p256_import_private(private_in);
    if (status != MANEKEY_CC310_OK) {
        return status;
    }
    return manekey_cc310_p256_ecdh_loaded(peer_public, shared_secret);
}
