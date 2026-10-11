/* SPDX-License-Identifier: Apache-2.0 */
/*
 * ManeKey's thin boundary around the vendored mldsa-native core API.
 *
 * This file intentionally owns no key material. Rust passes fixed-size buffers,
 * and the upstream implementation owns its ephemeral stack/allocation strategy.
 */
#include <stddef.h>
#include <stdint.h>

#include "mldsa_native.h"

static const uint8_t MANEKEY_MLDSA_PURE_PREFIX[] = {0x00u, 0x00u};

int manekey_mldsa44_keypair_from_seed(
    uint8_t pk[MLDSA44_PUBLICKEYBYTES], uint8_t sk[MLDSA44_SECRETKEYBYTES],
    const uint8_t seed[MLDSA44_SEEDBYTES]) {
  return manekey_mldsa_keypair_internal(pk, sk, seed);
}

int manekey_mldsa44_sign(
    uint8_t sig[MLDSA44_BYTES], const uint8_t *message, size_t message_len,
    const uint8_t rnd[MLDSA44_RNDBYTES],
    const uint8_t sk[MLDSA44_SECRETKEYBYTES]) {
  return manekey_mldsa_signature_internal(
      sig, message, message_len, MANEKEY_MLDSA_PURE_PREFIX,
      sizeof(MANEKEY_MLDSA_PURE_PREFIX), rnd, sk, 0);
}

int manekey_mldsa44_verify(
    const uint8_t sig[MLDSA44_BYTES], const uint8_t *message,
    size_t message_len, const uint8_t pk[MLDSA44_PUBLICKEYBYTES]) {
  return manekey_mldsa_verify_internal(
      sig, message, message_len, MANEKEY_MLDSA_PURE_PREFIX,
      sizeof(MANEKEY_MLDSA_PURE_PREFIX), pk, 0);
}
