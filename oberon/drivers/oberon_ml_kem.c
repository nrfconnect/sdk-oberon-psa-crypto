/*
 * Copyright (c) 2016 - 2025 Nordic Semiconductor ASA
 * Copyright (c) since 2020 Oberon microsystems AG
 *
 * SPDX-License-Identifier: LicenseRef-Nordic-5-Clause
 */

//
// This file implements functions from the Arm PSA Crypto Driver API.

#include <string.h>

#include "psa/crypto.h"
#include "oberon_ml_kem.h"
#include "psa_crypto_driver_wrappers.h"


#ifdef PSA_NEED_OBERON_ML_KEM_512
#include "ocrypto_ml_kem512.h"
#endif /* PSA_NEED_OBERON_ML_KEM_512 */
#ifdef PSA_NEED_OBERON_ML_KEM_768
#include "ocrypto_ml_kem768.h"
#endif /* PSA_NEED_OBERON_ML_KEM_768 */
#ifdef PSA_NEED_OBERON_ML_KEM_1024
#include "ocrypto_ml_kem1024.h"
#endif /* PSA_NEED_OBERON_ML_KEM_1024 */

#if defined(PSA_NEED_OBERON_ML_KEM_512) || \
    defined(PSA_NEED_OBERON_ML_KEM_768) || \
    defined(PSA_NEED_OBERON_ML_KEM_1024)

#include "ocrypto_version.h"

#define MIN_REQUIRED_OCRYPTO_VERSION  0x03090500


#ifdef PSA_NEED_OBERON_ML_KEM_1024
#define ML_KEM_PK_SIZE  ocrypto_ml_kem1024_PK_SIZE
#define ML_KEM_SK_SIZE  ocrypto_ml_kem1024_SK_SIZE
#else
#ifdef PSA_NEED_OBERON_ML_KEM_768
#define ML_KEM_PK_SIZE  ocrypto_ml_kem768_PK_SIZE
#define ML_KEM_SK_SIZE  ocrypto_ml_kem768_SK_SIZE
#else
#ifdef PSA_NEED_OBERON_ML_KEM_512
#define ML_KEM_PK_SIZE  ocrypto_ml_kem512_PK_SIZE
#define ML_KEM_SK_SIZE  ocrypto_ml_kem512_SK_SIZE
#else
#define ML_KEM_PK_SIZE  1
#define ML_KEM_SK_SIZE  1
#endif
#endif
#endif


typedef union {
    uint8_t dummy;
#ifdef PSA_NEED_OBERON_ML_KEM_512
    ocrypto_ml_kem512_ctx kem512;
#endif /* PSA_NEED_OBERON_ML_KEM_512 */
#ifdef PSA_NEED_OBERON_ML_KEM_768
    ocrypto_ml_kem768_ctx kem768;
#endif /* PSA_NEED_OBERON_ML_KEM_768 */
#ifdef PSA_NEED_OBERON_ML_KEM_1024
    ocrypto_ml_kem1024_ctx kem1024;
#endif /* PSA_NEED_OBERON_ML_KEM_1024 */
} ocrypto_ml_kem_ctx;


static psa_status_t oberon_ml_kem_encapsulate_sk(
    ocrypto_ml_kem_ctx *ctx,
    const uint8_t *key, size_t bits,
    const uint8_t rnd[32],
    uint8_t *output_key, size_t output_key_size, size_t *output_key_length,
    uint8_t *ciphertext, size_t ciphertext_size, size_t *ciphertext_length)
{
    uint8_t pk[ML_KEM_PK_SIZE];

    if (output_key_size < 32) return PSA_ERROR_BUFFER_TOO_SMALL;

    switch (bits) {
#ifdef PSA_NEED_OBERON_ML_KEM_512
    case 512:
        if (ciphertext_size < ocrypto_ml_kem512_CT_SIZE) return PSA_ERROR_BUFFER_TOO_SMALL;
        ocrypto_ml_kem512_key_pair(&ctx->kem512, NULL, pk, key, key + 32);
        ocrypto_ml_kem512_encaps(&ctx->kem512, output_key, ciphertext, pk, rnd);
        *ciphertext_length = ocrypto_ml_kem512_CT_SIZE;
        break;
#endif /* PSA_NEED_OBERON_ML_KEM_512 */
#ifdef PSA_NEED_OBERON_ML_KEM_768
    case 768:
        if (ciphertext_size < ocrypto_ml_kem768_CT_SIZE) return PSA_ERROR_BUFFER_TOO_SMALL;
        ocrypto_ml_kem768_key_pair(&ctx->kem768, NULL, pk, key, key + 32);
        ocrypto_ml_kem768_encaps(&ctx->kem768, output_key, ciphertext, pk, rnd);
        *ciphertext_length = ocrypto_ml_kem768_CT_SIZE;
        break;
#endif /* PSA_NEED_OBERON_ML_KEM_768 */
#ifdef PSA_NEED_OBERON_ML_KEM_1024
    case 1024:
        if (ciphertext_size < ocrypto_ml_kem1024_CT_SIZE) return PSA_ERROR_BUFFER_TOO_SMALL;
        ocrypto_ml_kem1024_key_pair(&ctx->kem1024, NULL, pk, key, key + 32);
        ocrypto_ml_kem1024_encaps(&ctx->kem1024, output_key, ciphertext, pk, rnd);
        *ciphertext_length = ocrypto_ml_kem1024_CT_SIZE;
        break;
#endif /* PSA_NEED_OBERON_ML_KEM_1024 */
    default:
        (void)ctx;
        (void)key;
        (void)rnd;
        (void)output_key;
        (void)ciphertext;
        (void)ciphertext_size;
        (void)ciphertext_length;
        (void)pk;
        return PSA_ERROR_NOT_SUPPORTED;
    }

    *output_key_length = 32;
    return PSA_SUCCESS;
}

psa_status_t oberon_ml_kem_encapsulate(
    const psa_key_attributes_t *attributes,
    const uint8_t *key, size_t key_length,
    psa_algorithm_t alg,
    const psa_key_attributes_t *output_attributes,
    uint8_t *output_key, size_t output_key_size, size_t *output_key_length,
    uint8_t *ciphertext, size_t ciphertext_size, size_t *ciphertext_length)
{
    _Static_assert(OCRYPTO_VERSION_NUMBER >= MIN_REQUIRED_OCRYPTO_VERSION, 
        "ML-KEM Oberon driver: ocrypto version incompatible");

    ocrypto_ml_kem_ctx ctx;
    psa_key_type_t type = psa_get_key_type(attributes);
    size_t bits = psa_get_key_bits(attributes);
    uint8_t rnd[32];
    psa_status_t status;

    if (alg != PSA_ALG_ML_KEM) return PSA_ERROR_NOT_SUPPORTED;

    status = psa_generate_random(rnd, 32);
    if (status != PSA_SUCCESS) return status;

    if (type == PSA_KEY_TYPE_ML_KEM_KEY_PAIR) {
        if (key_length != 64) return PSA_ERROR_INVALID_ARGUMENT;
        return oberon_ml_kem_encapsulate_sk(&ctx, key, bits, rnd, output_key, output_key_size,
            output_key_length, ciphertext, ciphertext_size, ciphertext_length);
    } else if (type != PSA_KEY_TYPE_ML_KEM_PUBLIC_KEY) {
        return PSA_ERROR_NOT_SUPPORTED;
    }

    if (output_key_size < 32) return PSA_ERROR_BUFFER_TOO_SMALL;

    switch (bits) {
#ifdef PSA_NEED_OBERON_ML_KEM_512
    case 512:
        if (key_length != ocrypto_ml_kem512_PK_SIZE) return PSA_ERROR_INVALID_ARGUMENT;
        if (ciphertext_size < ocrypto_ml_kem512_CT_SIZE) return PSA_ERROR_BUFFER_TOO_SMALL;
        ocrypto_ml_kem512_encaps(&ctx.kem512, output_key, ciphertext, key, rnd);
        *ciphertext_length = ocrypto_ml_kem512_CT_SIZE;
        break;
#endif /* PSA_NEED_OBERON_ML_KEM_512 */
#ifdef PSA_NEED_OBERON_ML_KEM_768
    case 768:
        if (key_length != ocrypto_ml_kem768_PK_SIZE) return PSA_ERROR_INVALID_ARGUMENT;
        if (ciphertext_size < ocrypto_ml_kem768_CT_SIZE) return PSA_ERROR_BUFFER_TOO_SMALL;
        ocrypto_ml_kem768_encaps(&ctx.kem768, output_key, ciphertext, key, rnd);
        *ciphertext_length = ocrypto_ml_kem768_CT_SIZE;
        break;
#endif /* PSA_NEED_OBERON_ML_KEM_768 */
#ifdef PSA_NEED_OBERON_ML_KEM_1024
    case 1024:
        if (key_length != ocrypto_ml_kem1024_PK_SIZE) return PSA_ERROR_INVALID_ARGUMENT;
        if (ciphertext_size < ocrypto_ml_kem1024_CT_SIZE) return PSA_ERROR_BUFFER_TOO_SMALL;
        ocrypto_ml_kem1024_encaps(&ctx.kem1024, output_key, ciphertext, key, rnd);
        *ciphertext_length = ocrypto_ml_kem1024_CT_SIZE;
        break;
#endif /* PSA_NEED_OBERON_ML_KEM_1024 */
    default:
        (void)output_attributes;
        (void)ctx;
        return PSA_ERROR_NOT_SUPPORTED;
    }

    *output_key_length = 32;
    return PSA_SUCCESS;
}

psa_status_t oberon_ml_kem_decapsulate(
    const psa_key_attributes_t *attributes,
    const uint8_t *key, size_t key_length,
    psa_algorithm_t alg,
    const uint8_t *ciphertext, size_t ciphertext_length,
    const psa_key_attributes_t *output_attributes,
    uint8_t *output_key, size_t output_key_size, size_t *output_key_length)
{
    _Static_assert(OCRYPTO_VERSION_NUMBER >= MIN_REQUIRED_OCRYPTO_VERSION, 
        "ML-KEM Oberon driver: ocrypto version incompatible");

    ocrypto_ml_kem_ctx ctx;
    uint8_t sk[ML_KEM_SK_SIZE];
    psa_key_type_t type = psa_get_key_type(attributes);
    size_t bits = psa_get_key_bits(attributes);

    if (alg != PSA_ALG_ML_KEM) return PSA_ERROR_NOT_SUPPORTED;
    if (type != PSA_KEY_TYPE_ML_KEM_KEY_PAIR) return PSA_ERROR_NOT_SUPPORTED;
    if (key_length != 64) return PSA_ERROR_INVALID_ARGUMENT;
    if (output_key_size < 32) return PSA_ERROR_BUFFER_TOO_SMALL;

    switch (bits) {
#ifdef PSA_NEED_OBERON_ML_KEM_512
    case 512:
        if (ciphertext_length != ocrypto_ml_kem512_CT_SIZE) return PSA_ERROR_INVALID_ARGUMENT;
        ocrypto_ml_kem512_key_pair(&ctx.kem512, sk, NULL, key, key + 32);
        ocrypto_ml_kem512_decaps(&ctx.kem512, output_key, sk, ciphertext);
        break;
#endif /* PSA_NEED_OBERON_ML_KEM_512 */
#ifdef PSA_NEED_OBERON_ML_KEM_768
    case 768:
        if (ciphertext_length != ocrypto_ml_kem768_CT_SIZE) return PSA_ERROR_INVALID_ARGUMENT;
        ocrypto_ml_kem768_key_pair(&ctx.kem768, sk, NULL, key, key + 32);
        ocrypto_ml_kem768_decaps(&ctx.kem768, output_key, sk, ciphertext);
        break;
#endif /* PSA_NEED_OBERON_ML_KEM_768 */
#ifdef PSA_NEED_OBERON_ML_KEM_1024
    case 1024:
        if (ciphertext_length != ocrypto_ml_kem1024_CT_SIZE) return PSA_ERROR_INVALID_ARGUMENT;
        ocrypto_ml_kem1024_key_pair(&ctx.kem1024, sk, NULL, key, key + 32);
        ocrypto_ml_kem1024_decaps(&ctx.kem1024, output_key, sk, ciphertext);
        break;
#endif /* PSA_NEED_OBERON_ML_KEM_1024 */
    default:
        (void)key;
        (void)ciphertext;
        (void)ciphertext_length;
        (void)output_attributes;
        (void)output_key;
        (void)ctx;
        (void)sk;
        return PSA_ERROR_NOT_SUPPORTED;
    }

    *output_key_length = 32;
    return PSA_SUCCESS;
}


psa_status_t oberon_export_ml_kem_public_key(
    const psa_key_attributes_t *attributes,
    const uint8_t *key, size_t key_length,
    uint8_t *data, size_t data_size, size_t *data_length)
{
    _Static_assert(OCRYPTO_VERSION_NUMBER >= MIN_REQUIRED_OCRYPTO_VERSION, 
        "ML-KEM Oberon driver: ocrypto version incompatible");

    ocrypto_ml_kem_ctx ctx;
    psa_key_type_t type = psa_get_key_type(attributes);
    size_t bits = psa_get_key_bits(attributes);

    if (type == PSA_KEY_TYPE_ML_KEM_KEY_PAIR) {
        if (key_length != 64) return PSA_ERROR_INVALID_ARGUMENT;
        switch (bits) {
#ifdef PSA_NEED_OBERON_ML_KEM_512
        case 512:
            if (data_size < ocrypto_ml_kem512_PK_SIZE) return PSA_ERROR_BUFFER_TOO_SMALL;
            ocrypto_ml_kem512_key_pair(&ctx.kem512, NULL, data, key, key + 32);
            *data_length = ocrypto_ml_kem512_PK_SIZE;
            break;
#endif /* PSA_NEED_OBERON_ML_KEM_512 */
#ifdef PSA_NEED_OBERON_ML_KEM_768
        case 768:
            if (data_size < ocrypto_ml_kem768_PK_SIZE) return PSA_ERROR_BUFFER_TOO_SMALL;
            ocrypto_ml_kem768_key_pair(&ctx.kem768, NULL, data, key, key + 32);
            *data_length = ocrypto_ml_kem768_PK_SIZE;
            break;
#endif /* PSA_NEED_OBERON_ML_KEM_768 */
#ifdef PSA_NEED_OBERON_ML_KEM_1024
        case 1024:
            if (data_size < ocrypto_ml_kem1024_PK_SIZE) return PSA_ERROR_BUFFER_TOO_SMALL;
            ocrypto_ml_kem1024_key_pair(&ctx.kem1024, NULL, data, key, key + 32);
            *data_length = ocrypto_ml_kem1024_PK_SIZE;
            break;
#endif /* PSA_NEED_OBERON_ML_KEM_1024 */
        default:
            (void)ctx;
            return PSA_ERROR_NOT_SUPPORTED;
        };
    } else if (type == PSA_KEY_TYPE_ML_KEM_PUBLIC_KEY) {
        if (data_size < key_length) return PSA_ERROR_BUFFER_TOO_SMALL;
        memcpy(data, key, key_length);
        *data_length = key_length;
    } else {
        return PSA_ERROR_NOT_SUPPORTED;
    }

    return PSA_SUCCESS;
}

psa_status_t oberon_import_ml_kem_key(
    const psa_key_attributes_t *attributes,
    const uint8_t *data, size_t data_length,
    uint8_t *key, size_t key_size, size_t *key_length,
    size_t *key_bits)
{
    _Static_assert(OCRYPTO_VERSION_NUMBER >= MIN_REQUIRED_OCRYPTO_VERSION, 
        "ML-KEM Oberon driver: ocrypto version incompatible");

    psa_key_type_t type = psa_get_key_type(attributes);
    size_t bits = psa_get_key_bits(attributes);

    switch (type) {
    case PSA_KEY_TYPE_ML_KEM_KEY_PAIR:
        if (data_length != 64) return PSA_ERROR_INVALID_ARGUMENT;
        if (bits != 512 && bits != 768 && bits != 1024) return PSA_ERROR_NOT_SUPPORTED;
        break;
    case PSA_KEY_TYPE_ML_KEM_PUBLIC_KEY:
        switch (data_length) {
#ifdef PSA_NEED_OBERON_ML_KEM_512
        case ocrypto_ml_kem512_PK_SIZE:
            if (ocrypto_ml_kem512_check_key(data)) return PSA_ERROR_INVALID_ARGUMENT;
            bits = 512;
            break;
#endif /* PSA_NEED_OBERON_ML_KEM_512 */
#ifdef PSA_NEED_OBERON_ML_KEM_768
        case ocrypto_ml_kem768_PK_SIZE:
            if (ocrypto_ml_kem768_check_key(data)) return PSA_ERROR_INVALID_ARGUMENT;
            bits = 768;
            break;
#endif /* PSA_NEED_OBERON_ML_KEM_768 */
#ifdef PSA_NEED_OBERON_ML_KEM_1024
        case ocrypto_ml_kem1024_PK_SIZE:
            if (ocrypto_ml_kem1024_check_key(data)) return PSA_ERROR_INVALID_ARGUMENT;
            bits = 1024;
            break;
#endif /* PSA_NEED_OBERON_ML_KEM_1024 */
        default:
            (void)data;
            return PSA_ERROR_NOT_SUPPORTED;
        }
        break;
    default:
        return PSA_ERROR_NOT_SUPPORTED;
    }

    if (key_size < data_length) return PSA_ERROR_BUFFER_TOO_SMALL;
    memcpy(key, data, data_length);
    *key_length = data_length;
    *key_bits = bits;
    return PSA_SUCCESS;
}

#endif /* PSA_NEED_OBERON_ML_KEM_* */
