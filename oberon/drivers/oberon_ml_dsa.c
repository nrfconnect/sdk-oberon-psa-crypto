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
#include "oberon_ml_dsa.h"
#include "psa_crypto_driver_wrappers.h"

#ifdef PSA_NEED_OBERON_ML_DSA_44
#include "ocrypto_ml_dsa44.h"
#endif /* PSA_NEED_OBERON_ML_DSA_44 */
#ifdef PSA_NEED_OBERON_ML_DSA_65
#include "ocrypto_ml_dsa65.h"
#endif /* PSA_NEED_OBERON_ML_DSA_65 */
#ifdef PSA_NEED_OBERON_ML_DSA_87
#include "ocrypto_ml_dsa87.h"
#endif /* PSA_NEED_OBERON_ML_DSA_87 */

#if defined(PSA_NEED_OBERON_ML_DSA_44) || \
    defined(PSA_NEED_OBERON_ML_DSA_65) || \
    defined(PSA_NEED_OBERON_ML_DSA_87)

#include "ocrypto_version.h"

#define MIN_REQUIRED_OCRYPTO_VERSION  0x03090500


#ifdef PSA_NEED_OBERON_HASH_ML_DSA
static const uint8_t sha256_oid[11]   = {0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01};
static const uint8_t sha384_oid[11]   = {0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02};
static const uint8_t sha512_oid[11]   = {0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03};
static const uint8_t sha3_256_oid[11] = {0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x08};
static const uint8_t sha3_384_oid[11] = {0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x09};
static const uint8_t sha3_512_oid[11] = {0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x0A};
static const uint8_t shake128_oid[11] = {0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x0B};
static const uint8_t shake256_oid[11] = {0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x0C};
#endif /* PSA_NEED_OBERON_HASH_ML_DSA */


#ifdef PSA_NEED_OBERON_ML_DSA_87
#define ML_DSA_PK_SIZE  ocrypto_ml_dsa87_PK_SIZE
#define ML_DSA_SK_SIZE  ocrypto_ml_dsa87_SK_SIZE
#else
#ifdef PSA_NEED_OBERON_ML_DSA_65
#define ML_DSA_PK_SIZE  ocrypto_ml_dsa65_PK_SIZE
#define ML_DSA_SK_SIZE  ocrypto_ml_dsa65_SK_SIZE
#else
#ifdef PSA_NEED_OBERON_ML_DSA_44
#define ML_DSA_PK_SIZE  ocrypto_ml_dsa44_PK_SIZE
#define ML_DSA_SK_SIZE  ocrypto_ml_dsa44_SK_SIZE
#else
#define ML_DSA_PK_SIZE  1
#define ML_DSA_SK_SIZE  1
#endif
#endif
#endif


typedef union {
    uint8_t dummy;
#ifdef PSA_NEED_OBERON_ML_DSA_44
    ocrypto_ml_dsa44_ctx dsa44;
#endif /* PSA_NEED_OBERON_ML_DSA_44 */
#ifdef PSA_NEED_OBERON_ML_DSA_65
    ocrypto_ml_dsa65_ctx dsa65;
#endif /* PSA_NEED_OBERON_ML_DSA_65 */
#ifdef PSA_NEED_OBERON_ML_DSA_87
    ocrypto_ml_dsa87_ctx dsa87;
#endif /* PSA_NEED_OBERON_ML_DSA_87 */
} ocrypto_ml_dsa_ctx;


#ifdef PSA_NEED_OBERON_HASH_ML_DSA
static uint8_t const * oberon_get_hash_oid(psa_algorithm_t alg)
{
    switch (PSA_ALG_GET_HASH(alg)) {
    case PSA_ALG_SHA_256: return sha256_oid;
    case PSA_ALG_SHA_384: return sha384_oid;
    case PSA_ALG_SHA_512: return sha512_oid;
    case PSA_ALG_SHA3_256: return sha3_256_oid;
    case PSA_ALG_SHA3_384: return sha3_384_oid;
    case PSA_ALG_SHA3_512: return sha3_512_oid;
    case PSA_ALG_SHAKE128_256: return shake128_oid;
    case PSA_ALG_SHAKE256_512: return shake256_oid;
    default: return NULL;
    }
}
#endif /* PSA_NEED_OBERON_HASH_ML_DSA */


psa_status_t oberon_ml_dsa_sign_message_with_context(
    const psa_key_attributes_t *attributes,
    const uint8_t *key, size_t key_length,
    psa_algorithm_t alg,
    const uint8_t *input, size_t input_length,
    const uint8_t *context, size_t context_length,
    uint8_t *signature, size_t signature_size, size_t *signature_length)
{
    _Static_assert(OCRYPTO_VERSION_NUMBER >= MIN_REQUIRED_OCRYPTO_VERSION, 
        "ML-DSA Oberon driver: ocrypto version incompatible");
    
    ocrypto_ml_dsa_ctx ctx;
    uint8_t sk[ML_DSA_SK_SIZE];
    psa_key_type_t type = psa_get_key_type(attributes);
    size_t bits = psa_get_key_bits(attributes);
    uint8_t rnd[32];
    psa_status_t status;

    if (type != PSA_KEY_TYPE_ML_DSA_KEY_PAIR) return PSA_ERROR_NOT_SUPPORTED;
    if (key_length != 32 || context_length >= 256) return PSA_ERROR_INVALID_ARGUMENT;

    if (alg == PSA_ALG_DETERMINISTIC_ML_DSA) {
        memset(rnd, 0, 32);
    } else if (alg == PSA_ALG_ML_DSA) {
        status = psa_generate_random(rnd, 32);
        if (status != PSA_SUCCESS) return status;
    } else {
        return PSA_ERROR_NOT_SUPPORTED;
    }

    switch (bits) {
#ifdef PSA_NEED_OBERON_ML_DSA_44
    case 128:
        if (signature_size < ocrypto_ml_dsa44_SIG_SIZE) return PSA_ERROR_BUFFER_TOO_SMALL;
        ocrypto_ml_dsa44_key_pair(&ctx.dsa44, sk, signature, key);
        ocrypto_ml_dsa44_sign(&ctx.dsa44, signature, input, input_length, context, context_length, sk, rnd);
        *signature_length = ocrypto_ml_dsa44_SIG_SIZE;
        return PSA_SUCCESS;
#endif /* PSA_NEED_OBERON_ML_DSA_44 */
#ifdef PSA_NEED_OBERON_ML_DSA_65
    case 192:
        if (signature_size < ocrypto_ml_dsa65_SIG_SIZE) return PSA_ERROR_BUFFER_TOO_SMALL;
        ocrypto_ml_dsa65_key_pair(&ctx.dsa65, sk, signature, key);
        ocrypto_ml_dsa65_sign(&ctx.dsa65, signature, input, input_length, context, context_length, sk, rnd);
        *signature_length = ocrypto_ml_dsa65_SIG_SIZE;
        return PSA_SUCCESS;
#endif /* PSA_NEED_OBERON_ML_DSA_65 */
#ifdef PSA_NEED_OBERON_ML_DSA_87
    case 256:
        if (signature_size < ocrypto_ml_dsa87_SIG_SIZE) return PSA_ERROR_BUFFER_TOO_SMALL;
        ocrypto_ml_dsa87_key_pair(&ctx.dsa87, sk, signature, key);
        ocrypto_ml_dsa87_sign(&ctx.dsa87, signature, input, input_length, context, context_length, sk, rnd);
        *signature_length = ocrypto_ml_dsa87_SIG_SIZE;
        return PSA_SUCCESS;
#endif /* PSA_NEED_OBERON_ML_DSA_87 */
    default:
        (void)key;
        (void)input;
        (void)input_length;
        (void)signature;
        (void)signature_size;
        (void)signature_length;
        (void)ctx;
        (void)sk;
        return PSA_ERROR_NOT_SUPPORTED;
    }
}

#ifdef PSA_NEED_OBERON_HASH_ML_DSA
psa_status_t oberon_ml_dsa_sign_hash_with_context(
    const psa_key_attributes_t *attributes,
    const uint8_t *key, size_t key_length,
    psa_algorithm_t alg,
    const uint8_t *hash, size_t hash_length,
    const uint8_t *context, size_t context_length,
    uint8_t *signature, size_t signature_size, size_t *signature_length)
{
    _Static_assert(OCRYPTO_VERSION_NUMBER >= MIN_REQUIRED_OCRYPTO_VERSION, 
        "ML-DSA Oberon driver: ocrypto version incompatible");

    ocrypto_ml_dsa_ctx ctx;
    uint8_t sk[ML_DSA_SK_SIZE];
    psa_key_type_t type = psa_get_key_type(attributes);
    size_t bits = psa_get_key_bits(attributes);
    uint8_t rnd[32];
    const uint8_t *oid;
    psa_status_t status;

    if (type != PSA_KEY_TYPE_ML_DSA_KEY_PAIR) return PSA_ERROR_NOT_SUPPORTED;
    if (key_length != 32 || context_length >= 256) return PSA_ERROR_INVALID_ARGUMENT;

    if (PSA_ALG_IS_DETERMINISTIC_HASH_ML_DSA(alg)) {
        memset(rnd, 0, 32);
    } else if (PSA_ALG_IS_HEDGED_HASH_ML_DSA(alg)) {
        status = psa_generate_random(rnd, 32);
        if (status != PSA_SUCCESS) return status;
    } else {
        return PSA_ERROR_NOT_SUPPORTED;
    }

    oid = oberon_get_hash_oid(alg);
    if (oid == NULL) return PSA_ERROR_NOT_SUPPORTED;

    switch (bits) {
#ifdef PSA_NEED_OBERON_ML_DSA_44
    case 128:
        if (signature_size < ocrypto_ml_dsa44_SIG_SIZE) return PSA_ERROR_BUFFER_TOO_SMALL;
        ocrypto_ml_dsa44_key_pair(&ctx.dsa44, sk, signature, key);
        ocrypto_ml_dsa44_sign_hash(&ctx.dsa44, signature, hash, hash_length, oid, context, context_length, sk, rnd);
        *signature_length = ocrypto_ml_dsa44_SIG_SIZE;
        return PSA_SUCCESS;
#endif /* PSA_NEED_OBERON_ML_DSA_44 */
#ifdef PSA_NEED_OBERON_ML_DSA_65
    case 192:
        if (signature_size < ocrypto_ml_dsa65_SIG_SIZE) return PSA_ERROR_BUFFER_TOO_SMALL;
        ocrypto_ml_dsa65_key_pair(&ctx.dsa65, sk, signature, key);
        ocrypto_ml_dsa65_sign_hash(&ctx.dsa65, signature, hash, hash_length, oid, context, context_length, sk, rnd);
        *signature_length = ocrypto_ml_dsa65_SIG_SIZE;
        return PSA_SUCCESS;
#endif /* PSA_NEED_OBERON_ML_DSA_65 */
#ifdef PSA_NEED_OBERON_ML_DSA_87
    case 256:
        if (signature_size < ocrypto_ml_dsa87_SIG_SIZE) return PSA_ERROR_BUFFER_TOO_SMALL;
        ocrypto_ml_dsa87_key_pair(&ctx.dsa87, sk, signature, key);
        ocrypto_ml_dsa87_sign_hash(&ctx.dsa87, signature, hash, hash_length, oid, context, context_length, sk, rnd);
        *signature_length = ocrypto_ml_dsa87_SIG_SIZE;
        return PSA_SUCCESS;
#endif /* PSA_NEED_OBERON_ML_DSA_87 */
    default:
        (void)key;
        (void)hash;
        (void)hash_length;
        (void)signature;
        (void)signature_size;
        (void)signature_length;
        (void)ctx;
        (void)sk;
        return PSA_ERROR_NOT_SUPPORTED;
    }
}
#endif /* PSA_NEED_OBERON_HASH_ML_DSA */

static psa_status_t oberon_ml_dsa_verify_message_sk(
    ocrypto_ml_dsa_ctx *ctx,
    const uint8_t *key, size_t bits,
    const uint8_t *input, size_t input_length,
    const uint8_t *context, size_t context_length,
    const uint8_t *signature, size_t signature_length)
{
    uint8_t pk[ML_DSA_PK_SIZE];
    int res;

    switch (bits) {
#ifdef PSA_NEED_OBERON_ML_DSA_44
    case 128:
        if (signature_length != ocrypto_ml_dsa44_SIG_SIZE) return PSA_ERROR_INVALID_ARGUMENT;
        ocrypto_ml_dsa44_key_pair(&ctx->dsa44, NULL, pk, key);
        res = ocrypto_ml_dsa44_verify(&ctx->dsa44, signature, input, input_length, context, context_length, pk);
        break;
#endif /* PSA_NEED_OBERON_ML_DSA_44 */
#ifdef PSA_NEED_OBERON_ML_DSA_65
    case 192:
        if (signature_length != ocrypto_ml_dsa65_SIG_SIZE) return PSA_ERROR_INVALID_ARGUMENT;
        ocrypto_ml_dsa65_key_pair(&ctx->dsa65, NULL, pk, key);
        res = ocrypto_ml_dsa65_verify(&ctx->dsa65, signature, input, input_length, context, context_length, pk);
        break;
#endif /* PSA_NEED_OBERON_ML_DSA_65 */
#ifdef PSA_NEED_OBERON_ML_DSA_87
    case 256:
        if (signature_length != ocrypto_ml_dsa87_SIG_SIZE) return PSA_ERROR_INVALID_ARGUMENT;
        ocrypto_ml_dsa87_key_pair(&ctx->dsa87, NULL, pk, key);
        res = ocrypto_ml_dsa87_verify(&ctx->dsa87, signature, input, input_length, context, context_length, pk);
        break;
#endif /* PSA_NEED_OBERON_ML_DSA_87 */
    default:
        (void)ctx;
        (void)key;
        (void)input;
        (void)input_length;
        (void)signature;
        (void)signature_length;
        (void)pk;
        return PSA_ERROR_NOT_SUPPORTED;
    }

    if (res) return PSA_ERROR_INVALID_SIGNATURE;
    return PSA_SUCCESS;
}

psa_status_t oberon_ml_dsa_verify_message_with_context(
    const psa_key_attributes_t *attributes,
    const uint8_t *key, size_t key_length,
    psa_algorithm_t alg,
    const uint8_t *input, size_t input_length,
    const uint8_t *context, size_t context_length,
    const uint8_t *signature, size_t signature_length)
{
    _Static_assert(OCRYPTO_VERSION_NUMBER >= MIN_REQUIRED_OCRYPTO_VERSION, 
        "ML-DSA Oberon driver: ocrypto version incompatible");

    ocrypto_ml_dsa_ctx ctx;
    psa_key_type_t type = psa_get_key_type(attributes);
    size_t bits = psa_get_key_bits(attributes);
    int res;

    if (alg != PSA_ALG_ML_DSA && alg != PSA_ALG_DETERMINISTIC_ML_DSA) {
        return PSA_ERROR_NOT_SUPPORTED;
    }
    if (context_length >= 256) return PSA_ERROR_INVALID_ARGUMENT;

    if (type == PSA_KEY_TYPE_ML_DSA_KEY_PAIR) {
        if (key_length != 32) return PSA_ERROR_INVALID_ARGUMENT;
        return oberon_ml_dsa_verify_message_sk(&ctx, key, bits, input, input_length, context, context_length, signature, signature_length);
    } else if (type != PSA_KEY_TYPE_ML_DSA_PUBLIC_KEY) {
        return PSA_ERROR_NOT_SUPPORTED;
    }

    switch (bits) {
#ifdef PSA_NEED_OBERON_ML_DSA_44
    case 128:
        if (key_length != ocrypto_ml_dsa44_PK_SIZE) return PSA_ERROR_INVALID_ARGUMENT;
        if (signature_length != ocrypto_ml_dsa44_SIG_SIZE) return PSA_ERROR_INVALID_ARGUMENT;
        res = ocrypto_ml_dsa44_verify(&ctx.dsa44, signature, input, input_length, context, context_length, key);
        break;
#endif /* PSA_NEED_OBERON_ML_DSA_44 */
#ifdef PSA_NEED_OBERON_ML_DSA_65
    case 192:
        if (key_length != ocrypto_ml_dsa65_PK_SIZE) return PSA_ERROR_INVALID_ARGUMENT;
        if (signature_length != ocrypto_ml_dsa65_SIG_SIZE) return PSA_ERROR_INVALID_ARGUMENT;
        res = ocrypto_ml_dsa65_verify(&ctx.dsa65, signature, input, input_length, context, context_length, key);
        break;
#endif /* PSA_NEED_OBERON_ML_DSA_65 */
#ifdef PSA_NEED_OBERON_ML_DSA_87
    case 256:
        if (key_length != ocrypto_ml_dsa87_PK_SIZE) return PSA_ERROR_INVALID_ARGUMENT;
        if (signature_length != ocrypto_ml_dsa87_SIG_SIZE) return PSA_ERROR_INVALID_ARGUMENT;
        res = ocrypto_ml_dsa87_verify(&ctx.dsa87, signature, input, input_length, context, context_length, key);
        break;
#endif /* PSA_NEED_OBERON_ML_DSA_87 */
    default:
        (void)input;
        (void)input_length;
        (void)signature;
        (void)signature_length;
        return PSA_ERROR_NOT_SUPPORTED;
    }

    if (res) return PSA_ERROR_INVALID_SIGNATURE;
    return PSA_SUCCESS;
}

#ifdef PSA_NEED_OBERON_HASH_ML_DSA
static psa_status_t oberon_ml_dsa_verify_hash_sk(
    ocrypto_ml_dsa_ctx *ctx,
    const uint8_t *key, size_t bits,
    const uint8_t *oid,
    const uint8_t *hash, size_t hash_length,
    const uint8_t *context, size_t context_length,
    const uint8_t *signature, size_t signature_length)
{
    uint8_t pk[ML_DSA_PK_SIZE];
    int res;

    switch (bits) {
#ifdef PSA_NEED_OBERON_ML_DSA_44
    case 128:
        if (signature_length != ocrypto_ml_dsa44_SIG_SIZE) return PSA_ERROR_INVALID_ARGUMENT;
        ocrypto_ml_dsa44_key_pair(&ctx->dsa44, NULL, pk, key);
        res = ocrypto_ml_dsa44_verify_hash(&ctx->dsa44, signature, hash, hash_length, oid, context, context_length, pk);
        break;
#endif /* PSA_NEED_OBERON_ML_DSA_44 */
#ifdef PSA_NEED_OBERON_ML_DSA_65
    case 192:
        if (signature_length != ocrypto_ml_dsa65_SIG_SIZE) return PSA_ERROR_INVALID_ARGUMENT;
        ocrypto_ml_dsa65_key_pair(&ctx->dsa65, NULL, pk, key);
        res = ocrypto_ml_dsa65_verify_hash(&ctx->dsa65, signature, hash, hash_length, oid, context, context_length, pk);
        break;
#endif /* PSA_NEED_OBERON_ML_DSA_65 */
#ifdef PSA_NEED_OBERON_ML_DSA_87
    case 256:
        if (signature_length != ocrypto_ml_dsa87_SIG_SIZE) return PSA_ERROR_INVALID_ARGUMENT;
        ocrypto_ml_dsa87_key_pair(&ctx->dsa87, NULL, pk, key);
        res = ocrypto_ml_dsa87_verify_hash(&ctx->dsa87, signature, hash, hash_length, oid, context, context_length, pk);
        break;
#endif /* PSA_NEED_OBERON_ML_DSA_87 */
    default:
        (void)ctx;
        (void)key;
        (void)oid;
        (void)hash;
        (void)hash_length;
        (void)signature;
        (void)signature_length;
        (void)pk;
        return PSA_ERROR_NOT_SUPPORTED;
    }

    if (res) return PSA_ERROR_INVALID_SIGNATURE;
    return PSA_SUCCESS;
}

psa_status_t oberon_ml_dsa_verify_hash_with_context(
    const psa_key_attributes_t *attributes,
    const uint8_t *key, size_t key_length,
    psa_algorithm_t alg,
    const uint8_t *hash, size_t hash_length,
    const uint8_t *context, size_t context_length,
    const uint8_t *signature, size_t signature_length)
{
    _Static_assert(OCRYPTO_VERSION_NUMBER >= MIN_REQUIRED_OCRYPTO_VERSION, 
        "ML-DSA Oberon driver: ocrypto version incompatible");

    ocrypto_ml_dsa_ctx ctx;
    psa_key_type_t type = psa_get_key_type(attributes);
    size_t bits = psa_get_key_bits(attributes);
    const uint8_t *oid;
    int res;

    if (!PSA_ALG_IS_HASH_ML_DSA(alg)) return PSA_ERROR_NOT_SUPPORTED;
    if (context_length >= 256) return PSA_ERROR_INVALID_ARGUMENT;

    oid = oberon_get_hash_oid(alg);
    if (oid == NULL) return PSA_ERROR_NOT_SUPPORTED;

    if (type == PSA_KEY_TYPE_ML_DSA_KEY_PAIR) {
        if (key_length != 32) return PSA_ERROR_INVALID_ARGUMENT;
        return oberon_ml_dsa_verify_hash_sk(&ctx, key, bits, oid, hash, hash_length, context, context_length, signature, signature_length);
    } else if (type != PSA_KEY_TYPE_ML_DSA_PUBLIC_KEY) {
        return PSA_ERROR_NOT_SUPPORTED;
    }

    switch (bits) {
#ifdef PSA_NEED_OBERON_ML_DSA_44
    case 128:
        if (key_length != ocrypto_ml_dsa44_PK_SIZE) return PSA_ERROR_INVALID_ARGUMENT;
        if (signature_length != ocrypto_ml_dsa44_SIG_SIZE) return PSA_ERROR_INVALID_ARGUMENT;
        res = ocrypto_ml_dsa44_verify_hash(&ctx.dsa44, signature, hash, hash_length, oid, context, context_length, key);
        break;
#endif /* PSA_NEED_OBERON_ML_DSA_44 */
#ifdef PSA_NEED_OBERON_ML_DSA_65
    case 192:
        if (key_length != ocrypto_ml_dsa65_PK_SIZE) return PSA_ERROR_INVALID_ARGUMENT;
        if (signature_length != ocrypto_ml_dsa65_SIG_SIZE) return PSA_ERROR_INVALID_ARGUMENT;
        res = ocrypto_ml_dsa65_verify_hash(&ctx.dsa65, signature, hash, hash_length, oid, context, context_length, key);
        break;
#endif /* PSA_NEED_OBERON_ML_DSA_65 */
#ifdef PSA_NEED_OBERON_ML_DSA_87
    case 256:
        if (key_length != ocrypto_ml_dsa87_PK_SIZE) return PSA_ERROR_INVALID_ARGUMENT;
        if (signature_length != ocrypto_ml_dsa87_SIG_SIZE) return PSA_ERROR_INVALID_ARGUMENT;
        res = ocrypto_ml_dsa87_verify_hash(&ctx.dsa87, signature, hash, hash_length, oid, context, context_length, key);
        break;
#endif /* PSA_NEED_OBERON_ML_DSA_87 */
    default:
        (void)hash;
        (void)hash_length;
        (void)signature;
        (void)signature_length;
        (void)ctx;
        return PSA_ERROR_NOT_SUPPORTED;
    }

    if (res) return PSA_ERROR_INVALID_SIGNATURE;
    return PSA_SUCCESS;
}
#endif /* PSA_NEED_OBERON_HASH_ML_DSA */


psa_status_t oberon_export_ml_dsa_public_key(
    const psa_key_attributes_t *attributes,
    const uint8_t *key, size_t key_length,
    uint8_t *data, size_t data_size, size_t *data_length)
{
    _Static_assert(OCRYPTO_VERSION_NUMBER >= MIN_REQUIRED_OCRYPTO_VERSION, 
        "ML-DSA Oberon driver: ocrypto version incompatible");

    ocrypto_ml_dsa_ctx ctx;
    psa_key_type_t type = psa_get_key_type(attributes);
    size_t bits = psa_get_key_bits(attributes);

    if (type == PSA_KEY_TYPE_ML_DSA_KEY_PAIR) {
        if (key_length != 32) return PSA_ERROR_INVALID_ARGUMENT;
        switch (bits) {
#ifdef PSA_NEED_OBERON_ML_DSA_44
        case 128:
            if (data_size < ocrypto_ml_dsa44_PK_SIZE) return PSA_ERROR_BUFFER_TOO_SMALL;
            ocrypto_ml_dsa44_key_pair(&ctx.dsa44, NULL, data, key);
            *data_length = ocrypto_ml_dsa44_PK_SIZE;
            break;
#endif /* PSA_NEED_OBERON_ML_DSA_44 */
#ifdef PSA_NEED_OBERON_ML_DSA_65
        case 192:
            if (data_size < ocrypto_ml_dsa65_PK_SIZE) return PSA_ERROR_BUFFER_TOO_SMALL;
            ocrypto_ml_dsa65_key_pair(&ctx.dsa65, NULL, data, key);
            *data_length = ocrypto_ml_dsa65_PK_SIZE;
            break;
#endif /* PSA_NEED_OBERON_ML_DSA_65 */
#ifdef PSA_NEED_OBERON_ML_DSA_87
        case 256:
            if (data_size < ocrypto_ml_dsa87_PK_SIZE) return PSA_ERROR_BUFFER_TOO_SMALL;
            ocrypto_ml_dsa87_key_pair(&ctx.dsa87, NULL, data, key);
            *data_length = ocrypto_ml_dsa87_PK_SIZE;
            break;
#endif /* PSA_NEED_OBERON_ML_DSA_87 */
        default:
            (void)ctx;
            return PSA_ERROR_NOT_SUPPORTED;
        };
    } else if (type == PSA_KEY_TYPE_ML_DSA_PUBLIC_KEY) {
        if (data_size < key_length) return PSA_ERROR_BUFFER_TOO_SMALL;
        memcpy(data, key, key_length);
        *data_length = key_length;
    } else {
        return PSA_ERROR_NOT_SUPPORTED;
    }

    return PSA_SUCCESS;
}

psa_status_t oberon_import_ml_dsa_key(
    const psa_key_attributes_t *attributes,
    const uint8_t *data, size_t data_length,
    uint8_t *key, size_t key_size, size_t *key_length,
    size_t *key_bits)
{
    _Static_assert(OCRYPTO_VERSION_NUMBER >= MIN_REQUIRED_OCRYPTO_VERSION, 
        "ML-DSA Oberon driver: ocrypto version incompatible");

    psa_key_type_t type = psa_get_key_type(attributes);
    size_t bits = psa_get_key_bits(attributes);

    switch (type) {
    case PSA_KEY_TYPE_ML_DSA_KEY_PAIR:
        if (data_length != 32) return PSA_ERROR_INVALID_ARGUMENT;
        if (bits != 128 && bits != 192 && bits != 256) return PSA_ERROR_NOT_SUPPORTED;
        break;
    case PSA_KEY_TYPE_ML_DSA_PUBLIC_KEY:
        switch (data_length) {
#ifdef PSA_NEED_OBERON_ML_DSA_44
        case ocrypto_ml_dsa44_PK_SIZE:
            bits = 128;
            break;
#endif /* PSA_NEED_OBERON_ML_DSA_44 */
#ifdef PSA_NEED_OBERON_ML_DSA_65
        case ocrypto_ml_dsa65_PK_SIZE:
            bits = 192;
            break;
#endif /* PSA_NEED_OBERON_ML_DSA_65 */
#ifdef PSA_NEED_OBERON_ML_DSA_87
        case ocrypto_ml_dsa87_PK_SIZE:
            bits = 256;
            break;
#endif /* PSA_NEED_OBERON_ML_DSA_87 */
        default:
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

#endif /* PSA_NEED_OBERON_ML_DSA_* */
