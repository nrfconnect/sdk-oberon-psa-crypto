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
#include "oberon_eddsa.h"
#include "psa_crypto_driver_wrappers.h"

#ifdef PSA_NEED_OBERON_PURE_EDDSA_TWISTED_EDWARDS_255
#include "ocrypto_ed25519.h"
#endif /* PSA_NEED_OBERON_PURE_EDDSA_TWISTED_EDWARDS_255 */
#ifdef PSA_NEED_OBERON_ED25519PH
#include "ocrypto_ed25519ph.h"
#endif /* PSA_NEED_OBERON_ED25519PH */
#ifdef PSA_NEED_OBERON_PURE_EDDSA_TWISTED_EDWARDS_448
#include "ocrypto_ed448.h"
#endif /* PSA_NEED_OBERON_PURE_EDDSA_TWISTED_EDWARDS_448 */
#ifdef PSA_NEED_OBERON_ED448PH
#include "ocrypto_ed448ph.h"
#endif /* PSA_NEED_OBERON_ED448PH */


psa_status_t oberon_eddsa_sign_hash_with_context(
    const psa_key_attributes_t *attributes,
    const uint8_t *key, size_t key_length,
    psa_algorithm_t alg,
    const uint8_t *hash, size_t hash_length,
    const uint8_t *context, size_t context_length,
    uint8_t *signature, size_t signature_size, size_t *signature_length)
{
    int res;
    psa_status_t status;
    uint8_t ek[PSA_BITS_TO_BYTES(PSA_VENDOR_ECC_MAX_CURVE_BITS)];
    psa_key_type_t type = psa_get_key_type(attributes);

    switch (type) {
#if defined(PSA_NEED_OBERON_ED25519PH) || defined(PSA_NEED_OBERON_ED448PH)
    case PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_TWISTED_EDWARDS):
        if (context_length != 0) return PSA_ERROR_NOT_SUPPORTED;
        switch (psa_get_key_bits(attributes)) {
#ifdef PSA_NEED_OBERON_ED25519PH
        case 255:
            if (hash_length != ocrypto_ed25519ph_HASH_BYTES) return PSA_ERROR_INVALID_ARGUMENT;
            if (key_length != ocrypto_ed25519ph_SECRET_KEY_BYTES) return PSA_ERROR_INVALID_ARGUMENT;
            if (signature_size < ocrypto_ed25519ph_BYTES) return PSA_ERROR_BUFFER_TOO_SMALL;
            *signature_length = ocrypto_ed25519ph_BYTES;
            ocrypto_ed25519ph_public_key(ek, key); // calculate public key
            ocrypto_ed25519ph_sign(signature, hash, key, ek);
            break;
#endif /* PSA_NEED_OBERON_ED25519PH */
#ifdef PSA_NEED_OBERON_ED448PH
        case 448:
            if (hash_length != ocrypto_ed448ph_HASH_BYTES) return PSA_ERROR_INVALID_ARGUMENT;
            if (key_length != ocrypto_ed448ph_SECRET_KEY_BYTES) return PSA_ERROR_INVALID_ARGUMENT;
            if (signature_size < ocrypto_ed448ph_BYTES) return PSA_ERROR_BUFFER_TOO_SMALL;
            *signature_length = ocrypto_ed448ph_BYTES;
            ocrypto_ed448ph_public_key(ek, key); // calculate public key
            ocrypto_ed448ph_sign(signature, hash, key, ek);
            break;
#endif /* PSA_NEED_OBERON_ED448PH */
        default:
            return PSA_ERROR_NOT_SUPPORTED;
        }
        return PSA_SUCCESS;
#endif /* PSA_NEED_OBERON_ED25519PH || PSA_NEED_OBERON_ED448PH */

    default:
        (void)key;
        (void)key_length;
        (void)alg;
        (void)hash;
        (void)hash_length;
        (void)context;
        (void)context_length;
        (void)signature;
        (void)signature_size;
        (void)signature_length;
        (void)ek;
        (void)status;
        (void)res;
        return PSA_ERROR_NOT_SUPPORTED;
    }
}

psa_status_t oberon_eddsa_sign_message_with_context(
    const psa_key_attributes_t *attributes,
    const uint8_t *key, size_t key_length,
    psa_algorithm_t alg,
    const uint8_t *input, size_t input_length,
    const uint8_t *context, size_t context_length,
    uint8_t *signature, size_t signature_size, size_t *signature_length)
{
#if defined(PSA_NEED_OBERON_PURE_EDDSA_TWISTED_EDWARDS_448)
    uint8_t pub_key[57];
#elif defined(PSA_NEED_OBERON_PURE_EDDSA_TWISTED_EDWARDS_255)
    uint8_t pub_key[32];
#endif
    psa_key_type_t type = psa_get_key_type(attributes);

    switch (type) {
#if defined(PSA_NEED_OBERON_PURE_EDDSA_TWISTED_EDWARDS_255) || defined(PSA_NEED_OBERON_PURE_EDDSA_TWISTED_EDWARDS_448)
    case PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_TWISTED_EDWARDS):
        // EDDSA is only available in sign_message
        // PSA_ALG_ED*PH must be delegated to sign_hash
        if (alg != PSA_ALG_PURE_EDDSA) return PSA_ERROR_NOT_SUPPORTED;
        switch (psa_get_key_bits(attributes)) {
#ifdef PSA_NEED_OBERON_PURE_EDDSA_TWISTED_EDWARDS_255
        case 255:
            if (alg == PSA_ALG_ED25519PH) return PSA_ERROR_NOT_SUPPORTED;
            if (key_length != ocrypto_ed25519_SECRET_KEY_BYTES) return PSA_ERROR_INVALID_ARGUMENT;
            if (signature_size < ocrypto_ed25519_BYTES) return PSA_ERROR_BUFFER_TOO_SMALL;
            *signature_length = ocrypto_ed25519_BYTES;
            ocrypto_ed25519_public_key(pub_key, key); // calculate public key
            ocrypto_ed25519_sign(signature, input, input_length, key, pub_key);
            break;
#endif
#ifdef PSA_NEED_OBERON_PURE_EDDSA_TWISTED_EDWARDS_448
        case 448:
            if (alg == PSA_ALG_ED448PH) return PSA_ERROR_NOT_SUPPORTED;
            if (key_length != ocrypto_ed448_SECRET_KEY_BYTES) return PSA_ERROR_INVALID_ARGUMENT;
            if (signature_size < ocrypto_ed448_BYTES) return PSA_ERROR_BUFFER_TOO_SMALL;
            *signature_length = ocrypto_ed448_BYTES;
            ocrypto_ed448_public_key(pub_key, key); // calculate public key
            ocrypto_ed448_sign(signature, input, input_length, key, pub_key);
            break;
#endif
        default:
            return PSA_ERROR_NOT_SUPPORTED;
        }
        return PSA_SUCCESS;
#endif /* PSA_NEED_OBERON_PURE_EDDSA_TWISTED_EDWARDS_255 || PSA_NEED_OBERON_PURE_EDDSA_TWISTED_EDWARDS_448 */
    default:
        (void)key;
        (void)key_length;
        (void)alg;
        (void)input;
        (void)input_length;
        (void)context;
        (void)context_length;
        (void)signature;
        (void)signature_size;
        (void)signature_length;
        return PSA_ERROR_NOT_SUPPORTED;
    }
}

psa_status_t oberon_eddsa_verify_hash_with_context(
    const psa_key_attributes_t *attributes,
    const uint8_t *key, size_t key_length,
    psa_algorithm_t alg,
    const uint8_t *hash, size_t hash_length,
    const uint8_t *context, size_t context_length,
    const uint8_t *signature, size_t signature_length)
{
    int res = 1;
    uint8_t key_buf[2 * PSA_BITS_TO_BYTES(PSA_VENDOR_ECC_MAX_CURVE_BITS)];
    psa_key_type_t type = psa_get_key_type(attributes);

    switch (type) {
#if defined(PSA_NEED_OBERON_ED25519PH) || defined(PSA_NEED_OBERON_ED448PH)
    case PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_TWISTED_EDWARDS):
    case PSA_KEY_TYPE_ECC_PUBLIC_KEY(PSA_ECC_FAMILY_TWISTED_EDWARDS):
        if (context_length != 0) return PSA_ERROR_NOT_SUPPORTED;
        switch (psa_get_key_bits(attributes)) {
#ifdef PSA_NEED_OBERON_ED25519PH
        case 255:
            if (key_length != ocrypto_ed25519ph_PUBLIC_KEY_BYTES) return PSA_ERROR_INVALID_ARGUMENT;
            if (hash_length != ocrypto_ed25519ph_HASH_BYTES) return PSA_ERROR_INVALID_ARGUMENT;
            if (signature_length != ocrypto_ed25519ph_BYTES) return PSA_ERROR_INVALID_SIGNATURE;
            if (type == PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_TWISTED_EDWARDS)) {
                ocrypto_ed25519ph_public_key(key_buf, key);
                key = key_buf;
            }
            res = ocrypto_ed25519ph_verify(signature, hash, key);
            break;
#endif /* PSA_NEED_OBERON_ED25519PH */
#ifdef PSA_NEED_OBERON_ED448PH
        case 448:
            if (key_length != ocrypto_ed448ph_PUBLIC_KEY_BYTES) return PSA_ERROR_INVALID_ARGUMENT;
            if (hash_length != ocrypto_ed448ph_HASH_BYTES) return PSA_ERROR_INVALID_ARGUMENT;
            if (signature_length != ocrypto_ed448ph_BYTES) return PSA_ERROR_INVALID_SIGNATURE;
            if (type == PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_TWISTED_EDWARDS)) {
                ocrypto_ed448ph_public_key(key_buf, key);
                key = key_buf;
            }
            res = ocrypto_ed448ph_verify(signature, hash, key);
            break;
#endif /* PSA_NEED_OBERON_ED448PH */
        default:
            return PSA_ERROR_NOT_SUPPORTED;
        }
        if (res) return PSA_ERROR_INVALID_SIGNATURE;
        return PSA_SUCCESS;
#endif /* PSA_NEED_OBERON_ED25519PH || PSA_NEED_OBERON_ED448PH */

    default:
        (void)key;
        (void)key_length;
        (void)alg;
        (void)hash;
        (void)hash_length;
        (void)context;
        (void)context_length;
        (void)signature;
        (void)signature_length;
        (void)res;
        (void)key_buf;
        return PSA_ERROR_NOT_SUPPORTED;
    }
}

psa_status_t oberon_eddsa_verify_message_with_context(
    const psa_key_attributes_t *attributes,
    const uint8_t *key, size_t key_length,
    psa_algorithm_t alg,
    const uint8_t *input, size_t input_length,
    const uint8_t *context, size_t context_length,
    const uint8_t *signature, size_t signature_length)
{
    int res = 1;
#if defined(PSA_NEED_OBERON_PURE_EDDSA_TWISTED_EDWARDS_448)
    uint8_t pub_key[57];
#elif defined(PSA_NEED_OBERON_PURE_EDDSA_TWISTED_EDWARDS_255)
    uint8_t pub_key[32];
#endif
    psa_key_type_t type = psa_get_key_type(attributes);

    switch (type) {
#if defined(PSA_NEED_OBERON_PURE_EDDSA_TWISTED_EDWARDS_255) || defined(PSA_NEED_OBERON_PURE_EDDSA_TWISTED_EDWARDS_448)
    case PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_TWISTED_EDWARDS):
    case PSA_KEY_TYPE_ECC_PUBLIC_KEY(PSA_ECC_FAMILY_TWISTED_EDWARDS):
        // EDDSA is only available in verify_message
        // PSA_ALG_ED*PH must be delegated to sign_hash
        if (alg != PSA_ALG_PURE_EDDSA) return PSA_ERROR_NOT_SUPPORTED;
        switch (psa_get_key_bits(attributes)) {
#ifdef PSA_NEED_OBERON_PURE_EDDSA_TWISTED_EDWARDS_255
        case 255:
            if (alg == PSA_ALG_ED25519PH) return PSA_ERROR_NOT_SUPPORTED;
            if (key_length != ocrypto_ed25519_PUBLIC_KEY_BYTES) return PSA_ERROR_INVALID_ARGUMENT;
            if (signature_length != ocrypto_ed25519_BYTES) return PSA_ERROR_INVALID_SIGNATURE;
            if (type == PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_TWISTED_EDWARDS)) {
                ocrypto_ed25519_public_key(pub_key, key);
                key = pub_key;
            }
            res = ocrypto_ed25519_verify(signature, input, input_length, key);
            break;
#endif /* PSA_NEED_OBERON_PURE_EDDSA_TWISTED_EDWARDS_255 */
#ifdef PSA_NEED_OBERON_PURE_EDDSA_TWISTED_EDWARDS_448
        case 448:
            if (alg == PSA_ALG_ED448PH) return PSA_ERROR_NOT_SUPPORTED;
            if (key_length != ocrypto_ed448_PUBLIC_KEY_BYTES) return PSA_ERROR_INVALID_ARGUMENT;
            if (signature_length != ocrypto_ed448_BYTES) return PSA_ERROR_INVALID_SIGNATURE;
            if (type == PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_TWISTED_EDWARDS)) {
                ocrypto_ed448_public_key(pub_key, key);
                key = pub_key;
            }
            res = ocrypto_ed448_verify(signature, input, input_length, key);
            break;
#endif /* PSA_NEED_OBERON_PURE_EDDSA_TWISTED_EDWARDS_448 */
        default:
            return PSA_ERROR_NOT_SUPPORTED;
        }
        if (res) return PSA_ERROR_INVALID_SIGNATURE;
        return PSA_SUCCESS;
#endif /* PSA_NEED_OBERON_PURE_EDDSA_TWISTED_EDWARDS_255 || PSA_NEED_OBERON_PURE_EDDSA_TWISTED_EDWARDS_448 */
    default:
        (void)key;
        (void)key_length;
        (void)alg;
        (void)input;
        (void)input_length;
        (void)context;
        (void)context_length;
        (void)signature;
        (void)signature_length;
        (void)res;
        return PSA_ERROR_NOT_SUPPORTED;
    }
}
