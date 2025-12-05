/*
 * Copyright (c) 2016 - 2025 Nordic Semiconductor ASA
 * Copyright (c) since 2020 Oberon microsystems AG
 *
 * SPDX-License-Identifier: LicenseRef-Nordic-5-Clause
 */

//
// This file implements functions from the Arm PSA Crypto Driver API.

#include "psa/crypto.h"
#include "oberon_asymmetric_signature.h"

#include "oberon_ecdsa.h"
#include "oberon_eddsa.h"
#include "oberon_lms.h"
#include "oberon_ml_dsa.h"
#include "oberon_xmss.h"
#include "oberon_rsa.h"


psa_status_t oberon_sign_hash_with_context(
    const psa_key_attributes_t *attributes,
    const uint8_t *key, size_t key_length,
    psa_algorithm_t alg,
    const uint8_t *hash, size_t hash_length,
    const uint8_t *context, size_t context_length,
    uint8_t *signature, size_t signature_size, size_t *signature_length)
{
    psa_key_type_t type = psa_get_key_type(attributes);

#ifdef PSA_NEED_OBERON_EDDSA_SIGN
    if (type == PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_TWISTED_EDWARDS)) {
        return oberon_eddsa_sign_hash_with_context(
            attributes, key, key_length,
            alg,
            hash, hash_length,
            context, context_length,
            signature, signature_size, signature_length);
    } else
#endif /* PSA_NEED_OBERON_EDDSA_SIGN */

#ifdef PSA_NEED_OBERON_ECDSA_SIGN
    if (PSA_KEY_TYPE_IS_ECC(type)) {
        return oberon_ecdsa_sign_hash(
            attributes, key, key_length,
            alg,
            hash, hash_length,
            signature, signature_size, signature_length);
    } else
#endif /* PSA_NEED_OBERON_ECDSA_SIGN */

#ifdef PSA_NEED_OBERON_RSA_ANY_SIGN
    if (PSA_KEY_TYPE_IS_RSA(type)) {
        return oberon_rsa_sign_hash(
            attributes, key, key_length,
            alg,
            hash, hash_length,
            signature, signature_size, signature_length);
    } else
#endif /* PSA_NEED_OBERON_RSA_ANY_SIGN */

#ifdef PSA_NEED_OBERON_ML_DSA_SIGN
#ifdef PSA_NEED_OBERON_HASH_ML_DSA
    if (PSA_KEY_TYPE_IS_ML_DSA(type)) {
        return oberon_ml_dsa_sign_hash_with_context(
            attributes, key, key_length,
            alg,
            hash, hash_length,
            context, context_length,
            signature, signature_size, signature_length);
    } else
#endif /* PSA_NEED_OBERON_HASH_ML_DSA */
#endif /* PSA_NEED_OBERON_ML_DSA_SIGN */

    {
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
        (void)type;
        return PSA_ERROR_NOT_SUPPORTED;
    }
}

psa_status_t oberon_sign_message_with_context(
    const psa_key_attributes_t *attributes,
    const uint8_t *key, size_t key_length,
    psa_algorithm_t alg,
    const uint8_t *input, size_t input_length,
    const uint8_t *context, size_t context_length,
    uint8_t *signature, size_t signature_size, size_t *signature_length)
{
    psa_key_type_t type = psa_get_key_type(attributes);

#ifdef PSA_NEED_OBERON_EDDSA_SIGN
    if (type == PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_TWISTED_EDWARDS)) {
        return oberon_eddsa_sign_message_with_context(
            attributes, key, key_length,
            alg,
            input, input_length,
            context, context_length,
            signature, signature_size, signature_length);
    } else
#endif /* PSA_NEED_OBERON_EDDSA_SIGN */

#ifdef PSA_NEED_OBERON_ML_DSA_SIGN
#ifdef PSA_NEED_OBERON_MESSAGE_ML_DSA
    if (PSA_KEY_TYPE_IS_ML_DSA(type)) {
        return oberon_ml_dsa_sign_message_with_context(
            attributes, key, key_length,
            alg,
            input, input_length,
            context, context_length,
            signature, signature_size, signature_length);
    } else
#endif /* PSA_NEED_OBERON_MESSAGE_ML_DSA */
#endif /* PSA_NEED_OBERON_ML_DSA_SIGN */

    {
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
        (void)type;
        return PSA_ERROR_NOT_SUPPORTED;
    }
}

psa_status_t oberon_verify_hash_with_context(
    const psa_key_attributes_t *attributes,
    const uint8_t *key, size_t key_length,
    psa_algorithm_t alg,
    const uint8_t *hash, size_t hash_length,
    const uint8_t *context, size_t context_length,
    const uint8_t *signature, size_t signature_length)
{
    psa_key_type_t type = psa_get_key_type(attributes);

#ifdef PSA_NEED_OBERON_EDDSA_VERIFY
        if (PSA_KEY_TYPE_PUBLIC_KEY_OF_KEY_PAIR(type) ==
            PSA_KEY_TYPE_ECC_PUBLIC_KEY(PSA_ECC_FAMILY_TWISTED_EDWARDS)) {
            return oberon_eddsa_verify_hash_with_context(
            attributes, key, key_length,
            alg,
            hash, hash_length,
            context, context_length,
            signature, signature_length);
    } else
#endif /* PSA_NEED_OBERON_EDDSA_VERIFY */

#ifdef PSA_NEED_OBERON_ECDSA_VERIFY
    if (PSA_KEY_TYPE_IS_ECC(type)) {
        return oberon_ecdsa_verify_hash(
            attributes, key, key_length,
            alg,
            hash, hash_length,
            signature, signature_length);
    } else
#endif /* PSA_NEED_OBERON_ECDSA_VERIFY */

#ifdef PSA_NEED_OBERON_RSA_ANY_VERIFY
    if (PSA_KEY_TYPE_IS_RSA(type)) {
        return oberon_rsa_verify_hash(
            attributes, key, key_length,
            alg,
            hash, hash_length,
            signature, signature_length);
    } else
#endif /* PSA_NEED_OBERON_RSA_ANY_VERIFY */

#ifdef PSA_NEED_OBERON_ML_DSA_VERIFY
#ifdef PSA_NEED_OBERON_HASH_ML_DSA
    if (PSA_KEY_TYPE_IS_ML_DSA(type)) {
        return oberon_ml_dsa_verify_hash_with_context(
            attributes, key, key_length,
            alg,
            hash, hash_length,
            context, context_length,
            signature, signature_length);
    } else
#endif /* PSA_NEED_OBERON_HASH_ML_DSA */
#endif /* PSA_NEED_OBERON_ML_DSA_VERIFY */

    {
        (void)key;
        (void)key_length;
        (void)alg;
        (void)hash;
        (void)hash_length;
        (void)context;
        (void)context_length;
        (void)signature;
        (void)signature_length;
        (void)type;
        return PSA_ERROR_NOT_SUPPORTED;
    }
}

psa_status_t oberon_verify_message_with_context(
    const psa_key_attributes_t *attributes,
    const uint8_t *key, size_t key_length,
    psa_algorithm_t alg,
    const uint8_t *input, size_t input_length,
    const uint8_t *context, size_t context_length,
    const uint8_t *signature, size_t signature_length)
{
    psa_key_type_t type = psa_get_key_type(attributes);

#ifdef PSA_NEED_OBERON_EDDSA_VERIFY
    if (PSA_KEY_TYPE_PUBLIC_KEY_OF_KEY_PAIR(type) ==
        PSA_KEY_TYPE_ECC_PUBLIC_KEY(PSA_ECC_FAMILY_TWISTED_EDWARDS)) {
        return oberon_eddsa_verify_message_with_context(
            attributes, key, key_length,
            alg,
            input, input_length,
            context, context_length,
            signature, signature_length);
    } else
#endif /* PSA_NEED_OBERON_EDDSA_VERIFY */

#ifdef PSA_NEED_OBERON_ML_DSA_VERIFY
#ifdef PSA_NEED_OBERON_MESSAGE_ML_DSA
        if (PSA_KEY_TYPE_IS_ML_DSA(type)) {
        return oberon_ml_dsa_verify_message_with_context(
            attributes, key, key_length,
            alg,
            input, input_length,
            context, context_length,
            signature, signature_length);
    } else
#endif /* PSA_NEED_OBERON_MESSAGE_ML_DSA */
#endif /* PSA_NEED_OBERON_ML_DSA_VERIFY */

#ifdef PSA_NEED_OBERON_LMS_VERIFY
    if (type == PSA_KEY_TYPE_LMS_PUBLIC_KEY) {
        return oberon_lms_verify_message(
            attributes, key, key_length,
            alg,
            input, input_length,
            signature, signature_length);
    } else
#endif /* PSA_NEED_OBERON_LMS_VERIFY */

#ifdef PSA_NEED_OBERON_HSS_VERIFY
    if (type == PSA_KEY_TYPE_HSS_PUBLIC_KEY) {
        return oberon_hss_verify_message(
            attributes, key, key_length,
            alg,
            input, input_length,
            signature, signature_length);
    } else
#endif /* PSA_NEED_OBERON_HSS_VERIFY */

#ifdef PSA_NEED_OBERON_XMSS_VERIFY
    if (type == PSA_KEY_TYPE_XMSS_PUBLIC_KEY) {
        return oberon_xmss_verify_message(
            attributes, key, key_length,
            alg,
            input, input_length,
            signature, signature_length);
    } else
#endif /* PSA_NEED_OBERON_XMSS_VERIFY */

#ifdef PSA_NEED_OBERON_XMSS_MT_VERIFY
    if (type == PSA_KEY_TYPE_XMSS_MT_PUBLIC_KEY) {
        return oberon_xmssmt_verify_message(
            attributes, key, key_length,
            alg,
            input, input_length,
            signature, signature_length);
    } else
#endif /* PSA_NEED_OBERON_XMSS_MT_VERIFY */

    {
        (void)key;
        (void)key_length;
        (void)alg;
        (void)input;
        (void)input_length;
        (void)context;
        (void)context_length;
        (void)signature;
        (void)signature_length;
        (void)type;
        return PSA_ERROR_NOT_SUPPORTED;
    }
}
