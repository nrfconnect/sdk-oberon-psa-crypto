/*
 * Copyright (c) 2016 - 2025 Nordic Semiconductor ASA
 * Copyright (c) since 2020 Oberon microsystems AG
 *
 * SPDX-License-Identifier: LicenseRef-Nordic-5-Clause
 */

//
// This file implements functions from the Arm PSA Crypto Driver API.

#include "psa/crypto.h"
#include "oberon_key_encapsulation.h"

#include "oberon_ml_kem.h"


psa_status_t oberon_encapsulate(
    const psa_key_attributes_t *attributes,
    const uint8_t *key, size_t key_length,
    psa_algorithm_t alg,
    const psa_key_attributes_t *output_attributes,
    uint8_t *output_key, size_t output_key_size, size_t *output_key_length,
    uint8_t *ciphertext, size_t ciphertext_size, size_t *ciphertext_length)
{
    psa_key_type_t type = psa_get_key_type(attributes);

#ifdef PSA_NEED_OBERON_ML_KEM
    if (PSA_KEY_TYPE_IS_ML_KEM(type)) {
        return oberon_ml_kem_encapsulate(
            attributes, key, key_length,
            alg, output_attributes,
            output_key, output_key_size, output_key_length,
            ciphertext, ciphertext_size, ciphertext_length);
    } else
#endif /* PSA_NEED_OBERON_ML_KEM */

    {
        (void)key;
        (void)key_length;
        (void)alg;
        (void)output_attributes;
        (void)output_key;
        (void)output_key_size;
        (void)output_key_length;
        (void)ciphertext;
        (void)ciphertext_size;
        (void)ciphertext_length;
        (void)type;
        return PSA_ERROR_NOT_SUPPORTED;
    }
}

psa_status_t oberon_decapsulate(
    const psa_key_attributes_t *attributes,
    const uint8_t *key, size_t key_length,
    psa_algorithm_t alg,
    const uint8_t *ciphertext, size_t ciphertext_length,
    const psa_key_attributes_t *output_attributes,
    uint8_t *output_key, size_t output_key_size, size_t *output_key_length)
{
    psa_key_type_t type = psa_get_key_type(attributes);

#ifdef PSA_NEED_OBERON_ML_KEM
    if (PSA_KEY_TYPE_IS_ML_KEM(type)) {
        return oberon_ml_kem_decapsulate(
            attributes, key, key_length,
            alg,
            ciphertext, ciphertext_length,
            output_attributes,
            output_key, output_key_size, output_key_length);
    } else
#endif /* PSA_NEED_OBERON_ML_KEM */

    {
        (void)key;
        (void)key_length;
        (void)alg;
        (void)ciphertext;
        (void)ciphertext_length;
        (void)output_attributes;
        (void)output_key;
        (void)output_key_size;
        (void)output_key_length;
        (void)type;
        return PSA_ERROR_NOT_SUPPORTED;
    }
}
