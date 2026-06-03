/*
 * Copyright (c) 2016 - 2026 Nordic Semiconductor ASA
 * Copyright (c) since 2020 Oberon microsystems AG
 *
 * SPDX-License-Identifier: LicenseRef-Nordic-5-Clause
 */

//
// This file is based on the Arm PSA Crypto Driver Interface.

#ifndef OBERON_ASYMMETRIC_SIGNATURE_H
#define OBERON_ASYMMETRIC_SIGNATURE_H

#include <psa/crypto_driver_common.h>


#ifdef __cplusplus
extern "C" {
#endif


/**
 * The major version of this implementation of the PSA Crypto Driver Interface
 */
#define PSA_CRYPTO_DRIVER_INTERFACE_ASYMMETRIC_SIGNATURE_VERSION_MAJOR 0

/**
 * The minor version of this implementation of the PSA Crypto Driver Interface
 */
#define PSA_CRYPTO_DRIVER_INTERFACE_ASYMMETRIC_SIGNATURE_VERSION_MINOR 0


psa_status_t oberon_sign_message_with_context(
    const psa_key_attributes_t *attributes,
    const uint8_t *key, size_t key_length,
    psa_algorithm_t alg,
    const uint8_t *input, size_t input_length,
    const uint8_t *context, size_t context_length,
    uint8_t *signature, size_t signature_size, size_t *signature_length);

psa_status_t oberon_sign_hash_with_context(
    const psa_key_attributes_t *attributes,
    const uint8_t *key, size_t key_length,
    psa_algorithm_t alg,
    const uint8_t *hash, size_t hash_length,
    const uint8_t *context, size_t context_length,
    uint8_t *signature, size_t signature_size, size_t *signature_length);

psa_status_t oberon_verify_message_with_context(
    const psa_key_attributes_t *attributes,
    const uint8_t *key, size_t key_length,
    psa_algorithm_t alg,
    const uint8_t *input, size_t input_length,
    const uint8_t *context, size_t context_length,
    const uint8_t *signature, size_t signature_length);

psa_status_t oberon_verify_hash_with_context(
    const psa_key_attributes_t *attributes,
    const uint8_t *key, size_t key_length,
    psa_algorithm_t alg,
    const uint8_t *hash, size_t hash_length,
    const uint8_t *context, size_t context_length,
    const uint8_t *signature, size_t signature_length);


#ifdef __cplusplus
}
#endif

#endif
