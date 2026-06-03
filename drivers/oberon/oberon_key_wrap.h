/*
 * Copyright (c) 2016 - 2026 Nordic Semiconductor ASA
 * Copyright (c) since 2020 Oberon microsystems AG
 *
 * SPDX-License-Identifier: LicenseRef-Nordic-5-Clause
 */

//
// This file is based on the Arm PSA Crypto Driver Interface.

#ifndef OBERON_KEY_WRAP_H
#define OBERON_KEY_WRAP_H

#include <psa/crypto_driver_common.h>


/**
 * The major version of this implementation of the PSA Crypto Driver Interface
 */
#define PSA_CRYPTO_DRIVER_INTERFACE_KEY_WRAP_VERSION_MAJOR 0

/**
 * The minor version of this implementation of the PSA Crypto Driver Interface
 */
#define PSA_CRYPTO_DRIVER_INTERFACE_KEY_WRAP_VERSION_MINOR 0


#ifdef __cplusplus
extern "C" {
#endif

    psa_status_t oberon_wrap_key(
        const psa_key_attributes_t *wrapping_key_attributes,
        const uint8_t *wrapping_key_data, size_t wrapping_key_size,
        psa_algorithm_t alg,
        const psa_key_attributes_t *key_attributes,
        const uint8_t *key_data, size_t key_size,
        uint8_t *data, size_t data_size, size_t *data_length);

    psa_status_t oberon_unwrap_key(
        const psa_key_attributes_t *attributes,
        const psa_key_attributes_t *wrapping_key_attributes,
        const uint8_t *wrapping_key_data, size_t wrapping_key_size,
        psa_algorithm_t alg,
        const uint8_t *data, size_t data_length,
        uint8_t *key, size_t key_size, size_t *key_length, size_t *bits);

#ifdef __cplusplus
}
#endif

#endif
