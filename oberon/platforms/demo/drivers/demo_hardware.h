/*
 * Copyright (c) 2016 - 2024 Nordic Semiconductor ASA
 * Copyright (c) since 2020 Oberon microsystems AG
 *
 * SPDX-License-Identifier: LicenseRef-Nordic-5-Clause
 */

//
// This file is based on the Arm PSA Crypto Driver API.

#ifndef DEMO_HARDWARE_H
#define DEMO_HARDWARE_H

#include <psa/crypto_driver_common.h>


#ifdef __cplusplus
extern "C" {
#endif


typedef struct {
    uint32_t h[8], v[8], w[80];
    uint8_t  buffer[64];
    uint32_t length;
    size_t   in_length;
    psa_algorithm_t alg;
} demo_hardware_hash_operation_t;

typedef struct {
    uint8_t  xkey[176];
    uint8_t  counter[16];
    uint8_t  cipher[16];
    uint32_t position;
    psa_algorithm_t alg;
} demo_hardware_cipher_operation_t;


psa_status_t demo_hardware_hash_setup(
    demo_hardware_hash_operation_t *operation,
    psa_algorithm_t alg);

psa_status_t demo_hardware_hash_clone(
    const demo_hardware_hash_operation_t *source_operation,
    demo_hardware_hash_operation_t *target_operation);

psa_status_t demo_hardware_hash_update(
    demo_hardware_hash_operation_t *operation,
    const uint8_t *input, size_t input_length);

psa_status_t demo_hardware_hash_finish(
    demo_hardware_hash_operation_t *operation,
    uint8_t *hash, size_t hash_size, size_t *hash_length);

psa_status_t demo_hardware_hash_abort(
    demo_hardware_hash_operation_t *operation);


psa_status_t demo_hardware_hash_compute(
    psa_algorithm_t alg,
    const uint8_t *input, size_t input_length,
    uint8_t *hash, size_t hash_size, size_t *hash_length);


psa_status_t demo_hardware_cipher_encrypt_setup(
    demo_hardware_cipher_operation_t *operation,
    const psa_key_attributes_t *attributes,
    const uint8_t *key, size_t key_length,
    psa_algorithm_t alg);

psa_status_t demo_hardware_cipher_decrypt_setup(
    demo_hardware_cipher_operation_t *operation,
    const psa_key_attributes_t *attributes,
    const uint8_t *key, size_t key_length,
    psa_algorithm_t alg);

psa_status_t demo_hardware_cipher_set_iv(
    demo_hardware_cipher_operation_t *operation,
    const uint8_t *iv, size_t iv_length);

psa_status_t demo_hardware_cipher_update(
    demo_hardware_cipher_operation_t *operation,
    const uint8_t *input, size_t input_length,
    uint8_t *output, size_t output_size, size_t *output_length);

psa_status_t demo_hardware_cipher_finish(
    demo_hardware_cipher_operation_t *operation,
    uint8_t *output, size_t output_size, size_t *output_length);

psa_status_t demo_hardware_cipher_abort(
    demo_hardware_cipher_operation_t *operation);


psa_status_t demo_hardware_cipher_encrypt(
    const psa_key_attributes_t *attributes,
    const uint8_t *key, size_t key_length,
    psa_algorithm_t alg,
    const uint8_t *iv, size_t iv_length,
    const uint8_t *input, size_t input_length,
    uint8_t *output, size_t output_size, size_t *output_length);

psa_status_t demo_hardware_cipher_decrypt(
    const psa_key_attributes_t *attributes,
    const uint8_t *key, size_t key_length,
    psa_algorithm_t alg,
    const uint8_t *input, size_t input_length,
    uint8_t *output, size_t output_size, size_t *output_length);


#ifdef __cplusplus
}
#endif

#endif
