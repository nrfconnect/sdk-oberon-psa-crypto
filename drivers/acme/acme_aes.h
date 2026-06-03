//
// Copyright Oberon microsystems AG, Switzerland.
// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
//
// This file is based on the Arm PSA Crypto Driver Interface.

/*
 * Please note: this simple implementation is provided for demonstration only. 
 *
 * Use in production is not recommended.
 */ 


#ifndef ACME_AES_H
#define ACME_AES_H

#include <psa/crypto_driver_common.h>


#ifdef __cplusplus
extern "C" {
#endif


typedef struct {
    uint8_t  xkey[176];
    uint8_t  counter[16];
    uint8_t  cipher[16];
    uint32_t position;
    psa_algorithm_t alg;
} acme_cipher_operation_t;


psa_status_t acme_cipher_encrypt_setup(
    acme_cipher_operation_t *operation,
    const psa_key_attributes_t *attributes,
    const uint8_t *key, size_t key_length,
    psa_algorithm_t alg);

psa_status_t acme_cipher_decrypt_setup(
    acme_cipher_operation_t *operation,
    const psa_key_attributes_t *attributes,
    const uint8_t *key, size_t key_length,
    psa_algorithm_t alg);

psa_status_t acme_cipher_set_iv(
    acme_cipher_operation_t *operation,
    const uint8_t *iv, size_t iv_length);

psa_status_t acme_cipher_update(
    acme_cipher_operation_t *operation,
    const uint8_t *input, size_t input_length,
    uint8_t *output, size_t output_size, size_t *output_length);

psa_status_t acme_cipher_finish(
    acme_cipher_operation_t *operation,
    uint8_t *output, size_t output_size, size_t *output_length);

psa_status_t acme_cipher_abort(
    acme_cipher_operation_t *operation);


psa_status_t acme_cipher_encrypt(
    const psa_key_attributes_t *attributes,
    const uint8_t *key, size_t key_length,
    psa_algorithm_t alg,
    const uint8_t *iv, size_t iv_length,
    const uint8_t *input, size_t input_length,
    uint8_t *output, size_t output_size, size_t *output_length);

psa_status_t acme_cipher_decrypt(
    const psa_key_attributes_t *attributes,
    const uint8_t *key, size_t key_length,
    psa_algorithm_t alg,
    const uint8_t *input, size_t input_length,
    uint8_t *output, size_t output_size, size_t *output_length);


#ifdef __cplusplus
}
#endif

#endif
