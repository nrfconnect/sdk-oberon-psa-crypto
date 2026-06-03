/*
 * Copyright (c) 2016 - 2026 Nordic Semiconductor ASA
 * Copyright (c) since 2020 Oberon microsystems AG
 *
 * SPDX-License-Identifier: LicenseRef-Nordic-5-Clause
 */

//
// This file is based on the Arm PSA Crypto Driver Interface.

#ifndef DEMO_OPAQUE_H
#define DEMO_OPAQUE_H

#include <psa/crypto_driver_common.h>


#define OBERON_DEMO_DRIVER_LOCATION 0x7fffff


#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    psa_cipher_operation_t *p_op;
} oberon_opaque_cipher_operation_t;

typedef struct {
    psa_key_derivation_operation_t *p_op;
    psa_algorithm_t alg;
    size_t capacity;
} oberon_opaque_key_derivation_operation_t;


psa_status_t demo_opaque_init(void);

void demo_opaque_free(void);


size_t demo_opaque_size_function(
    const psa_key_type_t key_type,
    const size_t key_bits);
    
psa_status_t demo_opaque_export_key(
    const psa_key_attributes_t *attributes,
    const uint8_t *key, size_t key_length,
    uint8_t *data, size_t data_size, size_t *data_length);

psa_status_t demo_opaque_export_public_key(
    const psa_key_attributes_t *attributes,
    const uint8_t *key, size_t key_length,
    uint8_t *data, size_t data_size, size_t *data_length);

psa_status_t demo_opaque_import_key(
    const psa_key_attributes_t *attributes,
    const uint8_t *data, size_t data_length,
    uint8_t *key, size_t key_size, size_t *key_length,
    size_t *bits);

psa_status_t demo_opaque_generate_key(
    const psa_key_attributes_t *attributes,
    uint8_t *key, size_t key_size, size_t *key_length);

psa_status_t demo_opaque_copy_key(
    psa_key_attributes_t *attributes,
    const uint8_t *source_key, size_t source_key_length,
    uint8_t *key, size_t key_size, size_t *key_length);

psa_status_t demo_opaque_derive_key(
    const psa_key_attributes_t *attributes,
    const uint8_t *input, size_t input_length,
    uint8_t *key, size_t key_size, size_t *key_length);

psa_status_t demo_opaque_destroy_key(
    const psa_key_attributes_t *attributes,
    const uint8_t *key, size_t key_length);


psa_status_t demo_opaque_signature_sign_message_with_context(
    const psa_key_attributes_t *attributes,
    const uint8_t *key, size_t key_length,
    psa_algorithm_t alg,
    const uint8_t *input, size_t input_length,
    const uint8_t *context, size_t context_length,
    uint8_t *signature, size_t signature_size, size_t *signature_length);
    
psa_status_t demo_opaque_signature_verify_message_with_context(
    const psa_key_attributes_t *attributes,
    const uint8_t *key, size_t key_length,
    psa_algorithm_t alg,
    const uint8_t *input, size_t input_length,
    const uint8_t *context, size_t context_length,
    const uint8_t *signature, size_t signature_length);
    
psa_status_t demo_opaque_signature_sign_hash_with_context(
    const psa_key_attributes_t *attributes,
    const uint8_t *key, size_t key_length,
    psa_algorithm_t alg,
    const uint8_t *hash, size_t hash_length,
    const uint8_t *context, size_t context_length,
    uint8_t *signature, size_t signature_size, size_t *signature_length);

psa_status_t demo_opaque_signature_verify_hash_with_context(
    const psa_key_attributes_t *attributes,
    const uint8_t *key, size_t key_length,
    psa_algorithm_t alg,
    const uint8_t *hash, size_t hash_length,
    const uint8_t *context, size_t context_length,
    const uint8_t *signature, size_t signature_length);


psa_status_t demo_opaque_cipher_encrypt_setup(
    oberon_opaque_cipher_operation_t *operation,
    const psa_key_attributes_t *attributes,
    const uint8_t *key, size_t key_length,
    psa_algorithm_t alg);

psa_status_t demo_opaque_cipher_decrypt_setup(
    oberon_opaque_cipher_operation_t *operation,
    const psa_key_attributes_t *attributes,
    const uint8_t *key, size_t key_length,
    psa_algorithm_t alg);

psa_status_t demo_opaque_cipher_set_iv(
    oberon_opaque_cipher_operation_t *operation,
    const uint8_t *iv, size_t iv_length);

psa_status_t demo_opaque_cipher_update(
    oberon_opaque_cipher_operation_t *operation,
    const uint8_t *input, size_t input_length,
    uint8_t *output, size_t output_size, size_t *output_length);

psa_status_t demo_opaque_cipher_finish(
    oberon_opaque_cipher_operation_t *operation,
    uint8_t *output, size_t output_size, size_t *output_length);

psa_status_t demo_opaque_cipher_abort(
    oberon_opaque_cipher_operation_t *operation);

psa_status_t demo_opaque_cipher_encrypt(
    const psa_key_attributes_t *attributes,
    const uint8_t *key, size_t key_length,
    psa_algorithm_t alg,
    const uint8_t *iv, size_t iv_length,
    const uint8_t *input, size_t input_length,
    uint8_t *output, size_t output_size, size_t *output_length);

psa_status_t demo_opaque_cipher_decrypt(
    const psa_key_attributes_t *attributes,
    const uint8_t *key, size_t key_length,
    psa_algorithm_t alg,
    const uint8_t *input, size_t input_length,
    uint8_t *output, size_t output_size, size_t *output_length);


psa_status_t demo_opaque_key_agreement(
    const psa_key_attributes_t *attributes,
    const uint8_t *key, size_t key_length,
    psa_algorithm_t alg,
    const uint8_t *peer_key, size_t peer_key_length,
    uint8_t *output, size_t output_size, size_t *output_length);

psa_status_t demo_opaque_key_agreement_to_key(
    const psa_key_attributes_t *attributes,
    const uint8_t *key, size_t key_length,
    psa_algorithm_t alg,
    const uint8_t *peer_key, size_t peer_key_length,
    const psa_key_attributes_t *output_attributes,
    uint8_t *output, size_t output_size, size_t *output_length);


psa_status_t demo_opaque_key_derivation_setup(
    oberon_opaque_key_derivation_operation_t *operation,
    const psa_key_attributes_t *key_attributes,
    psa_algorithm_t alg);

psa_status_t demo_opaque_key_derivation_set_capacity(
    oberon_opaque_key_derivation_operation_t *operation,
    size_t capacity);

psa_status_t demo_opaque_key_derivation_input_bytes(
    oberon_opaque_key_derivation_operation_t *operation,
    psa_key_derivation_step_t step,
    const uint8_t *data, size_t data_length);

psa_status_t demo_opaque_key_derivation_input_key(
    oberon_opaque_key_derivation_operation_t *operation,
    psa_key_derivation_step_t step,
    const psa_key_attributes_t *key_attributes,
    const uint8_t *key, size_t key_length);

psa_status_t demo_opaque_key_derivation_input_integer(
    oberon_opaque_key_derivation_operation_t *operation,
    psa_key_derivation_step_t step,
    uint64_t value);

psa_status_t demo_opaque_key_derivation_output_bytes(
    oberon_opaque_key_derivation_operation_t *operation,
    uint8_t *output, size_t output_length);

psa_status_t demo_opaque_key_derivation_output_key(
    oberon_opaque_key_derivation_operation_t *operation,
    const psa_key_attributes_t *key_attributes,
    uint8_t *key, size_t key_size, size_t *key_length);

psa_status_t demo_opaque_key_derivation_verify_bytes(
    oberon_opaque_key_derivation_operation_t *operation,
    const uint8_t *expected, size_t length);

psa_status_t demo_opaque_key_derivation_verify_key(
    oberon_opaque_key_derivation_operation_t *operation,
    const psa_key_attributes_t *key_attributes,
    const uint8_t *key, size_t key_size);

psa_status_t demo_opaque_key_derivation_abort(
    oberon_opaque_key_derivation_operation_t *operation);


#ifdef __cplusplus
}
#endif

#endif
