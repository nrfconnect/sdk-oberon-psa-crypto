/*
 * Copyright (c) 2016 - 2024 Nordic Semiconductor ASA
 * Copyright (c) since 2020 Oberon microsystems AG
 *
 * SPDX-License-Identifier: LicenseRef-Nordic-5-Clause
 */

//
// This file implements functions from the Arm PSA Crypto Driver API.

#include <string.h>

#include "mbedtls/platform.h"

#include "psa/crypto.h"
#include "demo_opaque.h"
#include "psa_crypto_driver_wrappers.h"


psa_status_t demo_opaque_init()
{
    return PSA_SUCCESS;
}

void demo_opaque_free()
{
    return;
}


size_t demo_opaque_size_function(
    const psa_key_type_t key_type,
    const size_t key_bits)
{
    return PSA_EXPORT_KEY_OUTPUT_SIZE(key_type, key_bits);
}

psa_status_t demo_opaque_copy_key(
    psa_key_attributes_t *attributes,
    const uint8_t *source_key, size_t source_key_length,
    uint8_t *key_buffer, size_t key_buffer_size, size_t *key_buffer_length)
{
    (void)attributes;
    if (source_key_length > key_buffer_size) return PSA_ERROR_BUFFER_TOO_SMALL;
    memcpy(key_buffer, source_key, source_key_length);
    *key_buffer_length = source_key_length;
    return PSA_SUCCESS;
}

psa_status_t demo_opaque_export_key(
    const psa_key_attributes_t *attributes,
    const uint8_t *key, size_t key_length,
    uint8_t *data, size_t data_size, size_t *data_length)
{
    (void)attributes;
    if (key_length > data_size) return PSA_ERROR_BUFFER_TOO_SMALL;
    memcpy(data, key, key_length);
    *data_length = key_length;
    return PSA_SUCCESS;
}

psa_status_t demo_opaque_export_public_key(
    const psa_key_attributes_t *attributes,
    const uint8_t *key, size_t key_length,
    uint8_t *data, size_t data_size, size_t *data_length)
{
    psa_key_attributes_t local_attr = *attributes;
    psa_set_key_lifetime(&local_attr, PSA_KEY_LIFETIME_VOLATILE);
    return psa_driver_wrapper_export_public_key(
        &local_attr, key, key_length, data, data_size, data_length);
}

psa_status_t demo_opaque_import_key(
    const psa_key_attributes_t *attributes,
    const uint8_t *data, size_t data_length,
    uint8_t *key, size_t key_size, size_t *key_length,
    size_t *key_bits)
{
    psa_key_attributes_t local_attr = *attributes;
    psa_set_key_lifetime(&local_attr, PSA_KEY_LIFETIME_VOLATILE);
    return psa_driver_wrapper_import_key(
        &local_attr, data, data_length, key, key_size, key_length, key_bits);
}

psa_status_t demo_opaque_generate_key(
    const psa_key_attributes_t *attributes,
    uint8_t *key, size_t key_size, size_t *key_length)
{
    psa_key_attributes_t local_attr = *attributes;
    psa_set_key_lifetime(&local_attr, PSA_KEY_LIFETIME_VOLATILE);
    return psa_driver_wrapper_generate_key(
        &local_attr, key, key_size, key_length);
}


psa_status_t demo_opaque_signature_sign_message(
    const psa_key_attributes_t *attributes,
    const uint8_t *key, size_t key_length,
    psa_algorithm_t alg,
    const uint8_t *input, size_t input_length,
    uint8_t *signature, size_t signature_size, size_t *signature_length)
{
    psa_key_attributes_t local_attr = *attributes;
    psa_set_key_lifetime(&local_attr, PSA_KEY_LIFETIME_VOLATILE);
    return psa_driver_wrapper_sign_message(
        &local_attr, key, key_length,
        alg, input, input_length,
        signature, signature_size, signature_length);
}

psa_status_t demo_opaque_signature_verify_message(
    const psa_key_attributes_t *attributes,
    const uint8_t *key, size_t key_length,
    psa_algorithm_t alg,
    const uint8_t *input, size_t input_length,
    const uint8_t *signature, size_t signature_length)
{
    psa_key_attributes_t local_attr = *attributes;
    psa_set_key_lifetime(&local_attr, PSA_KEY_LIFETIME_VOLATILE);
    return psa_driver_wrapper_verify_message(
        &local_attr, key, key_length,
        alg, input, input_length,
        signature, signature_length);
}

psa_status_t demo_opaque_signature_sign_hash(
    const psa_key_attributes_t *attributes,
    const uint8_t *key, size_t key_length,
    psa_algorithm_t alg,
    const uint8_t *hash, size_t hash_length,
    uint8_t *signature, size_t signature_size, size_t *signature_length)
{
    psa_key_attributes_t local_attr = *attributes;
    psa_set_key_lifetime(&local_attr, PSA_KEY_LIFETIME_VOLATILE);
    return psa_driver_wrapper_sign_hash(
        &local_attr, key, key_length,
        alg, hash, hash_length,
        signature, signature_size, signature_length);
}

psa_status_t demo_opaque_signature_verify_hash(
    const psa_key_attributes_t *attributes,
    const uint8_t *key, size_t key_length,
    psa_algorithm_t alg,
    const uint8_t *hash, size_t hash_length,
    const uint8_t *signature, size_t signature_length)
{
    psa_key_attributes_t local_attr = *attributes;
    psa_set_key_lifetime(&local_attr, PSA_KEY_LIFETIME_VOLATILE);
    return psa_driver_wrapper_verify_hash(
        &local_attr, key, key_length,
        alg, hash, hash_length,
        signature, signature_length);
}


psa_status_t demo_opaque_cipher_encrypt_setup(
    oberon_opaque_cipher_operation_t *operation,
    const psa_key_attributes_t *attributes,
    const uint8_t *key, size_t key_length,
    psa_algorithm_t alg)
{
    psa_key_attributes_t local_attr = *attributes;
    psa_set_key_lifetime(&local_attr, PSA_KEY_LIFETIME_VOLATILE);
    operation->p_op = mbedtls_calloc(1, sizeof *operation->p_op);
    return psa_driver_wrapper_cipher_encrypt_setup(
        operation->p_op, &local_attr, key, key_length, alg);
}

psa_status_t demo_opaque_cipher_decrypt_setup(
    oberon_opaque_cipher_operation_t *operation,
    const psa_key_attributes_t *attributes,
    const uint8_t *key, size_t key_length,
    psa_algorithm_t alg)
{
    psa_key_attributes_t local_attr = *attributes;
    psa_set_key_lifetime(&local_attr, PSA_KEY_LIFETIME_VOLATILE);
    operation->p_op = mbedtls_calloc(1, sizeof *operation->p_op);
    return psa_driver_wrapper_cipher_decrypt_setup(
        operation->p_op, &local_attr, key, key_length, alg);
}

psa_status_t demo_opaque_cipher_set_iv(
    oberon_opaque_cipher_operation_t *operation,
    const uint8_t *iv, size_t iv_length)
{
    return psa_driver_wrapper_cipher_set_iv(
        operation->p_op, iv, iv_length);
}

psa_status_t demo_opaque_cipher_update(
    oberon_opaque_cipher_operation_t *operation,
    const uint8_t *input, size_t input_length,
    uint8_t *output, size_t output_size, size_t *output_length)
{
    return psa_driver_wrapper_cipher_update(
        operation->p_op, input, input_length,
        output, output_size, output_length);
}

psa_status_t demo_opaque_cipher_finish(
    oberon_opaque_cipher_operation_t *operation,
    uint8_t *output, size_t output_size, size_t *output_length)
{
    return psa_driver_wrapper_cipher_finish(
        operation->p_op, output, output_size, output_length);
}

psa_status_t demo_opaque_cipher_abort(
    oberon_opaque_cipher_operation_t *operation)
{
    psa_status_t status = psa_driver_wrapper_cipher_abort(operation->p_op);
    mbedtls_free(operation->p_op);
    operation->p_op = NULL;
    return status;
}

psa_status_t demo_opaque_cipher_encrypt(
    const psa_key_attributes_t *attributes,
    const uint8_t *key, size_t key_length,
    psa_algorithm_t alg,
    const uint8_t *iv, size_t iv_length,
    const uint8_t *input, size_t input_length,
    uint8_t *output, size_t output_size, size_t *output_length)
{
    psa_key_attributes_t local_attr = *attributes;
    psa_set_key_lifetime(&local_attr, PSA_KEY_LIFETIME_VOLATILE);
    return psa_driver_wrapper_cipher_encrypt(
        &local_attr, key, key_length,
        alg, iv, iv_length, input, input_length,
        output, output_size, output_length);
}

psa_status_t demo_opaque_cipher_decrypt(
    const psa_key_attributes_t *attributes,
    const uint8_t *key, size_t key_length,
    psa_algorithm_t alg,
    const uint8_t *input, size_t input_length,
    uint8_t *output, size_t output_size, size_t *output_length)
{
    psa_key_attributes_t local_attr = *attributes;
    psa_set_key_lifetime(&local_attr, PSA_KEY_LIFETIME_VOLATILE);
    return psa_driver_wrapper_cipher_decrypt(
        &local_attr, key, key_length,
        alg, input, input_length,
        output, output_size, output_length);
}
