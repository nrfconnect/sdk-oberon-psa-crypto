/*
 * Copyright (c) 2016 - 2026 Nordic Semiconductor ASA
 * Copyright (c) since 2020 Oberon microsystems AG
 *
 * SPDX-License-Identifier: LicenseRef-Nordic-5-Clause
 */

//
// This file implements functions from the Arm PSA Crypto Driver Interface.

#include <string.h>

#include "mbedtls/platform.h"

#include "psa/crypto.h"
#include "demo_opaque.h"
#include "psa_crypto_driver_wrappers.h"


/*
 * This demo driver implements a simple opaque driver.
 * It stores all keys in a local key store in static memory.
 * The key context stored in the global key store consists of a key index only.
 * Ideally, all crypto operations should be done locally in the driver.
 * However, crypto functions from transparent drivers are called here to keep it simple.
 * This demo driver is not thread safe.
 */


#define MAX_KEY_IDX  8
#define MAX_KEY_SIZE 1024
#define KEY_IDX_LEN  1

// local key store
static struct key_data {
    uint8_t data[MAX_KEY_SIZE];
    size_t size;
} key_store[MAX_KEY_IDX];


psa_status_t demo_opaque_init()
{
    // initialize local key store
    int i;
    for (i = 0; i < MAX_KEY_IDX; i++) key_store[i].size = 0;
    return PSA_SUCCESS;
}

void demo_opaque_free()
{
    // check for unreleased keys
    int i = 0;
    for (i = 0; i < MAX_KEY_IDX; i++) {
        if (key_store[i].size != 0) {
            printf("UNRELEASED KEY\r\n");
        }
    }
    
    // reset local key store
    memset(key_store, 0, sizeof key_store);
}


size_t demo_opaque_size_function(
    const psa_key_type_t key_type,
    const size_t key_bits)
{
    (void)key_type;
    (void)key_bits;
    return KEY_IDX_LEN;
}

psa_status_t demo_opaque_copy_key(
    psa_key_attributes_t *attributes,
    const uint8_t *source_key, size_t source_key_length,
    uint8_t *key_buffer, size_t key_buffer_size, size_t *key_buffer_length)
{
    (void)attributes;
    int i = *source_key; // key store index
    int j = 0;           // new key store index
    if (source_key_length != KEY_IDX_LEN) return PSA_ERROR_INVALID_ARGUMENT;
    if (i >= MAX_KEY_IDX || key_store[i].size == 0) return PSA_ERROR_INVALID_HANDLE;
    if (KEY_IDX_LEN > key_buffer_size) return PSA_ERROR_BUFFER_TOO_SMALL;

    // get free slot
    while (key_store[j].size != 0) {
        j++;
        if (j == MAX_KEY_IDX) return PSA_ERROR_INSUFFICIENT_STORAGE;
    }

    memcpy(key_store[j].data, key_store[i].data, key_store[i].size);
    key_store[j].size = key_store[i].size;

    // store new key context to global key store
    *key_buffer = (uint8_t)j;
    *key_buffer_length = KEY_IDX_LEN;

    return PSA_SUCCESS;
}

psa_status_t demo_opaque_export_key(
    const psa_key_attributes_t *attributes,
    const uint8_t *key, size_t key_length,
    uint8_t *data, size_t data_size, size_t *data_length)
{
    (void)attributes;
    int i = *key; // key store index
    if (key_length != KEY_IDX_LEN) return PSA_ERROR_INVALID_ARGUMENT;
    if (i >= MAX_KEY_IDX || key_store[i].size == 0) return PSA_ERROR_INVALID_HANDLE;
    if (key_store[i].size > data_size) return PSA_ERROR_BUFFER_TOO_SMALL;
    memcpy(data, key_store[i].data, key_store[i].size);
    *data_length = key_store[i].size;
    return PSA_SUCCESS;
}

psa_status_t demo_opaque_export_public_key(
    const psa_key_attributes_t *attributes,
    const uint8_t *key, size_t key_length,
    uint8_t *data, size_t data_size, size_t *data_length)
{
    psa_key_attributes_t local_attr = *attributes;
    int i = *key; // key store index
    if (key_length != KEY_IDX_LEN) return PSA_ERROR_INVALID_ARGUMENT;
    if (i >= MAX_KEY_IDX || key_store[i].size == 0) return PSA_ERROR_INVALID_HANDLE;
    psa_set_key_lifetime(&local_attr, PSA_KEY_LIFETIME_VOLATILE);
    return psa_driver_wrapper_export_public_key(
        &local_attr, key_store[i].data, key_store[i].size, data, data_size, data_length);
}

psa_status_t demo_opaque_import_key(
    const psa_key_attributes_t *attributes,
    const uint8_t *data, size_t data_length,
    uint8_t *key, size_t key_size, size_t *key_length,
    size_t *key_bits)
{
    int i = 0;
    psa_status_t status;
    size_t length;
    psa_key_attributes_t local_attr = *attributes;

    // get free slot
    while (key_store[i].size != 0) {
        i++;
        if (i == MAX_KEY_IDX) return PSA_ERROR_INSUFFICIENT_STORAGE;
    }
    if (KEY_IDX_LEN > key_size) return PSA_ERROR_BUFFER_TOO_SMALL;

    // use standard import to validate the data and store key to the local key store
    psa_set_key_lifetime(&local_attr, PSA_KEY_LIFETIME_VOLATILE);
    status = psa_driver_wrapper_import_key(&local_attr, data, data_length,
                                           key_store[i].data, MAX_KEY_SIZE, &length, key_bits);
    if (status) return status;
    key_store[i].size = length;

    // store key context to global key store
    *key = (uint8_t)i;
    *key_length = KEY_IDX_LEN;

    return PSA_SUCCESS;
}

psa_status_t demo_opaque_generate_key(
    const psa_key_attributes_t *attributes,
    uint8_t *key, size_t key_size, size_t *key_length)
{
    int i = 0;
    psa_status_t status;
    size_t length;
    psa_key_attributes_t local_attr = *attributes;

    // get free slot
    while (key_store[i].size != 0) {
        i++;
        if (i == MAX_KEY_IDX) return PSA_ERROR_INSUFFICIENT_STORAGE;
    }
    if (KEY_IDX_LEN > key_size) return PSA_ERROR_BUFFER_TOO_SMALL;

    // use standard key generation and store to the local key store
    psa_set_key_lifetime(&local_attr, PSA_KEY_LIFETIME_VOLATILE);
    status = psa_driver_wrapper_generate_key(&local_attr, key_store[i].data, MAX_KEY_SIZE, &length);
    if (status) return status;
    key_store[i].size = length;

    // store key context to global key store
    *key = (uint8_t)i;
    *key_length = KEY_IDX_LEN;

    return PSA_SUCCESS;
}

psa_status_t demo_opaque_derive_key(
    const psa_key_attributes_t *attributes,
    const uint8_t *input, size_t input_length,
    uint8_t *key, size_t key_size, size_t *key_length)
{
    (void)attributes;
    (void)input;
    (void)input_length;
    (void)key;
    (void)key_size;
    (void)key_length;
    return PSA_ERROR_NOT_SUPPORTED;
}

psa_status_t demo_opaque_destroy_key(
    const psa_key_attributes_t *attributes,
    const uint8_t *key_buffer, size_t key_buffer_size)
{
    (void)attributes;
    int i = *key_buffer; // key store index
    if (key_buffer_size != KEY_IDX_LEN) return PSA_ERROR_INVALID_ARGUMENT;
    if (i >= MAX_KEY_IDX || key_store[i].size == 0) return PSA_ERROR_INVALID_HANDLE;
    memset(key_store[i].data, 0, key_store[i].size); // remove key
    key_store[i].size = 0; // free slot
    return PSA_SUCCESS;
}

psa_status_t demo_opaque_signature_sign_message_with_context(
    const psa_key_attributes_t *attributes,
    const uint8_t *key, size_t key_length,
    psa_algorithm_t alg,
    const uint8_t *input, size_t input_length,
    const uint8_t *context, size_t context_length,
    uint8_t *signature, size_t signature_size, size_t *signature_length)
{
    psa_key_attributes_t local_attr = *attributes;
    int i = *key; // key store index
    if (key_length != KEY_IDX_LEN) return PSA_ERROR_INVALID_ARGUMENT;
    if (i >= MAX_KEY_IDX || key_store[i].size == 0) return PSA_ERROR_INVALID_HANDLE;

    psa_set_key_lifetime(&local_attr, PSA_KEY_LIFETIME_VOLATILE);
    return psa_driver_wrapper_sign_message_with_context(
        &local_attr, key_store[i].data, key_store[i].size,
        alg, input, input_length, context, context_length,
        signature, signature_size, signature_length);
}

psa_status_t demo_opaque_signature_verify_message_with_context(
    const psa_key_attributes_t *attributes,
    const uint8_t *key, size_t key_length,
    psa_algorithm_t alg,
    const uint8_t *input, size_t input_length,
    const uint8_t *context, size_t context_length,
    const uint8_t *signature, size_t signature_length)
{
    psa_key_attributes_t local_attr = *attributes;
    int i = *key; // key store index
    if (key_length != KEY_IDX_LEN) return PSA_ERROR_INVALID_ARGUMENT;
    if (i >= MAX_KEY_IDX || key_store[i].size == 0) return PSA_ERROR_INVALID_HANDLE;

    psa_set_key_lifetime(&local_attr, PSA_KEY_LIFETIME_VOLATILE);
    return psa_driver_wrapper_verify_message_with_context(
        &local_attr, key_store[i].data, key_store[i].size,
        alg, input, input_length, context, context_length,
        signature, signature_length);
}

psa_status_t demo_opaque_signature_sign_hash_with_context(
    const psa_key_attributes_t *attributes,
    const uint8_t *key, size_t key_length,
    psa_algorithm_t alg,
    const uint8_t *hash, size_t hash_length,
    const uint8_t *context, size_t context_length,
    uint8_t *signature, size_t signature_size, size_t *signature_length)
{
    psa_key_attributes_t local_attr = *attributes;
    int i = *key; // key store index
    if (key_length != KEY_IDX_LEN) return PSA_ERROR_INVALID_ARGUMENT;
    if (i >= MAX_KEY_IDX || key_store[i].size == 0) return PSA_ERROR_INVALID_HANDLE;

    psa_set_key_lifetime(&local_attr, PSA_KEY_LIFETIME_VOLATILE);
    return psa_driver_wrapper_sign_hash_with_context(
        &local_attr, key_store[i].data, key_store[i].size,
        alg, hash, hash_length, context, context_length,
        signature, signature_size, signature_length);
}

psa_status_t demo_opaque_signature_verify_hash_with_context(
    const psa_key_attributes_t *attributes,
    const uint8_t *key, size_t key_length,
    psa_algorithm_t alg,
    const uint8_t *hash, size_t hash_length,
    const uint8_t *context, size_t context_length,
    const uint8_t *signature, size_t signature_length)
{
    psa_key_attributes_t local_attr = *attributes;
    int i = *key; // key store index
    if (key_length != KEY_IDX_LEN) return PSA_ERROR_INVALID_ARGUMENT;
    if (i >= MAX_KEY_IDX || key_store[i].size == 0) return PSA_ERROR_INVALID_HANDLE;

    psa_set_key_lifetime(&local_attr, PSA_KEY_LIFETIME_VOLATILE);
    return psa_driver_wrapper_verify_hash_with_context(
        &local_attr, key_store[i].data, key_store[i].size,
        alg, hash, hash_length, context, context_length,
        signature, signature_length);
}


psa_status_t demo_opaque_cipher_encrypt_setup(
    oberon_opaque_cipher_operation_t *operation,
    const psa_key_attributes_t *attributes,
    const uint8_t *key, size_t key_length,
    psa_algorithm_t alg)
{
    psa_key_attributes_t local_attr = *attributes;
    int i = *key; // key store index
    if (key_length != KEY_IDX_LEN) return PSA_ERROR_INVALID_ARGUMENT;
    if (i >= MAX_KEY_IDX || key_store[i].size == 0) return PSA_ERROR_INVALID_HANDLE;

    psa_set_key_lifetime(&local_attr, PSA_KEY_LIFETIME_VOLATILE);
    operation->p_op = mbedtls_calloc(1, sizeof *operation->p_op);
    return psa_driver_wrapper_cipher_encrypt_setup(
        operation->p_op, &local_attr, key_store[i].data, key_store[i].size, alg);
}

psa_status_t demo_opaque_cipher_decrypt_setup(
    oberon_opaque_cipher_operation_t *operation,
    const psa_key_attributes_t *attributes,
    const uint8_t *key, size_t key_length,
    psa_algorithm_t alg)
{
    psa_key_attributes_t local_attr = *attributes;
    int i = *key; // key store index
    if (key_length != KEY_IDX_LEN) return PSA_ERROR_INVALID_ARGUMENT;
    if (i >= MAX_KEY_IDX || key_store[i].size == 0) return PSA_ERROR_INVALID_HANDLE;

    psa_set_key_lifetime(&local_attr, PSA_KEY_LIFETIME_VOLATILE);
    operation->p_op = mbedtls_calloc(1, sizeof *operation->p_op);
    return psa_driver_wrapper_cipher_decrypt_setup(
        operation->p_op, &local_attr, key_store[i].data, key_store[i].size, alg);
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
    int i = *key; // key store index
    if (key_length != KEY_IDX_LEN) return PSA_ERROR_INVALID_ARGUMENT;
    if (i >= MAX_KEY_IDX || key_store[i].size == 0) return PSA_ERROR_INVALID_HANDLE;

    psa_set_key_lifetime(&local_attr, PSA_KEY_LIFETIME_VOLATILE);
    return psa_driver_wrapper_cipher_encrypt(
        &local_attr, key_store[i].data, key_store[i].size,
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
    int i = *key; // key store index
    if (key_length != KEY_IDX_LEN) return PSA_ERROR_INVALID_ARGUMENT;
    if (i >= MAX_KEY_IDX || key_store[i].size == 0) return PSA_ERROR_INVALID_HANDLE;

    psa_set_key_lifetime(&local_attr, PSA_KEY_LIFETIME_VOLATILE);
    return psa_driver_wrapper_cipher_decrypt(
        &local_attr, key_store[i].data, key_store[i].size,
        alg, input, input_length,
        output, output_size, output_length);
}


psa_status_t demo_opaque_key_agreement(
    const psa_key_attributes_t *attributes,
    const uint8_t *key, size_t key_length,
    psa_algorithm_t alg,
    const uint8_t *peer_key, size_t peer_key_length,
    uint8_t *output, size_t output_size, size_t *output_length)
{
    psa_key_attributes_t local_attr = *attributes;
    int i = *key; // key store index
    if (key_length != KEY_IDX_LEN) return PSA_ERROR_INVALID_ARGUMENT;
    if (i >= MAX_KEY_IDX || key_store[i].size == 0) return PSA_ERROR_INVALID_HANDLE;

    psa_set_key_lifetime(&local_attr, PSA_KEY_LIFETIME_VOLATILE);
    return psa_driver_wrapper_key_agreement(
        &local_attr, key_store[i].data, key_store[i].size,
        alg, peer_key, peer_key_length,
        output, output_size, output_length);
}

psa_status_t demo_opaque_key_agreement_to_key(
    const psa_key_attributes_t *attributes,
    const uint8_t *key, size_t key_length,
    psa_algorithm_t alg,
    const uint8_t *peer_key, size_t peer_key_length,
    const psa_key_attributes_t *output_attributes,
    uint8_t *output, size_t output_size, size_t *output_length)
{
    psa_key_attributes_t local_attr = *attributes;
    psa_status_t status;
    size_t length;
    int i = *key; // key store index
    int j = 0;    // new key store index
    if (key_length != KEY_IDX_LEN) return PSA_ERROR_INVALID_ARGUMENT;
    if (i >= MAX_KEY_IDX || key_store[i].size == 0) return PSA_ERROR_INVALID_HANDLE;

    // get free slot
    while (key_store[j].size != 0) {
        j++;
        if (j == MAX_KEY_IDX) return PSA_ERROR_INSUFFICIENT_STORAGE;
    }
    if (KEY_IDX_LEN > output_size) return PSA_ERROR_BUFFER_TOO_SMALL;

    psa_set_key_lifetime(&local_attr, PSA_KEY_LIFETIME_VOLATILE);
    status =  psa_driver_wrapper_key_agreement(
        &local_attr, key_store[i].data, key_store[i].size,
        alg, peer_key, peer_key_length,
        key_store[j].data, MAX_KEY_SIZE, &length);
    if (status) return status;
    key_store[j].size = length;
    *output = (uint8_t)j;
    *output_length = KEY_IDX_LEN;
    (void)output_attributes;
    return PSA_SUCCESS;
}


psa_status_t demo_opaque_key_derivation_setup(
    oberon_opaque_key_derivation_operation_t *operation,
    const psa_key_attributes_t *key_attributes,
    psa_algorithm_t alg)
{
    psa_key_attributes_t local_attr = *key_attributes;
    psa_set_key_lifetime(&local_attr, PSA_KEY_LIFETIME_VOLATILE);
    operation->p_op = mbedtls_calloc(1, sizeof *operation->p_op);
    operation->alg = alg;
    return psa_driver_wrapper_key_derivation_setup(
        operation->p_op, &local_attr, alg);
}

psa_status_t demo_opaque_key_derivation_set_capacity(
    oberon_opaque_key_derivation_operation_t *operation,
    size_t capacity)
{
    operation->capacity = capacity;
    return psa_driver_wrapper_key_derivation_set_capacity(
        operation->p_op, capacity);
}

psa_status_t demo_opaque_key_derivation_input_bytes(
    oberon_opaque_key_derivation_operation_t *operation,
    psa_key_derivation_step_t step,
    const uint8_t *data, size_t data_length)
{
    return psa_driver_wrapper_key_derivation_input_bytes(
        operation->p_op, step, data, data_length);
}

psa_status_t demo_opaque_key_derivation_input_key(
    oberon_opaque_key_derivation_operation_t *operation,
    psa_key_derivation_step_t step,
    const psa_key_attributes_t *key_attributes,
    const uint8_t *key, size_t key_length)
{
    int i = *key; // key store index
    if (key_length != KEY_IDX_LEN) return PSA_ERROR_INVALID_ARGUMENT;
    if (i >= MAX_KEY_IDX || key_store[i].size == 0) return PSA_ERROR_INVALID_HANDLE;

    return psa_driver_wrapper_key_derivation_input_bytes(
        operation->p_op, step, key_store[i].data, key_store[i].size);
    (void)key_attributes;
}

psa_status_t demo_opaque_key_derivation_input_integer(
    oberon_opaque_key_derivation_operation_t *operation,
    psa_key_derivation_step_t step,
    uint64_t value)
{
    return psa_driver_wrapper_key_derivation_input_integer(
        operation->p_op, step, value);
}

psa_status_t demo_opaque_key_derivation_output_bytes(
    oberon_opaque_key_derivation_operation_t *operation,
    uint8_t *output, size_t output_length)
{
    if (operation->p_op == NULL) return PSA_ERROR_INSUFFICIENT_DATA;
    return psa_driver_wrapper_key_derivation_output_bytes(
        operation->p_op, output, output_length);
}

psa_status_t demo_opaque_key_derivation_output_key(
    oberon_opaque_key_derivation_operation_t *operation,
    const psa_key_attributes_t *key_attributes,
    uint8_t *key, size_t key_size, size_t *key_length)
{
    int i = 0;
    psa_status_t status;
    psa_key_type_t type = psa_get_key_type(key_attributes);
    size_t bits = psa_get_key_bits(key_attributes);
    size_t length;

    if (operation->p_op == NULL) return PSA_ERROR_INSUFFICIENT_DATA;

    if (PSA_KEY_TYPE_IS_SRP_KEY_PAIR(type)) {
        length = PSA_HASH_LENGTH(operation->alg);
    } else {
        length = PSA_EXPORT_KEY_OUTPUT_SIZE(type, bits);
    }

    // get free slot
    while (key_store[i].size != 0) {
        i++;
        if (i == MAX_KEY_IDX) return PSA_ERROR_INSUFFICIENT_STORAGE;
    }
    if (KEY_IDX_LEN > key_size) return PSA_ERROR_BUFFER_TOO_SMALL;
    if (length > MAX_KEY_SIZE) return PSA_ERROR_BUFFER_TOO_SMALL;

    status = psa_driver_wrapper_key_derivation_output_bytes(
        operation->p_op, key_store[i].data, length);
    if (status) return status;
    key_store[i].size = length;
    *key = (uint8_t)i;
    *key_length = KEY_IDX_LEN;
    return PSA_SUCCESS;
}

psa_status_t demo_opaque_key_derivation_verify_bytes(
    oberon_opaque_key_derivation_operation_t *operation,
    const uint8_t *expected, size_t length)
{
    psa_status_t status;
    uint8_t *data = mbedtls_calloc(1, length);
    if (data == NULL) return PSA_ERROR_INSUFFICIENT_STORAGE;
    status = psa_driver_wrapper_key_derivation_output_bytes(
        operation->p_op, data, length);
    if (status) goto exit;
    if (oberon_ct_compare(data, expected, length)) status = PSA_ERROR_INVALID_SIGNATURE;
    status = PSA_SUCCESS;
exit:
    mbedtls_free(data);
    return status;
}

psa_status_t demo_opaque_key_derivation_verify_key(
    oberon_opaque_key_derivation_operation_t *operation,
    const psa_key_attributes_t *key_attributes,
    const uint8_t *key, size_t key_length)
{
    (void)key_attributes;
    int i = *key; // key store index
    if (key_length != KEY_IDX_LEN) return PSA_ERROR_INVALID_ARGUMENT;
    if (i >= MAX_KEY_IDX || key_store[i].size == 0) return PSA_ERROR_INVALID_HANDLE;
    return demo_opaque_key_derivation_verify_bytes(operation, key_store[i].data, key_store[i].size);
}

psa_status_t demo_opaque_key_derivation_abort(
    oberon_opaque_key_derivation_operation_t *operation)
{
    psa_status_t status;
    if (operation->p_op == NULL) return PSA_SUCCESS;
    status = psa_driver_wrapper_key_derivation_abort(operation->p_op);
    mbedtls_free(operation->p_op);
    operation->p_op = NULL;
    return status;
}


