//
// Copyright Oberon microsystems AG, Switzerland.
// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
//
// This file implements functions from the Arm PSA Crypto Driver Interface.

#include "string.h"

/*
 * Please note: this simple implementation is provided for demonstration only. 
 *
 * Use in production is not recommended.
 */ 


#include "psa/crypto.h"
#include "acme_kdf.h"
#include "psa_crypto_driver_wrappers.h"


/* HKDF SHA-256 */

static psa_status_t setup_kdf_mac(
    acme_key_derivation_operation_t *operation,
    const uint8_t *key, size_t key_length)
{
    psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;
    psa_set_key_type(&attributes, PSA_KEY_TYPE_HMAC);
    psa_set_key_bits(&attributes, PSA_BYTES_TO_BITS(key_length));
    psa_set_key_usage_flags(&attributes, PSA_KEY_USAGE_SIGN_MESSAGE);

    memset(&operation->mac_op, 0, sizeof operation->mac_op);
    return psa_driver_wrapper_mac_sign_setup(
        &operation->mac_op,
        &attributes, key, key_length,
        operation->mac_alg);
}

psa_status_t acme_key_derivation_setup(
    acme_key_derivation_operation_t *operation,
    const psa_key_attributes_t *key_attributes,
    psa_algorithm_t alg)
{
    (void)key_attributes;
    if (!PSA_ALG_IS_HKDF(alg)) return PSA_ERROR_NOT_SUPPORTED;
    if (PSA_HASH_LENGTH(alg) == 0) return PSA_ERROR_NOT_SUPPORTED;
    operation->mac_alg = PSA_ALG_HMAC(PSA_ALG_GET_HASH(alg));
    operation->index = 1;
    return PSA_SUCCESS;
}

psa_status_t acme_key_derivation_input_bytes(
    acme_key_derivation_operation_t *operation,
    psa_key_derivation_step_t step,
    const uint8_t *data, size_t data_length)
{
    uint8_t zero[PSA_HASH_MAX_SIZE];
    psa_status_t status = PSA_ERROR_CORRUPTION_DETECTED;
    size_t length, block_length = PSA_HASH_LENGTH(operation->mac_alg);

    switch (step) {

    case PSA_KEY_DERIVATION_INPUT_SALT:
        if (data_length) {
            status = setup_kdf_mac(operation, data, data_length);
            if (status) goto exit;
            operation->salt_length = (uint16_t)data_length;
        }
        return PSA_SUCCESS;

    case PSA_KEY_DERIVATION_INPUT_SECRET:
        if (operation->salt_length == 0) {
            // set zero salt
            memset(zero, 0, block_length);
            status = setup_kdf_mac(operation, zero, block_length);
            if (status) goto exit;
        }
        // add secret
        status = psa_driver_wrapper_mac_update(&operation->mac_op, data, data_length);
        if (status) goto exit;
        // HKDF extract
        status = psa_driver_wrapper_mac_sign_finish(&operation->mac_op,
            operation->key, block_length, &length);
        if (status) goto exit;
        return PSA_SUCCESS;

    case PSA_KEY_DERIVATION_INPUT_INFO:
        if (data_length > sizeof operation->info) return PSA_ERROR_INSUFFICIENT_MEMORY;
        memcpy(operation->info, data, data_length);
        operation->info_length = (uint16_t)data_length;
        return PSA_SUCCESS;

    default:
        return PSA_ERROR_INVALID_ARGUMENT;
    }

exit:
    psa_driver_wrapper_mac_abort(&operation->mac_op);
    return status;
}

psa_status_t acme_key_derivation_output_bytes(
    acme_key_derivation_operation_t *operation,
    uint8_t *output, size_t output_length)
{
    psa_status_t status = PSA_ERROR_CORRUPTION_DETECTED;
    size_t data_length = operation->data_length;
    size_t length, block_length = PSA_HASH_LENGTH(operation->mac_alg);
    uint8_t idx;

    if (output_length == 0) return PSA_SUCCESS;

    if (data_length) {
        if (data_length >= output_length) {
            memcpy(output, operation->data + block_length - data_length, output_length);
            operation->data_length = (uint8_t)(data_length - output_length);
            return PSA_SUCCESS;
        } else {
            memcpy(output, operation->data + block_length - data_length, data_length);
            output += data_length;
            output_length -= data_length;
        }
    }

    for (;;) {
        status = setup_kdf_mac(operation, operation->key, block_length); // prk
        if (status) goto exit;
        // T(i-1)
        if (operation->index > 1) {
            status = psa_driver_wrapper_mac_update(&operation->mac_op, operation->data, block_length);
            if (status) goto exit;
        }
        // info
        status = psa_driver_wrapper_mac_update(&operation->mac_op, operation->info, operation->info_length);
        if (status) goto exit;
        // i
        idx = (uint8_t)operation->index;
        status = psa_driver_wrapper_mac_update(&operation->mac_op, &idx, 1);
        if (status) goto exit;
        status = psa_driver_wrapper_mac_sign_finish(&operation->mac_op, operation->data, block_length, &length);
        if (status) goto exit;

        operation->index++;
        if (output_length > block_length) {
            memcpy(output, operation->data, block_length);
            output += block_length;
            output_length -= block_length;
        } else {
            memcpy(output, operation->data, output_length);
            operation->data_length = (uint8_t)(block_length - output_length);
            return PSA_SUCCESS;
        }
    }

exit:
    psa_driver_wrapper_mac_abort(&operation->mac_op);
    return status;
}

psa_status_t acme_key_derivation_abort(
    acme_key_derivation_operation_t *operation)
{
    return psa_driver_wrapper_mac_abort(&operation->mac_op);
}
