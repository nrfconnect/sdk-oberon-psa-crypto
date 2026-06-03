//
// Copyright Oberon microsystems AG, Switzerland.
// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
//
// This file implements functions from the Arm PSA Crypto Driver Interface.

/*
 * Please note: this simple implementation is provided for demonstration only. 
 *
 * Use in production is not recommended.
 */ 


#include "string.h"

#include "psa/crypto.h"
#include "acme_mac.h"
#include "psa_crypto_driver_wrappers.h"


/* HMAC SHA-256 */

psa_status_t acme_mac_sign_setup(
    acme_mac_operation_t *operation,
    const psa_key_attributes_t *attributes,
    const uint8_t *key, size_t key_length,
    psa_algorithm_t alg)
{
    psa_status_t status;
    size_t i, length;
    (void)attributes;

    if (!PSA_ALG_IS_HMAC(alg)) return PSA_ERROR_NOT_SUPPORTED;
    psa_algorithm_t hash_alg = PSA_ALG_HMAC_GET_HASH(alg);
    size_t block_size = PSA_HASH_BLOCK_LENGTH(hash_alg);

    if (key_length > block_size) {
        // replace key by H(key) stored in k
        status = psa_driver_wrapper_hash_setup(&operation->hash_op, hash_alg);
        if (status) return status;
        status = psa_driver_wrapper_hash_update(&operation->hash_op, key, key_length);
        if (status) return status;
        status = psa_driver_wrapper_hash_finish(&operation->hash_op, operation->k, sizeof operation->k, &length);
        if (status) return status;
        memset(&operation->hash_op, 0, sizeof operation->hash_op);
        key = operation->k;
        key_length = length;
    }

    status = psa_driver_wrapper_hash_setup(&operation->hash_op, hash_alg);
    if (status) return status;

    // k = key ^ ipad
    for (i = 0; i < key_length; i++) operation->k[i] = (uint8_t)(key[i] ^ 0x36);
    for (; i < block_size; i++) operation->k[i] = 0x36;
    status =  psa_driver_wrapper_hash_update(&operation->hash_op, operation->k, block_size); // key ^ ipad
    if (status) return status;

    operation->hash_alg = hash_alg;
    return PSA_SUCCESS;
}

psa_status_t acme_mac_verify_setup(
    acme_mac_operation_t *operation,
    const psa_key_attributes_t *attributes,
    const uint8_t *key, size_t key_length,
    psa_algorithm_t alg)
{
    return acme_mac_sign_setup(operation,
        attributes, key, key_length, alg);
}

psa_status_t acme_mac_update(
    acme_mac_operation_t *operation,
    const uint8_t *input, size_t input_len)
{
    return psa_driver_wrapper_hash_update(&operation->hash_op, input, input_len);
}

psa_status_t acme_mac_sign_finish(
    acme_mac_operation_t *operation,
    uint8_t *mac, size_t mac_size, size_t *mac_length)
{
    psa_status_t status;
    size_t i, length;

    // H(K ^ ipad, in, num)
    status = psa_driver_wrapper_hash_finish(&operation->hash_op, operation->hash, sizeof operation->hash, &length);
    if (status) goto exit;

    // k = key ^ opad = (key ^ ipad) ^ (ipad ^ opad) = k ^ (ipad ^ opad)
    size_t block_size = PSA_HASH_BLOCK_LENGTH(operation->hash_alg);
    for (i = 0; i < block_size; i++) operation->k[i] = (uint8_t)(operation->k[i] ^ (0x36 ^ 0x5c));

    memset(&operation->hash_op, 0, sizeof operation->hash_op);
    status = psa_driver_wrapper_hash_setup(&operation->hash_op, operation->hash_alg);
    if (status) goto exit;
    status = psa_driver_wrapper_hash_update(&operation->hash_op, operation->k, block_size);
    if (status) goto exit;
    status = psa_driver_wrapper_hash_update(&operation->hash_op, operation->hash, length);
    if (status) goto exit;
    status = psa_driver_wrapper_hash_finish(&operation->hash_op, operation->hash, sizeof operation->hash, &length);
    if (status) goto exit;
    memcpy(mac, operation->hash, mac_size);
    *mac_length = mac_size;

exit:
    psa_driver_wrapper_hash_abort(&operation->hash_op);
    return status;
}

psa_status_t acme_mac_verify_finish(
    acme_mac_operation_t *operation,
    const uint8_t *mac, size_t mac_length)
{
    uint8_t temp_mac[PSA_HASH_MAX_SIZE];
    size_t mac_len, i;
    psa_status_t status;
    int diff = 0;

    status = acme_mac_sign_finish(operation, temp_mac, mac_length, &mac_len);
    if (status != PSA_SUCCESS) return status;
    for (i = 0; i < mac_len; i++) {
        diff |= (int)(mac[i] ^ temp_mac[i]);
    }
    return diff ? PSA_ERROR_INVALID_SIGNATURE : PSA_SUCCESS;
}

psa_status_t acme_mac_abort(
    acme_mac_operation_t *operation)
{
    psa_driver_wrapper_hash_abort(&operation->hash_op);
    memset(operation, 0, sizeof *operation);
    return PSA_SUCCESS;
}


psa_status_t acme_mac_compute(
    const psa_key_attributes_t *attributes,
    const uint8_t *key, size_t key_length,
    psa_algorithm_t alg,
    const uint8_t *input, size_t input_length,
    uint8_t *mac, size_t mac_size, size_t *mac_length)
{
    acme_mac_operation_t operation;
    psa_status_t status;

    memset(&operation, 0, sizeof operation);
    status = acme_mac_sign_setup(&operation, attributes, key, key_length, alg);
    if (status) goto exit;
    status = acme_mac_update(&operation, input, input_length);
    if (status) goto exit;
    return acme_mac_sign_finish(&operation, mac, mac_size, mac_length);

exit:
    psa_driver_wrapper_hash_abort(&operation.hash_op);
    return status;
}
