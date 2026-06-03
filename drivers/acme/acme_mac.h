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


#ifndef ACME_MAC_H
#define ACME_MAC_H

#include <psa/crypto_driver_common.h>


#ifdef __cplusplus
extern "C" {
#endif


typedef struct {
    psa_hash_operation_t hash_op;
    psa_algorithm_t hash_alg;
    uint8_t hash[PSA_HASH_MAX_SIZE];
    uint8_t k[PSA_HMAC_MAX_HASH_BLOCK_SIZE];
} acme_mac_operation_t;


psa_status_t acme_mac_sign_setup(
    acme_mac_operation_t *operation,
    const psa_key_attributes_t *attributes,
    const uint8_t *key, size_t key_length,
    psa_algorithm_t alg);

psa_status_t acme_mac_verify_setup(
    acme_mac_operation_t *operation,
    const psa_key_attributes_t *attributes,
    const uint8_t *key, size_t key_length,
    psa_algorithm_t alg);

psa_status_t acme_mac_update(
    acme_mac_operation_t *operation,
    const uint8_t *input, size_t input_length );

psa_status_t acme_mac_sign_finish(
    acme_mac_operation_t *operation,
    uint8_t *mac, size_t mac_size, size_t *mac_length);

psa_status_t acme_mac_verify_finish(
    acme_mac_operation_t *operation,
    const uint8_t *mac, size_t mac_length);

psa_status_t acme_mac_abort(
    acme_mac_operation_t *operation);


psa_status_t acme_mac_compute(
    const psa_key_attributes_t *attributes,
    const uint8_t *key, size_t key_length,
    psa_algorithm_t alg,
    const uint8_t *input, size_t input_length,
    uint8_t *mac, size_t mac_size, size_t *mac_length);


#ifdef __cplusplus
}
#endif

#endif
