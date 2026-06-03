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


#ifndef ACME_SHA_H
#define ACME_SHA_H

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
} acme_hash_operation_t;


psa_status_t acme_hash_setup(
    acme_hash_operation_t *operation,
    psa_algorithm_t alg);

psa_status_t acme_hash_clone(
    const acme_hash_operation_t *source_operation,
    acme_hash_operation_t *target_operation);

psa_status_t acme_hash_update(
    acme_hash_operation_t *operation,
    const uint8_t *input, size_t input_length);

psa_status_t acme_hash_finish(
    acme_hash_operation_t *operation,
    uint8_t *hash, size_t hash_size, size_t *hash_length);

psa_status_t acme_hash_abort(
    acme_hash_operation_t *operation);


psa_status_t acme_hash_compute(
    psa_algorithm_t alg,
    const uint8_t *input, size_t input_length,
    uint8_t *hash, size_t hash_size, size_t *hash_length);


#ifdef __cplusplus
}
#endif

#endif
