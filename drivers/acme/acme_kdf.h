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


#ifndef ACME_KDF_H
#define ACME_KDF_H

#include <psa/crypto_driver_common.h>


#ifdef __cplusplus
extern "C" {
#endif


typedef struct {
    psa_mac_operation_t mac_op;
    psa_algorithm_t mac_alg;
    uint8_t  data[PSA_HASH_MAX_SIZE];
    uint8_t  info[256];
    uint8_t  key[PSA_HASH_MAX_SIZE];
    uint8_t  data_length;
    uint16_t salt_length;
    uint16_t info_length;
    uint32_t index;
} acme_key_derivation_operation_t;


psa_status_t acme_key_derivation_setup(
    acme_key_derivation_operation_t *operation,
    const psa_key_attributes_t *key_attributes,
    psa_algorithm_t alg);

psa_status_t acme_key_derivation_input_bytes(
    acme_key_derivation_operation_t *operation,
    psa_key_derivation_step_t step,
    const uint8_t *data, size_t data_length);

psa_status_t acme_key_derivation_output_bytes(
    acme_key_derivation_operation_t *operation,
    uint8_t *output, size_t output_length);

psa_status_t acme_key_derivation_abort(
    acme_key_derivation_operation_t *operation );


#ifdef __cplusplus
}
#endif

#endif
