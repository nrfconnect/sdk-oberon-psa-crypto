//
// Copyright Oberon microsystems AG, Switzerland.
// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
//
// This file is based on the Arm PSA Crypto Driver Interface.

/*
 * Please note: this simple implementation is provided for demonstration only. 
 *
 * It assumes that `rand()` is implemented based on a true random number 
 * generator with sufficient entropy.
 * 
 * Use in production is not recommended.
 */ 

#ifndef ACME_RNG_H
#define ACME_RNG_H

#include <psa/crypto_driver_common.h>


#ifdef __cplusplus
extern "C" {
#endif


typedef struct {    
    unsigned dummy; /* Make sure this union is always non-empty */
#ifdef OBERON_USE_MUTEX
    oberon_mutex_type mutex;
#endif
} acme_rng_context_t;


psa_status_t acme_rng_init(
    acme_rng_context_t *context);

psa_status_t acme_rng_get_random(
    acme_rng_context_t *context,
    uint8_t *output,
    size_t output_size);

psa_status_t acme_rng_free(
    acme_rng_context_t *context);


#ifdef __cplusplus
}
#endif

#endif
