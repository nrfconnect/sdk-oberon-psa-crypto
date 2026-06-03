//
// Copyright Oberon microsystems AG, Switzerland.
// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
//
// This file implements functions from the Arm PSA Crypto Driver Interface.

/*
 * Please note: this simple implementation is provided for demonstration only. 
 *
 * It assumes that `rand()` is implemented based on a true random number 
 * generator with sufficient entropy.
 * 
 * Use in production is not recommended.
 */ 

#include <stdlib.h>
#include <time.h>

#include "psa/crypto.h"
#include "acme_rng.h"

psa_status_t acme_rng_init(
    acme_rng_context_t *context)
{
#ifdef OBERON_USE_MUTEX
    oberon_mutex_init(&context->mutex);
    if (oberon_mutex_lock(&context->mutex)) {
        return PSA_ERROR_GENERIC_ERROR;
    }
#else
    (void)context;
#endif

    srand((unsigned int)time(0));

#ifdef OBERON_USE_MUTEX
    if (oberon_mutex_unlock(&context->mutex)) {
        return PSA_ERROR_GENERIC_ERROR;
    }
#endif

    return PSA_SUCCESS;
}

psa_status_t acme_rng_get_random(
    acme_rng_context_t *context,
    uint8_t *output,
    size_t output_size)
{
#ifdef OBERON_USE_MUTEX
    if (oberon_mutex_lock(&context->mutex)) {
        return PSA_ERROR_GENERIC_ERROR;
    }
#else
    (void)context;
#endif

    size_t i;

    for (i = 0; i < output_size; i++) {
        output[i] = (uint8_t)rand();
    }

#ifdef OBERON_USE_MUTEX
    if (oberon_mutex_unlock(&context->mutex)) {
        return PSA_ERROR_GENERIC_ERROR;
    }
#endif

    return PSA_SUCCESS;
}

psa_status_t acme_rng_free(
    acme_rng_context_t *context)
{
    (void)context;

#ifdef OBERON_USE_MUTEX
    oberon_mutex_free(&context->mutex);
#else
    (void)context;
#endif

    return PSA_SUCCESS;
}
