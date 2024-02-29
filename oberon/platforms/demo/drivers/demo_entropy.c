/*
 * Copyright (c) 2016 - 2024 Nordic Semiconductor ASA
 * Copyright (c) since 2020 Oberon microsystems AG
 *
 * SPDX-License-Identifier: LicenseRef-Nordic-5-Clause
 */

//
// This file implements functions from the Arm PSA Crypto Driver API.

#include <stdlib.h>
#include <time.h>

#include "psa/crypto.h"
#include "demo_entropy.h"


psa_status_t demo_init_entropy()
{
    srand((unsigned int)time(0));
    return PSA_SUCCESS;
}

psa_status_t demo_get_entropy(
    uint32_t flags,
    size_t *estimate_bits,
    uint8_t *output,
    size_t output_size)
{
    size_t i;
    (void)flags;

    for (i = 0; i < output_size; i++) {
        output[i] = (uint8_t)rand();
    }

    // assume full entropy
    *estimate_bits = PSA_BYTES_TO_BITS(output_size);
    return PSA_SUCCESS;
}
