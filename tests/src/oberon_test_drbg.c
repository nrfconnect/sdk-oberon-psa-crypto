/*
 * Copyright (c) 2016 - 2024 Nordic Semiconductor ASA
 * Copyright (c) since 2020 Oberon microsystems AG
 *
 * SPDX-License-Identifier: LicenseRef-Nordic-5-Clause
 */

//
// This file implements functions from the Arm PSA Crypto Driver API.

#include <string.h>

#include "psa/crypto.h"
#include "psa_crypto_driver_wrappers.h"
#include "oberon_test_drbg.h"


const uint8_t *random_data = NULL;
size_t random_length, random_index;


// set new random data
void oberon_test_drbg_setup(
    const uint8_t *data, size_t data_length)
{
    random_data = data;
    random_length = data_length;
    random_index = 0;
}

// generate random bytes
psa_status_t oberon_test_drbg_get_random(
    void *context,
    uint8_t *output,
    size_t output_size)
{
    (void)context;
    if (random_data && random_index + output_size <= random_length) {
        memcpy(output, &random_data[random_index], output_size);
        random_index += output_size;
        return PSA_SUCCESS;
    } else {
        return PSA_ERROR_INSUFFICIENT_ENTROPY;
    }
}
