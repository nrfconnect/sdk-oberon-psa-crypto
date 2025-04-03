/*
 * Copyright (c) 2016 - 2025 Nordic Semiconductor ASA
 * Copyright (c) since 2020 Oberon microsystems AG
 *
 * SPDX-License-Identifier: LicenseRef-Nordic-5-Clause
 */

//
// This file is based on the Arm PSA Crypto Driver API.

#ifndef OBERON_TEST_DRBG_H
#define OBERON_TEST_DRBG_H

#include <psa/crypto_driver_common.h>


#ifdef __cplusplus
extern "C" {
#endif


void oberon_test_drbg_setup(
    const uint8_t *data, size_t data_length);

psa_status_t oberon_test_drbg_get_random(
    void *context,
    uint8_t *output,
    size_t output_size);


#ifdef __cplusplus
}
#endif

#endif
