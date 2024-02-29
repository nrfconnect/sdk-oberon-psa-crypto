/*
 * Copyright (c) 2016 - 2024 Nordic Semiconductor ASA
 * Copyright (c) since 2020 Oberon microsystems AG
 *
 * SPDX-License-Identifier: LicenseRef-Nordic-5-Clause
 */

//
// This file is based on the Arm PSA Crypto Driver API.

#ifndef DEMO_ENTROPY_H
#define DEMO_ENTROPY_H

#include <psa/crypto_driver_common.h>


#ifdef __cplusplus
extern "C" {
#endif


psa_status_t demo_init_entropy();

psa_status_t demo_get_entropy(
    uint32_t flags,
    size_t *estimate_bits,
    uint8_t *output,
    size_t output_size);


#ifdef __cplusplus
}
#endif

#endif
