/*
 * Copyright (c) 2016 - 2026 Nordic Semiconductor ASA
 * Copyright (c) since 2020 Oberon microsystems AG
 *
 * SPDX-License-Identifier: LicenseRef-Nordic-5-Clause
 */

//
// This file is based on the Arm PSA Crypto Driver Interface.

#ifndef OBERON_TEST_XOF_H
#define OBERON_TEST_XOF_H

#include <psa/crypto_driver_common.h>
#include "oberon_xof.h"


#ifdef __cplusplus
extern "C" {
#endif

// error_count decrements on each output call and provokes a PSA_ERROR_GENERIC_ERROR when reaching 0.
// When mask is set, most of the bytes in a full block output buffer are set to 0xFF.
void oberon_test_xof_config(int error_count, int mask);


psa_status_t oberon_test_xof_setup(
    oberon_xof_operation_t *operation,
    psa_algorithm_t alg);

psa_status_t oberon_test_xof_update(
    oberon_xof_operation_t *operation,
    const uint8_t *input, size_t input_length);

psa_status_t oberon_test_xof_output(
    oberon_xof_operation_t *operation,
    uint8_t *output, size_t output_length);

psa_status_t oberon_test_xof_abort(
    oberon_xof_operation_t *operation);


#ifdef __cplusplus
}
#endif

#endif
