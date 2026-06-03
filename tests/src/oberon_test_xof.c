/*
 * Copyright (c) 2016 - 2026 Nordic Semiconductor ASA
 * Copyright (c) since 2020 Oberon microsystems AG
 *
 * SPDX-License-Identifier: LicenseRef-Nordic-5-Clause
 */

//
// This file implements functions from the Arm PSA Crypto Driver Interface.

#include <string.h>

#include "psa/crypto.h"
#include "oberon_test_xof.h"


static int error_count, out_mask;

void oberon_test_xof_config(int err_count, int mask)
{
    error_count = err_count;
    out_mask = mask;
}


psa_status_t oberon_test_xof_setup(
    oberon_xof_operation_t *operation,
    psa_algorithm_t alg)
{
    switch (alg) {
    case PSA_ALG_SHAKE128:
    case PSA_ALG_SHAKE256:
        return oberon_xof_setup(operation, alg);
    default:
        return PSA_ERROR_NOT_SUPPORTED;
    }
}

psa_status_t oberon_test_xof_update(
    oberon_xof_operation_t *operation,
    const uint8_t *input, size_t input_length)
{
    switch (operation->alg) {
    case PSA_ALG_SHAKE128:
    case PSA_ALG_SHAKE256:
        return oberon_xof_update(operation, input, input_length);
    default:
        return PSA_ERROR_NOT_SUPPORTED;
    }
}

psa_status_t oberon_test_xof_output(
    oberon_xof_operation_t *operation,
    uint8_t *output, size_t output_length)
{
    psa_status_t status;

    switch (operation->alg) {
    case PSA_ALG_SHAKE128:
    case PSA_ALG_SHAKE256:
        status = oberon_xof_output(operation, output, output_length);
        if (status) return status;
        break;
    default:
        return PSA_ERROR_NOT_SUPPORTED;
    }

    if (error_count > 0) {
        // error injection
        error_count--;
        if (error_count == 0) {
            return PSA_ERROR_GENERIC_ERROR;
        }
    }
    if (out_mask && (output_length == 136 || output_length == 168)) {
        // mask output to provoke many rejections
        memset(output, 0xFF, output_length - 16);
    }
    return PSA_SUCCESS;
}

psa_status_t oberon_test_xof_abort(
    oberon_xof_operation_t *operation)
{
    oberon_xof_abort(operation);
    memset(operation, 0, sizeof *operation);
    return PSA_SUCCESS;
}
