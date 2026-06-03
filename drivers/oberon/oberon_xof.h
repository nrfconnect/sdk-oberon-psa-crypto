/*
 * Copyright (c) 2016 - 2026 Nordic Semiconductor ASA
 * Copyright (c) since 2020 Oberon microsystems AG
 *
 * SPDX-License-Identifier: LicenseRef-Nordic-5-Clause
 */

//
// This file is based on the Arm PSA Crypto Driver Interface.

#ifndef OBERON_XOF_H
#define OBERON_XOF_H

#include <psa/crypto_driver_common.h>


#ifdef __cplusplus
extern "C" {
#endif


/**
 * The major version of this implementation of the PSA Crypto Driver Interface
 */
#define PSA_CRYPTO_DRIVER_INTERFACE_XOF_VERSION_MAJOR 0

/**
 * The minor version of this implementation of the PSA Crypto Driver Interface
 */
#define PSA_CRYPTO_DRIVER_INTERFACE_XOF_VERSION_MINOR 0


typedef struct {
#if defined(PSA_NEED_OBERON_SHAKE128) || defined(PSA_NEED_OBERON_SHAKE256)
    uint64_t ctx[27];
#else /* defined(PSA_NEED_OBERON_ASCON_XOF128) */
    uint64_t ctx[6];
#endif
    psa_algorithm_t alg;
    uint8_t context;
    uint8_t squeeze;
} oberon_xof_operation_t;


psa_status_t oberon_xof_setup(
    oberon_xof_operation_t *operation,
    psa_algorithm_t alg);

psa_status_t oberon_xof_set_context(
    oberon_xof_operation_t *operation,
    const uint8_t *context, size_t context_length);

psa_status_t oberon_xof_update(
    oberon_xof_operation_t *operation,
    const uint8_t *input, size_t input_length);

psa_status_t oberon_xof_output(
    oberon_xof_operation_t *operation,
    uint8_t *output, size_t output_length);

psa_status_t oberon_xof_abort(
    oberon_xof_operation_t *operation);


#ifdef __cplusplus
}
#endif

#endif
