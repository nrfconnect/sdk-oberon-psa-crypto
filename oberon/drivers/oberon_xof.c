/*
 * Copyright (c) 2016 - 2025 Nordic Semiconductor ASA
 * Copyright (c) since 2020 Oberon microsystems AG
 *
 * SPDX-License-Identifier: LicenseRef-Nordic-5-Clause
 */

//
// This file implements functions from the Arm PSA Crypto Driver API.

#include <string.h>

#include "psa/crypto.h"
#include "oberon_xof.h"

#if defined(PSA_NEED_OBERON_SHAKE128) || defined(PSA_NEED_OBERON_SHAKE256)
#include "ocrypto_shake.h"
#endif
#if defined(PSA_NEED_OBERON_ASCON_XOF128)
#include "ocrypto_ascon_hash.h"
#endif


psa_status_t oberon_xof_setup(
    oberon_xof_operation_t *operation,
    psa_algorithm_t alg)
{
    switch (alg) {
#ifdef PSA_NEED_OBERON_SHAKE128
    _Static_assert(sizeof operation->ctx >= sizeof(ocrypto_shake_ctx), "oberon_xof_operation_t.ctx too small");
    case PSA_ALG_SHAKE128:
        ocrypto_shake_init((ocrypto_shake_ctx*)operation->ctx);
        break;
#endif
#ifdef PSA_NEED_OBERON_SHAKE256
    _Static_assert(sizeof operation->ctx >= sizeof(ocrypto_shake_ctx), "oberon_xof_operation_t.ctx too small");
    case PSA_ALG_SHAKE256:
        ocrypto_shake_init((ocrypto_shake_ctx*)operation->ctx);
        break;
#endif
#ifdef PSA_NEED_OBERON_ASCON_XOF128
    _Static_assert(sizeof operation->ctx >= sizeof(ocrypto_ascon_hash_ctx), "oberon_xof_operation_t.ctx too small");
    case PSA_ALG_ASCON_XOF128:
        ocrypto_ascon_xof128_init((ocrypto_ascon_hash_ctx*)operation->ctx);
        break;
#endif
#ifdef PSA_NEED_OBERON_ASCON_CXOF128
    _Static_assert(sizeof operation->ctx >= sizeof(ocrypto_ascon_hash_ctx), "oberon_xof_operation_t.ctx too small");
    case PSA_ALG_ASCON_CXOF128:
        break;
#endif
    default:
        return PSA_ERROR_NOT_SUPPORTED;
    }

    operation->alg = alg;
    return PSA_SUCCESS;
}

psa_status_t oberon_xof_set_context(
    oberon_xof_operation_t *operation,
    const uint8_t *context, size_t context_length)
{
    switch (operation->alg) {
#ifdef PSA_NEED_OBERON_ASCON_CXOF128
    case PSA_ALG_ASCON_CXOF128:
        ocrypto_ascon_cxof128_init((ocrypto_ascon_hash_ctx*)operation->ctx, context, context_length);
        operation->context = 1;
        break;
#endif
    default:
        (void)context;
        (void)context_length;
        return PSA_ERROR_NOT_SUPPORTED;
    }

    return PSA_SUCCESS;
}

psa_status_t oberon_xof_update(
    oberon_xof_operation_t *operation,
    const uint8_t *input, size_t input_length)
{
    switch (operation->alg) {
#ifdef PSA_NEED_OBERON_SHAKE128
    case PSA_ALG_SHAKE128:
        ocrypto_shake128_update((ocrypto_shake_ctx*)operation->ctx, input, input_length);
        break;
#endif
#ifdef PSA_NEED_OBERON_SHAKE256
    case PSA_ALG_SHAKE256:
        ocrypto_shake256_update((ocrypto_shake_ctx*)operation->ctx, input, input_length);
        break;
#endif
#ifdef PSA_NEED_OBERON_ASCON_XOF128
    case PSA_ALG_ASCON_XOF128:
        ocrypto_ascon_hash256_update((ocrypto_ascon_hash_ctx*)operation->ctx, input, input_length);
        break;
#endif
#ifdef PSA_NEED_OBERON_ASCON_CXOF128
    case PSA_ALG_ASCON_CXOF128:
        if (!operation->context) {
            ocrypto_ascon_cxof128_init((ocrypto_ascon_hash_ctx*)operation->ctx, NULL, 0);
            operation->context = 1;
        }
        ocrypto_ascon_hash256_update((ocrypto_ascon_hash_ctx*)operation->ctx, input, input_length);
        break;
#endif
    default:
        (void)input;
        (void)input_length;
        return PSA_ERROR_NOT_SUPPORTED;
    }

    return PSA_SUCCESS;
}

psa_status_t oberon_xof_output(
    oberon_xof_operation_t *operation,
    uint8_t *output, size_t output_length)
{
    switch (operation->alg) {
#ifdef PSA_NEED_OBERON_SHAKE128
    case PSA_ALG_SHAKE128:
        if (operation->squeeze) {
            ocrypto_shake128_ext((ocrypto_shake_ctx*)operation->ctx, output, output_length);
        } else {
            ocrypto_shake128_final((ocrypto_shake_ctx *)operation->ctx, output, output_length);
            operation->squeeze = 1;
        }
        break;
#endif
#ifdef PSA_NEED_OBERON_SHAKE256
    case PSA_ALG_SHAKE256:
        if (operation->squeeze) {
            ocrypto_shake256_ext((ocrypto_shake_ctx*)operation->ctx, output, output_length);
        } else {
            ocrypto_shake256_final((ocrypto_shake_ctx*)operation->ctx, output, output_length);
            operation->squeeze = 1;
        }
        break;
#endif
#ifdef PSA_NEED_OBERON_ASCON_XOF128
    case PSA_ALG_ASCON_XOF128:
        if (operation->squeeze) {
            ocrypto_ascon_xof128_ext((ocrypto_ascon_hash_ctx*)operation->ctx, output, output_length);
        } else {
            ocrypto_ascon_xof128_final((ocrypto_ascon_hash_ctx*)operation->ctx, output, output_length);
            operation->squeeze = 1;
        }
        break;
#endif
#ifdef PSA_NEED_OBERON_ASCON_CXOF128
    case PSA_ALG_ASCON_CXOF128:
        if (operation->squeeze) {
            ocrypto_ascon_xof128_ext((ocrypto_ascon_hash_ctx*)operation->ctx, output, output_length);
        } else {
            if (!operation->context) {
                ocrypto_ascon_cxof128_init((ocrypto_ascon_hash_ctx*)operation->ctx, NULL, 0);
            }
            ocrypto_ascon_xof128_final((ocrypto_ascon_hash_ctx*)operation->ctx, output, output_length);
            operation->squeeze = 1;
        }
        break;
#endif
    default:
        (void)output;
        (void)output_length;
        return PSA_ERROR_NOT_SUPPORTED;
    }

    return PSA_SUCCESS;
}

psa_status_t oberon_xof_abort(
    oberon_xof_operation_t *operation)
{
    memset(operation, 0, sizeof *operation);
    return PSA_SUCCESS;
}
