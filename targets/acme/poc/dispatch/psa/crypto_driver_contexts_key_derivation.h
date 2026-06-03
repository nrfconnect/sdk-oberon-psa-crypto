/*
 *  Declaration of context structures for use with the PSA driver wrapper
 *  interface. This file contains the context structures for key derivation
 *  operations.
 *
 * \note This file may not be included directly. Applications must
 * include psa/crypto.h.
 *
 * \note This header and its content are not part of the PSA Crypto API and
 * applications must not depend on it. Its main purpose is to define the
 * multi-part state objects of the PSA drivers included in the cryptographic
 * library. The definitions of these objects are then used by crypto_struct.h
 * to define the implementation-defined types of PSA multi-part state objects.
 */
/*  Copyright The Mbed TLS Contributors
 *  SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
 */

/*
 * NOTICE: This file has been modified by Oberon microsystems AG.
 */

#ifndef PSA_CRYPTO_DRIVER_CONTEXTS_KEY_DERIVATION_H
#define PSA_CRYPTO_DRIVER_CONTEXTS_KEY_DERIVATION_H

#include "psa/crypto_driver_common.h"

/* Include the context structure definitions for enabled drivers. */

#ifdef PSA_NEED_ACME_RNG_DRIVER
#include "acme_rng.h"
#endif
#ifdef PSA_NEED_ACME_KDF_DRIVER
#include "acme_kdf.h"
#endif

// add driver specific includes here

/* Define the context to be used for an operation that is executed through the
 * PSA Driver wrapper layer as the union of all possible drivers' contexts.
 *
 * The union members are the driver's context structures, and the member names
 * are formatted as `'drivername'_ctx`. */

typedef union {
    unsigned dummy; /* Make sure this union is always non-empty */
    // add driver specific types here
#ifdef PSA_NEED_ACME_KDF_DRIVER
    acme_key_derivation_operation_t acme_kdf_ctx;
#endif
} psa_driver_key_derivation_context_t;

typedef union {
    unsigned dummy; /* Make sure this union is always non-empty */
    // add driver specific types here
} psa_driver_pake_context_t;

typedef union {
    unsigned dummy; /* Make sure this union is always non-empty */
    // add driver specific types here
#ifdef PSA_NEED_ACME_RNG_DRIVER
    acme_rng_context_t acme_rng_ctx;
#endif
} psa_driver_random_context_t;

#endif /* PSA_CRYPTO_DRIVER_CONTEXTS_KEY_DERIVATION_H */
