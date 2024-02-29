/*
 *  Declaration of context structures for use with the PSA driver wrapper
 *  interface. This file contains the context structures for key derivation
 *  operations and extends crypto_driver_contexts_composites.h
 *
 * \note This file may not be included directly. Applications must
 * include psa/crypto.h.
 *
 * \note This header and its content are not part of the PSA Crypto API and
 * applications must not depend on it. Their main purpose is to define the
 * multi-part state objects of the PSA drivers included in the cryptographic
 * library. The definition of these objects are then used by crypto_struct.h
 * to define the implementation-defined types of PSA multi-part state objects.
 */
/*  Copyright The Mbed TLS Contributors
 *  SPDX-License-Identifier: Apache-2.0
 *
 *  Licensed under the Apache License, Version 2.0 (the "License"); you may
 *  not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 *  WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */

/*
 * NOTICE: This file has been modified by Oberon microsystems AG.
 */

#ifndef PSA_CRYPTO_DRIVER_CONTEXTS_KEY_DERIVATION_H
#define PSA_CRYPTO_DRIVER_CONTEXTS_KEY_DERIVATION_H

#include "psa/crypto_driver_common.h"

/* Include the context structure definitions for enabled drivers. */

#ifdef PSA_NEED_OBERON_KEY_DERIVATION_DRIVER
#include "oberon_key_derivation.h"
#endif
#ifdef PSA_NEED_OBERON_PAKE_DRIVER
#include "oberon_pake.h"
#endif
#ifdef PSA_NEED_OBERON_CTR_DRBG_DRIVER
#include "oberon_ctr_drbg.h"
#endif
#ifdef PSA_NEED_OBERON_HMAC_DRBG_DRIVER
#include "oberon_hmac_drbg.h"
#endif

/* Define the context to be used for an operation that is executed through the
 * PSA Driver wrapper layer as the union of all possible drivers' contexts.
 *
 * The union members are the driver's context structures, and the member names
 * are formatted as `'drivername'_ctx`. */

typedef union {
    unsigned dummy; /* Make sure this union is always non-empty */
#ifdef PSA_NEED_OBERON_KEY_DERIVATION_DRIVER
    oberon_key_derivation_operation_t oberon_kdf_ctx;
#endif
} psa_driver_key_derivation_context_t;

typedef union {
    unsigned dummy; /* Make sure this union is always non-empty */
#ifdef PSA_NEED_OBERON_PAKE_DRIVER
    oberon_pake_operation_t oberon_pake_ctx;
#endif
} psa_driver_pake_context_t;

typedef union {
    unsigned dummy; /* Make sure this union is always non-empty */
#ifdef PSA_NEED_OBERON_CTR_DRBG_DRIVER
    oberon_ctr_drbg_context_t oberon_ctr_drbg_ctx;
#endif
#ifdef PSA_NEED_OBERON_HMAC_DRBG_DRIVER
    oberon_hmac_drbg_context_t oberon_hmac_drbg_ctx;
#endif
} psa_driver_random_context_t;

#endif /* PSA_CRYPTO_DRIVER_CONTEXTS_KEY_DERIVATION_H */
