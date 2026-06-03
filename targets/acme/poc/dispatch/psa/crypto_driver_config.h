//
// Copyright Oberon microsystems AG, Switzerland.
// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
//

#ifndef PSA_CRYPTO_DRIVER_CONFIG_H
#define PSA_CRYPTO_DRIVER_CONFIG_H


#if defined(MBEDTLS_PSA_CRYPTO_CONFIG_FILE)
#include MBEDTLS_PSA_CRYPTO_CONFIG_FILE
#else
#include "psa/crypto_config.h"
#endif

/* RNG Demo Driver */

#if defined(PSA_WANT_GENERATE_RANDOM)
    #if defined(PSA_USE_ACME_RNG_DRIVER)
        #define PSA_NEED_ACME_RNG_DRIVER 1
        #include "acme_driver_config.h"
    #endif
#endif // defined(PSA_WANT_GENERATE_RANDOM)

#endif /* PSA_CRYPTO_DRIVER_CONFIG_H */
