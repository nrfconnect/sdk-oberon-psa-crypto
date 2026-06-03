//
// Copyright Oberon microsystems AG, Switzerland.
// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
//

/*
 * Please note: this simple configuration helper is provided for demonstration. 
 */ 

#ifndef DEMO_DRIVER_CONFIG_H
#define DEMO_DRIVER_CONFIG_H

#include "psa/crypto_driver_config.h"


/* RNG Demo Driver */

#if defined(PSA_WANT_GENERATE_RANDOM)
    #if defined(PSA_USE_ACME_RNG_DRIVER)
        #define PSA_NEED_ACME_RNG_DRIVER 1
    #endif
#endif // defined(PSA_WANT_GENERATE_RANDOM)


/* SHA Demo Driver */

#if defined(PSA_WANT_ALG_SHA_1)
#define PSA_NEED_ACME_SHA_DRIVER 1
#endif

#if defined(PSA_WANT_ALG_SHA_224)
#define PSA_NEED_ACME_SHA_DRIVER 1
#endif

#if defined(PSA_WANT_ALG_SHA_256)
#define PSA_NEED_ACME_SHA_DRIVER 1
#endif


/* AES Demo Driver */

#if defined(PSA_WANT_ALG_CTR)
#define PSA_NEED_ACME_AES_DRIVER 1
#endif

#if defined(PSA_WANT_ALG_CCM_STAR_NO_TAG)
#define PSA_NEED_ACME_AES_DRIVER 1
#endif


/* HMAC Demo Driver */

#if defined(PSA_WANT_ALG_HMAC)
#define PSA_NEED_ACME_MAC_DRIVER 1
#endif


/* HKDF Demo Driver */

#if defined(PSA_WANT_ALG_HKDF)
#define PSA_NEED_ACME_KDF_DRIVER 1
#endif


#endif /* DEMO_DRIVER_CONFIG_H */
