/*
 *  Copyright The Mbed TLS Contributors
 *  SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
 */

#ifndef PSA_CRYPTO_DRIVER_CONFIG_H
#define PSA_CRYPTO_DRIVER_CONFIG_H


#if defined(MBEDTLS_PSA_CRYPTO_CONFIG_FILE)
#include MBEDTLS_PSA_CRYPTO_CONFIG_FILE
#else
#include "psa/crypto_config.h"
#endif

#include "cc3xx_psa_config.h"
#if defined(PSA_USE_DEMO_ENTROPY_DRIVER) || \
    defined(PSA_USE_DEMO_HARDWARE_DRIVER) || \
    defined(PSA_USE_DEMO_OPAQUE_DRIVER)
#include "demo_driver_config.h"
#endif

#endif /* PSA_CRYPTO_DRIVER_CONFIG_H */
