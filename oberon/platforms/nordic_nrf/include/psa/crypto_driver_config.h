/*
 * Copyright (c) 2016 - 2024 Nordic Semiconductor ASA
 * Copyright (c) since 2020 Oberon microsystems AG
 *
 * SPDX-License-Identifier: LicenseRef-Nordic-5-Clause
 */


#ifndef PSA_CRYPTO_DRIVER_CONFIG_H
#define PSA_CRYPTO_DRIVER_CONFIG_H


#if defined(MBEDTLS_PSA_CRYPTO_CONFIG_FILE)
#include MBEDTLS_PSA_CRYPTO_CONFIG_FILE
#else
#include "psa/crypto_config.h"
#endif

#include "cc3xx_psa_config.h"
#include "demo_driver_config.h"


#endif /* PSA_CRYPTO_DRIVER_CONFIG_H */
