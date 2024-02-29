/*
 * Copyright (c) 2016 - 2024 Nordic Semiconductor ASA
 * Copyright (c) since 2020 Oberon microsystems AG
 *
 * SPDX-License-Identifier: LicenseRef-Nordic-5-Clause
 */


#ifndef DEMO_DRIVER_CONFIG_H
#define DEMO_DRIVER_CONFIG_H

#include "psa/crypto_driver_config.h"


/* Opaque Demo Driver */

#if defined(PSA_USE_DEMO_OPAQUE_DRIVER)
#define PSA_NEED_OPAQUE_DEMO_DRIVER 1
#endif


/* Entropy Demo Driver */

#if defined(PSA_USE_DEMO_ENTROPY_DRIVER)
#define PSA_NEED_ENTROPY_DEMO_DRIVER 1
#define PSA_ACCEL_GET_ENTROPY 1
#endif


/* Hardware Demo Driver */

#if defined(PSA_WANT_ALG_SHA_1) && defined(PSA_USE_DEMO_HARDWARE_DRIVER)
#define PSA_NEED_HARDWARE_DEMO_DRIVER 1
#define PSA_ACCEL_SHA_1 1
#endif

#if defined(PSA_WANT_ALG_SHA_224) && defined(PSA_USE_DEMO_HARDWARE_DRIVER)
#define PSA_NEED_HARDWARE_DEMO_DRIVER 1
#define PSA_ACCEL_SHA_224 1
#endif

#if defined(PSA_WANT_ALG_SHA_256) && defined(PSA_USE_DEMO_HARDWARE_DRIVER)
#define PSA_NEED_HARDWARE_DEMO_DRIVER 1
#define PSA_ACCEL_SHA_256 1
#endif

#if defined(PSA_WANT_ALG_CTR) && defined(PSA_USE_DEMO_HARDWARE_DRIVER)
#define PSA_NEED_HARDWARE_DEMO_DRIVER 1
#define PSA_ACCEL_CTR_AES_128 1
#endif

#if defined(PSA_WANT_ALG_CCM_STAR_NO_TAG) && defined(PSA_USE_DEMO_HARDWARE_DRIVER)
#define PSA_NEED_HARDWARE_DEMO_DRIVER 1
#define PSA_ACCEL_CCM_STAR_NO_TAG_AES_128 1
#endif


#endif /* DEMO_DRIVER_CONFIG_H */
