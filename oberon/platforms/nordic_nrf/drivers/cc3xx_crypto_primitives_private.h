/*
 * Copyright (c) 2016 - 2024 Nordic Semiconductor ASA
 * Copyright (c) since 2020 Oberon microsystems AG
 *
 * SPDX-License-Identifier: LicenseRef-Nordic-5-Clause
 */

//
// This file implements functions from the Arm PSA Crypto Driver API.

#ifndef CC3XX_CRYPTO_PRIMITIVES_PRIVATE_H
#define CC3XX_CRYPTO_PRIMITIVES_PRIVATE_H

#include "cc3xx_crypto_primitives.h"
#include <psa/crypto_driver_common.h>


#ifdef __cplusplus
extern "C" {
#endif


struct cc3xx_hash_operation_s {
    uint64_t ctx[52];
    psa_algorithm_t alg;
};

struct cc3xx_cipher_operation_s {
    uint32_t ctx[70];
    psa_algorithm_t alg;
    uint8_t decrypt;
};

struct cc3xx_aead_operation_s {
    struct {
        uint32_t a[77];
        size_t s[2];
    } ctx;
    size_t ad_length;
    size_t pt_length;
    psa_algorithm_t alg;
    uint8_t decrypt;
    uint8_t length_set;
    uint8_t tag_length;
};

typedef enum {
    CC3XX_HMAC_ALG = 1,
    CC3XX_CMAC_ALG = 2,
} cc3xx_mac_alg;

typedef struct {
    struct cc3xx_hash_operation_s hash_op;
    psa_algorithm_t hash_alg;
    uint8_t hash[PSA_HASH_MAX_SIZE];
    uint8_t k[PSA_HMAC_MAX_HASH_BLOCK_SIZE];
    uint8_t block_size;
} cc3xx_hmac_operation_t;

typedef struct {
    struct cc3xx_cipher_operation_s aes_op;
    uint8_t block[PSA_BLOCK_CIPHER_BLOCK_MAX_SIZE];
    uint8_t k[PSA_BLOCK_CIPHER_BLOCK_MAX_SIZE];
    size_t length;
} cc3xx_cmac_operation_t;

struct cc3xx_mac_operation_s {
    union {
        cc3xx_hmac_operation_t hmac;
        cc3xx_cmac_operation_t cmac;
    };
    cc3xx_mac_alg alg;
};


#ifdef __cplusplus
}
#endif

#endif /* CC3XX_CRYPTO_PRIMITIVES_PRIVATE_H */
