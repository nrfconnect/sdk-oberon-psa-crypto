/**
 * \file psa/crypto_config.h
 * \brief PSA crypto configuration options (set of defines)
 *
 */
/**
 * To enable a cryptographic mechanism, uncomment the definition of
 * the corresponding \c PSA_WANT_xxx preprocessor symbol.
 * To disable a cryptographic mechanism, comment out the definition of
 * the corresponding \c PSA_WANT_xxx preprocessor symbol.
 * The names of cryptographic mechanisms correspond to values
 * defined in psa/crypto_values.h, with the prefix \c PSA_WANT_ instead
 * of \c PSA_.
 *
 * Note that many cryptographic mechanisms involve two symbols: one for
 * the key type (\c PSA_WANT_KEY_TYPE_xxx) and one for the algorithm
 * (\c PSA_WANT_ALG_xxx). Mechanisms with additional parameters may involve
 * additional symbols.
 */

/*
 *  Copyright The Mbed TLS Contributors
 *  SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
 */

/*
 * NOTICE: This file has been modified by Oberon microsystems AG.
 */

#ifndef PSA_CRYPTO_CONFIG_H
#define PSA_CRYPTO_CONFIG_H

//#define PSA_WANT_ALG_CBC_NO_PADDING             1
//#define PSA_WANT_ALG_CBC_PKCS7                  1
#define PSA_WANT_ALG_CCM                        1
#define PSA_WANT_ALG_CCM_STAR_NO_TAG            1
//#define PSA_WANT_ALG_CHACHA20_POLY1305          1
//#define PSA_WANT_ALG_CMAC                       1
//#define PSA_WANT_ALG_CTR                        1
#define PSA_WANT_ALG_DETERMINISTIC_ECDSA        1
#define PSA_WANT_ALG_ECB_NO_PADDING             1
#define PSA_WANT_ALG_ECDH                       1
#define PSA_WANT_ALG_ECDSA                      1
//#define PSA_WANT_ALG_GCM                        1
//#define PSA_WANT_ALG_HKDF                       1
//#define PSA_WANT_ALG_HKDF_EXTRACT               1
//#define PSA_WANT_ALG_HKDF_EXPAND                1
#define PSA_WANT_ALG_HMAC                       1
//#define PSA_WANT_ALG_JPAKE                      1
//#define PSA_WANT_ALG_PBKDF2_HMAC                1
//#define PSA_WANT_ALG_PBKDF2_AES_CMAC_PRF_128    1
//#define PSA_WANT_ALG_PURE_EDDSA                 1
//#define PSA_WANT_ALG_ED25519PH                  1
//#define PSA_WANT_ALG_ED448PH                    1
//#define PSA_WANT_ALG_RSA_OAEP                   1
//#define PSA_WANT_ALG_RSA_PKCS1V15_CRYPT         1
//#define PSA_WANT_ALG_RSA_PKCS1V15_SIGN          1
//#define PSA_WANT_ALG_RSA_PSS                    1
//#define PSA_WANT_ALG_SHA_1                      1
//#define PSA_WANT_ALG_SHA_224                    1
#define PSA_WANT_ALG_SHA_256                    1
//#define PSA_WANT_ALG_SHA_384                    1
//#define PSA_WANT_ALG_SHA_512                    1
//#define PSA_WANT_ALG_SHA3_224                   1
//#define PSA_WANT_ALG_SHA3_256                   1
//#define PSA_WANT_ALG_SHA3_384                   1
//#define PSA_WANT_ALG_SHA3_512                   1
//#define PSA_WANT_ALG_SHAKE256_512               1
//#define PSA_WANT_ALG_SPAKE2P_HMAC               1
//#define PSA_WANT_ALG_SPAKE2P_CMAC               1
//#define PSA_WANT_ALG_SPAKE2P_MATTER             1
//#define PSA_WANT_ALG_SRP_6                      1
//#define PSA_WANT_ALG_SRP_PASSWORD_HASH          1
//#define PSA_WANT_ALG_STREAM_CIPHER              1
//#define PSA_WANT_ALG_TLS12_ECJPAKE_TO_PMS       1
//#define PSA_WANT_ALG_TLS12_PRF                  1
//#define PSA_WANT_ALG_TLS12_PSK_TO_MS            1
//#define PSA_WANT_ALG_SP800_108_COUNTER_HMAC     1
//#define PSA_WANT_ALG_SP800_108_COUNTER_CMAC     1
//#define PSA_WANT_ALG_AES_KW                     1
//#define PSA_WANT_ALG_AES_KWP                    1
//#define PSA_WANT_ALG_WPA3_SAE                   1
//#define PSA_WANT_ALG_WPA3_SAE_PT                1

//#define PSA_WANT_ECC_MONTGOMERY_255             1
//#define PSA_WANT_ECC_MONTGOMERY_448             1
//#define PSA_WANT_ECC_TWISTED_EDWARDS_255        1
//#define PSA_WANT_ECC_TWISTED_EDWARDS_448        1
//#define PSA_WANT_ECC_SECP_R1_224                1
#define PSA_WANT_ECC_SECP_R1_256                1
//#define PSA_WANT_ECC_SECP_R1_384                1
//#define PSA_WANT_ECC_SECP_R1_521                1

#define PSA_WANT_KEY_TYPE_DERIVE                1
//#define PSA_WANT_KEY_TYPE_PASSWORD              1
//#define PSA_WANT_KEY_TYPE_PASSWORD_HASH         1
#define PSA_WANT_KEY_TYPE_HMAC                  1
#define PSA_WANT_KEY_TYPE_AES                   1
//#define PSA_WANT_KEY_TYPE_CHACHA20              1
//#define PSA_WANT_KEY_TYPE_ECC_KEY_PAIR          1 /* Deprecated */
#define PSA_WANT_KEY_TYPE_ECC_PUBLIC_KEY        1
#define PSA_WANT_KEY_TYPE_RAW_DATA              1
//#define PSA_WANT_KEY_TYPE_RSA_KEY_PAIR          1 /* Deprecated */
//#define PSA_WANT_KEY_TYPE_RSA_PUBLIC_KEY        1
//#define PSA_WANT_KEY_TYPE_SPAKE2P_PUBLIC_KEY    1
//#define PSA_WANT_KEY_TYPE_SRP_PUBLIC_KEY        1
//#define PSA_WANT_KEY_TYPE_WPA3_SAE_PT           1

#define PSA_WANT_KEY_TYPE_ECC_KEY_PAIR_BASIC    1
#define PSA_WANT_KEY_TYPE_ECC_KEY_PAIR_IMPORT   1
#define PSA_WANT_KEY_TYPE_ECC_KEY_PAIR_EXPORT   1
#define PSA_WANT_KEY_TYPE_ECC_KEY_PAIR_GENERATE 1
//#define PSA_WANT_KEY_TYPE_ECC_KEY_PAIR_DERIVE   1

//#define PSA_WANT_KEY_TYPE_RSA_KEY_PAIR_BASIC    1
//#define PSA_WANT_KEY_TYPE_RSA_KEY_PAIR_IMPORT   1
//#define PSA_WANT_KEY_TYPE_RSA_KEY_PAIR_EXPORT   1

//#define PSA_WANT_KEY_TYPE_SPAKE2P_KEY_PAIR_BASIC  1
//#define PSA_WANT_KEY_TYPE_SPAKE2P_KEY_PAIR_IMPORT 1
//#define PSA_WANT_KEY_TYPE_SPAKE2P_KEY_PAIR_EXPORT 1
//#define PSA_WANT_KEY_TYPE_SPAKE2P_KEY_PAIR_DERIVE 1

//#define PSA_WANT_KEY_TYPE_SRP_KEY_PAIR_BASIC    1
//#define PSA_WANT_KEY_TYPE_SRP_KEY_PAIR_IMPORT   1
//#define PSA_WANT_KEY_TYPE_SRP_KEY_PAIR_EXPORT   1
//#define PSA_WANT_KEY_TYPE_SRP_KEY_PAIR_DERIVE   1

// Additional AES key size option
#define PSA_WANT_AES_KEY_SIZE_128               1
//#define PSA_WANT_AES_KEY_SIZE_192               1
//#define PSA_WANT_AES_KEY_SIZE_256               1

// Additional RSA key size option
//#define PSA_WANT_RSA_KEY_SIZE_1024              1
//#define PSA_WANT_RSA_KEY_SIZE_1536              1
//#define PSA_WANT_RSA_KEY_SIZE_2048              1
//#define PSA_WANT_RSA_KEY_SIZE_3072              1
//#define PSA_WANT_RSA_KEY_SIZE_4096              1
//#define PSA_WANT_RSA_KEY_SIZE_6144              1
//#define PSA_WANT_RSA_KEY_SIZE_8192              1

// Additional configuration option
#define PSA_WANT_GENERATE_RANDOM                1

// Moved from mbedtls_config.h
#define MBEDTLS_PSA_KEY_SLOT_COUNT              2
#define MBEDTLS_PSA_STATIC_KEY_SLOT_BUFFER_SIZE 256


/* Driver usage configuration */

//#define PSA_USE_CTR_DRBG_DRIVER                 1
#define PSA_USE_HMAC_DRBG_DRIVER                1

/* Hardware driver demonstration */
#define PSA_USE_DEMO_ENTROPY_DRIVER             1
//#define PSA_USE_DEMO_HARDWARE_DRIVER            1
//#define PSA_USE_DEMO_OPAQUE_DRIVER              1


#endif /* PSA_CRYPTO_CONFIG_H */
