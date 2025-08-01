/*
 * Copyright (c) 2016 - 2025 Nordic Semiconductor ASA
 * Copyright (c) since 2020 Oberon microsystems AG
 *
 * SPDX-License-Identifier: LicenseRef-Nordic-5-Clause
 */


#ifndef CC3XX_PSA_CONFIG_H
#define CC3XX_PSA_CONFIG_H

#include "psa/crypto_driver_config.h"

/* CC3xx AEAD Driver */

#if defined(PSA_WANT_KEY_TYPE_AES) && defined(PSA_WANT_ALG_CCM) && defined(PSA_USE_CC3XX_AEAD_DRIVER)
    #define PSA_NEED_CC3XX_AEAD_DRIVER 1
    #define PSA_NEED_CC3XX_CCM_AES 1
    #define PSA_ACCEL_CCM_AES_128 1
    #define PSA_ACCEL_CCM_AES_192 1
    #define PSA_ACCEL_CCM_AES_256 1
#endif

#if defined(PSA_WANT_KEY_TYPE_AES) && defined(PSA_WANT_ALG_GCM) && defined(PSA_USE_CC3XX_AEAD_DRIVER)
    #define PSA_NEED_CC3XX_AEAD_DRIVER 1
    #define PSA_NEED_CC3XX_GCM_AES 1
    #define PSA_ACCEL_GCM_AES_128 1
    #define PSA_ACCEL_GCM_AES_192 1
    #define PSA_ACCEL_GCM_AES_256 1
#endif

#if defined(PSA_WANT_ALG_CHACHA20_POLY1305) && defined(PSA_USE_CC3XX_AEAD_DRIVER)
    #define PSA_NEED_CC3XX_AEAD_DRIVER 1
    #define PSA_NEED_CC3XX_CHACHA20_POLY1305 1
    #define PSA_ACCEL_CHACHA20_POLY1305 1
#endif

/* CC3xx Cipher Driver */

#if defined(PSA_WANT_KEY_TYPE_AES) && defined(PSA_WANT_ALG_CTR) && defined(PSA_USE_CC3XX_CIPHER_DRIVER)
    #define PSA_NEED_CC3XX_CIPHER_DRIVER 1
    #define PSA_NEED_CC3XX_CTR_AES 1
    #define PSA_ACCEL_CTR_AES_128 1
    #define PSA_ACCEL_CTR_AES_192 1
    #define PSA_ACCEL_CTR_AES_256 1
#endif

#if defined(PSA_WANT_KEY_TYPE_AES) && defined(PSA_WANT_ALG_CBC_PKCS7) && defined(PSA_USE_CC3XX_CIPHER_DRIVER)
    #define PSA_NEED_CC3XX_CIPHER_DRIVER 1
    #define PSA_NEED_CC3XX_CBC_PKCS7_AES 1
    #define PSA_ACCEL_CBC_PKCS7_AES_128 1
    #define PSA_ACCEL_CBC_PKCS7_AES_192 1
    #define PSA_ACCEL_CBC_PKCS7_AES_256 1
#endif

#if defined(PSA_WANT_KEY_TYPE_AES) && defined(PSA_WANT_ALG_CBC_NO_PADDING) && defined(PSA_USE_CC3XX_CIPHER_DRIVER)
    #define PSA_NEED_CC3XX_CIPHER_DRIVER 1
    #define PSA_NEED_CC3XX_CBC_NO_PADDING_AES 1
    #define PSA_ACCEL_CBC_NO_PADDING_AES_128 1
    #define PSA_ACCEL_CBC_NO_PADDING_AES_192 1
    #define PSA_ACCEL_CBC_NO_PADDING_AES_256 1
#endif

#if defined(PSA_WANT_KEY_TYPE_AES) && defined(PSA_WANT_ALG_ECB_NO_PADDING) && defined(PSA_USE_CC3XX_CIPHER_DRIVER)
    #define PSA_NEED_CC3XX_CIPHER_DRIVER 1
    #define PSA_NEED_CC3XX_ECB_NO_PADDING_AES 1
    #define PSA_ACCEL_ECB_NO_PADDING_AES_128 1
    #define PSA_ACCEL_ECB_NO_PADDING_AES_192 1
    #define PSA_ACCEL_ECB_NO_PADDING_AES_256 1
#endif

#if defined(PSA_WANT_KEY_TYPE_CHACHA20) && defined(PSA_WANT_ALG_STREAM_CIPHER) && defined(PSA_USE_CC3XX_CIPHER_DRIVER)
    #define PSA_NEED_CC3XX_CIPHER_DRIVER 1
    #define PSA_NEED_CC3XX_STREAM_CIPHER_CHACHA20 1
    #define PSA_ACCEL_STREAM_CIPHER_CHACHA20 1
#endif

/* CC3xx Key Agreement Driver */

#if defined(PSA_WANT_ALG_ECDH) && defined(PSA_WANT_ECC_SECP_R1_224) && defined(PSA_USE_CC3XX_KEY_AGREEMENT_DRIVER)
    #define PSA_NEED_CC3XX_KEY_AGREEMENT_DRIVER 1
    #define PSA_NEED_CC3XX_ECDH_SECP_R1_224 1
    #define PSA_ACCEL_ECDH_SECP_R1_224 1
#endif

#if defined(PSA_WANT_ALG_ECDH) && defined(PSA_WANT_ECC_SECP_R1_256) && defined(PSA_USE_CC3XX_KEY_AGREEMENT_DRIVER)
    #define PSA_NEED_CC3XX_KEY_AGREEMENT_DRIVER 1
    #define PSA_NEED_CC3XX_ECDH_SECP_R1_256 1
    #define PSA_ACCEL_ECDH_SECP_R1_256 1
#endif

// #if defined(PSA_WANT_ALG_ECDH) && defined(PSA_WANT_ECC_SECP_R1_384) && defined(PSA_USE_CC3XX_KEY_AGREEMENT_DRIVER)
//     #define PSA_NEED_CC3XX_KEY_AGREEMENT_DRIVER 1
//     #define PSA_NEED_CC3XX_ECDH_SECP_R1_384 1
//     #define PSA_ACCEL_ECDH_SECP_R1_384 1
// #endif

// #if defined(PSA_WANT_ALG_ECDH) && defined(PSA_WANT_ECC_SECP_R1_521) && defined(PSA_USE_CC3XX_KEY_AGREEMENT_DRIVER)
//     #define PSA_NEED_CC3XX_KEY_AGREEMENT_DRIVER 1
//     #define PSA_NEED_CC3XX_ECDH_SECP_R1_521 1
//     #define PSA_ACCEL_ECDH_SECP_R1_521 1
// #endif

#if defined(PSA_WANT_ALG_ECDH) && defined(PSA_WANT_ECC_MONTGOMERY_255) && defined(PSA_USE_CC3XX_KEY_AGREEMENT_DRIVER)
    #define PSA_NEED_CC3XX_KEY_AGREEMENT_DRIVER 1
    #define PSA_NEED_CC3XX_ECDH_MONTGOMERY_255 1
    #define PSA_ACCEL_ECDH_MONTGOMERY_255 1
#endif

/* CC3xx Asymmetric Signature Driver */

#if defined(PSA_WANT_ALG_ECDSA) || defined(PSA_WANT_ALG_DETERMINISTIC_ECDSA)
    #define PSA_WANT_ALG_ANY_ECDSA
#endif

#if defined(PSA_WANT_ALG_ANY_ECDSA) && defined(PSA_WANT_ECC_SECP_R1_224) && \
    defined(PSA_USE_CC3XX_ASYMMETRIC_SIGNATURE_DRIVER)
    #define PSA_NEED_CC3XX_ASYMMETRIC_SIGNATURE_DRIVER 1
    #define PSA_NEED_CC3XX_ECDSA_SECP_R1_224 1
    #define PSA_ACCEL_ECDSA_SECP_R1_224_SHA_224 1
    #define PSA_ACCEL_ECDSA_SECP_R1_224_SHA_256 1
#endif

#if defined(PSA_WANT_ALG_ANY_ECDSA) && defined(PSA_WANT_ECC_SECP_R1_256) && \
    defined(PSA_USE_CC3XX_ASYMMETRIC_SIGNATURE_DRIVER)
    #define PSA_NEED_CC3XX_ASYMMETRIC_SIGNATURE_DRIVER 1
    #define PSA_NEED_CC3XX_ECDSA_SECP_R1_256 1
    #define PSA_ACCEL_ECDSA_SECP_R1_256_SHA_224 1
    #define PSA_ACCEL_ECDSA_SECP_R1_256_SHA_256 1
#endif

/*
#if defined(PSA_WANT_ALG_ANY_ECDSA) && defined(PSA_WANT_ECC_SECP_R1_384) && \
    defined(PSA_USE_CC3XX_ASYMMETRIC_SIGNATURE_DRIVER)
    #define PSA_NEED_CC3XX_ASYMMETRIC_SIGNATURE_DRIVER 1
    #define PSA_NEED_CC3XX_ECDSA_SECP_R1_384 1
    #define PSA_ACCEL_ECDSA_SECP_R1_384_SHA_224 1
    #define PSA_ACCEL_ECDSA_SECP_R1_384_SHA_256 1
#endif

#if defined(PSA_WANT_ALG_ANY_ECDSA) && defined(PSA_WANT_ECC_SECP_R1_521) && \
    defined(PSA_USE_CC3XX_ASYMMETRIC_SIGNATURE_DRIVER)
    #define PSA_NEED_CC3XX_ASYMMETRIC_SIGNATURE_DRIVER 1
    #define PSA_NEED_CC3XX_ECDSA_SECP_R1_521 1
    #define PSA_ACCEL_ECDSA_SECP_R1_521_SHA_224 1
    #define PSA_ACCEL_ECDSA_SECP_R1_521_SHA_256 1
#endif
*/

#if defined(PSA_WANT_ALG_RSA_PKCS1V15_SIGN) && defined(PSA_USE_CC3XX_ASYMMETRIC_SIGNATURE_DRIVER)
    #define PSA_NEED_CC3XX_ASYMMETRIC_SIGNATURE_DRIVER 1
    #define PSA_NEED_CC3XX_RSA_PKCS1V15_SIGN 1
    #define PSA_ACCEL_RSA_PKCS1V15_SIGN_1024_SHA_224 1
    #define PSA_ACCEL_RSA_PKCS1V15_SIGN_1024_SHA_256 1
    #define PSA_ACCEL_RSA_PKCS1V15_SIGN_1536_SHA_224 1
    #define PSA_ACCEL_RSA_PKCS1V15_SIGN_1536_SHA_256 1
    #define PSA_ACCEL_RSA_PKCS1V15_SIGN_2048_SHA_224 1
    #define PSA_ACCEL_RSA_PKCS1V15_SIGN_2048_SHA_256 1
    #define PSA_ACCEL_RSA_PKCS1V15_SIGN_3072_SHA_224 1
    #define PSA_ACCEL_RSA_PKCS1V15_SIGN_3072_SHA_256 1
#endif

#if defined(PSA_WANT_ALG_RSA_PSS) && defined(PSA_USE_CC3XX_ASYMMETRIC_SIGNATURE_DRIVER)
    #define PSA_NEED_CC3XX_ASYMMETRIC_SIGNATURE_DRIVER 1
    #define PSA_NEED_CC3XX_RSA_PSS 1
    #define PSA_ACCEL_RSA_PSS_1024_SHA_224 1
    #define PSA_ACCEL_RSA_PSS_1024_SHA_256 1
    #define PSA_ACCEL_RSA_PSS_1536_SHA_224 1
    #define PSA_ACCEL_RSA_PSS_1536_SHA_256 1
    #define PSA_ACCEL_RSA_PSS_2048_SHA_224 1
    #define PSA_ACCEL_RSA_PSS_2048_SHA_256 1
    #define PSA_ACCEL_RSA_PSS_3072_SHA_224 1
    #define PSA_ACCEL_RSA_PSS_3072_SHA_256 1
#endif

/* CC3xx Asymmetric Encryption Driver */

#if defined(PSA_WANT_ALG_RSA_OAEP) && defined(PSA_USE_CC3XX_ASYMMETRIC_ENCRYPTION_DRIVER)
    #define PSA_NEED_CC3XX_ASYMMETRIC_ENCRYPTION_DRIVER 1
    #define PSA_NEED_CC3XX_RSA_OAEP 1
    #define PSA_ACCEL_RSA_OAEP_1024_SHA_224 1
    #define PSA_ACCEL_RSA_OAEP_1024_SHA_256 1
    #define PSA_ACCEL_RSA_OAEP_1536_SHA_224 1
    #define PSA_ACCEL_RSA_OAEP_1536_SHA_256 1
    #define PSA_ACCEL_RSA_OAEP_2048_SHA_224 1
    #define PSA_ACCEL_RSA_OAEP_2048_SHA_256 1
    #define PSA_ACCEL_RSA_OAEP_3072_SHA_224 1
    #define PSA_ACCEL_RSA_OAEP_3072_SHA_256 1
#endif

#if defined(PSA_WANT_ALG_RSA_PKCS1V15_CRYPT) && defined(PSA_USE_CC3XX_ASYMMETRIC_ENCRYPTION_DRIVER)
    #define PSA_NEED_CC3XX_ASYMMETRIC_ENCRYPTION_DRIVER 1
    #define PSA_NEED_CC3XX_RSA_PKCS1V15_CRYPT 1
    #define PSA_ACCEL_RSA_PKCS1V15_CRYPT_1024 1
    #define PSA_ACCEL_RSA_PKCS1V15_CRYPT_1536 1
    #define PSA_ACCEL_RSA_PKCS1V15_CRYPT_2048 1
    #define PSA_ACCEL_RSA_PKCS1V15_CRYPT_3072 1
#endif

/* CC3xx Hash Driver */

#if defined(PSA_WANT_ALG_SHA_1) && defined(PSA_USE_CC3XX_HASH_DRIVER)
    #define PSA_NEED_CC3XX_HASH_DRIVER 1
    #define PSA_NEED_CC3XX_SHA_1 1
    #define PSA_ACCEL_SHA_1 1
#endif

#if defined(PSA_WANT_ALG_SHA_224) && defined(PSA_USE_CC3XX_HASH_DRIVER)
    #define PSA_NEED_CC3XX_HASH_DRIVER 1
    #define PSA_NEED_CC3XX_SHA_224 1
    #define PSA_ACCEL_SHA_224 1
#endif

#if defined(PSA_WANT_ALG_SHA_256) && defined(PSA_USE_CC3XX_HASH_DRIVER)
    #define PSA_NEED_CC3XX_HASH_DRIVER 1
    #define PSA_NEED_CC3XX_SHA_256 1
    #define PSA_ACCEL_SHA_256 1
#endif

/* CC3xx Key Generation Driver */

#if defined(PSA_WANT_ECC_SECP_R1_224) && defined(PSA_USE_CC3XX_KEY_MANAGEMENT_DRIVER)
    #define PSA_NEED_CC3XX_KEY_MANAGEMENT_DRIVER 1
    #if defined(PSA_WANT_KEY_TYPE_ECC_KEY_PAIR_IMPORT)
        #define PSA_NEED_CC3XX_KEY_TYPE_ECC_KEY_PAIR_IMPORT_SECP 1
        #define PSA_NEED_CC3XX_KEY_TYPE_ECC_KEY_PAIR_IMPORT_SECP_R1_224 1
        #define PSA_ACCEL_KEY_TYPE_ECC_KEY_PAIR_IMPORT_SECP_R1_224 1
    #endif
    #if defined(PSA_WANT_KEY_TYPE_ECC_KEY_PAIR_EXPORT)
        #define PSA_NEED_CC3XX_KEY_TYPE_ECC_KEY_PAIR_EXPORT_SECP 1
        #define PSA_NEED_CC3XX_KEY_TYPE_ECC_KEY_PAIR_EXPORT_SECP_R1_224 1
        #define PSA_ACCEL_KEY_TYPE_ECC_KEY_PAIR_EXPORT_SECP_R1_224 1
    #endif
    #if defined(PSA_WANT_KEY_TYPE_ECC_KEY_PAIR_GENERATE)
        #define PSA_NEED_CC3XX_KEY_TYPE_ECC_KEY_PAIR_GENERATE_SECP 1
        #define PSA_NEED_CC3XX_KEY_TYPE_ECC_KEY_PAIR_GENERATE_SECP_R1_224 1
        #define PSA_ACCEL_KEY_TYPE_ECC_KEY_PAIR_GENERATE_SECP_R1_224 1
    #endif
    #if defined(PSA_WANT_KEY_TYPE_ECC_PUBLIC_KEY)
        #define PSA_NEED_CC3XX_KEY_TYPE_ECC_PUBLIC_KEY_SECP 1
        #define PSA_NEED_CC3XX_KEY_TYPE_ECC_PUBLIC_KEY_SECP_R1_224 1
        #define PSA_ACCEL_KEY_TYPE_ECC_PUBLIC_KEY_SECP_R1_224 1
    #endif
#endif

#if defined(PSA_WANT_ECC_SECP_R1_256) && defined(PSA_USE_CC3XX_KEY_MANAGEMENT_DRIVER)
    #define PSA_NEED_CC3XX_KEY_MANAGEMENT_DRIVER 1
    #if defined(PSA_WANT_KEY_TYPE_ECC_KEY_PAIR_IMPORT)
        #define PSA_NEED_CC3XX_KEY_TYPE_ECC_KEY_PAIR_IMPORT_SECP 1
        #define PSA_NEED_CC3XX_KEY_TYPE_ECC_KEY_PAIR_IMPORT_SECP_R1_256 1
        #define PSA_ACCEL_KEY_TYPE_ECC_KEY_PAIR_IMPORT_SECP_R1_256 1
    #endif
    #if defined(PSA_WANT_KEY_TYPE_ECC_KEY_PAIR_EXPORT)
        #define PSA_NEED_CC3XX_KEY_TYPE_ECC_KEY_PAIR_EXPORT_SECP 1
        #define PSA_NEED_CC3XX_KEY_TYPE_ECC_KEY_PAIR_EXPORT_SECP_R1_256 1
        #define PSA_ACCEL_KEY_TYPE_ECC_KEY_PAIR_EXPORT_SECP_R1_256 1
    #endif
    #if defined(PSA_WANT_KEY_TYPE_ECC_KEY_PAIR_GENERATE)
        #define PSA_NEED_CC3XX_KEY_TYPE_ECC_KEY_PAIR_GENERATE_SECP 1
        #define PSA_NEED_CC3XX_KEY_TYPE_ECC_KEY_PAIR_GENERATE_SECP_R1_256 1
        #define PSA_ACCEL_KEY_TYPE_ECC_KEY_PAIR_GENERATE_SECP_R1_256 1
    #endif
    #if defined(PSA_WANT_KEY_TYPE_ECC_PUBLIC_KEY)
        #define PSA_NEED_CC3XX_KEY_TYPE_ECC_PUBLIC_KEY_SECP 1
        #define PSA_NEED_CC3XX_KEY_TYPE_ECC_PUBLIC_KEY_SECP_R1_256 1
        #define PSA_ACCEL_KEY_TYPE_ECC_PUBLIC_KEY_SECP_R1_256 1
    #endif
#endif

//#if defined(PSA_WANT_ECC_SECP_R1_384) && defined(PSA_USE_CC3XX_KEY_MANAGEMENT_DRIVER)
//    #define PSA_NEED_CC3XX_KEY_MANAGEMENT_DRIVER 1
//    #if defined(PSA_WANT_KEY_TYPE_ECC_KEY_PAIR_IMPORT)
//        #define PSA_NEED_CC3XX_KEY_TYPE_ECC_KEY_PAIR_IMPORT_SECP 1
//        #define PSA_NEED_CC3XX_KEY_TYPE_ECC_KEY_PAIR_IMPORT_SECP_R1_384 1
//        #define PSA_ACCEL_KEY_TYPE_ECC_KEY_PAIR_IMPORT_SECP_R1_384 1
//    #endif
//    #if defined(PSA_WANT_KEY_TYPE_ECC_KEY_PAIR_EXPORT)
//        #define PSA_NEED_CC3XX_KEY_TYPE_ECC_KEY_PAIR_EXPORT_SECP 1
//        #define PSA_NEED_CC3XX_KEY_TYPE_ECC_KEY_PAIR_EXPORT_SECP_R1_384 1
//        #define PSA_ACCEL_KEY_TYPE_ECC_KEY_PAIR_EXPORT_SECP_R1_384 1
//    #endif
//    #if defined(PSA_WANT_KEY_TYPE_ECC_KEY_PAIR_GENERATE)
//        #define PSA_NEED_CC3XX_KEY_TYPE_ECC_KEY_PAIR_GENERATE_SECP 1
//        #define PSA_NEED_CC3XX_KEY_TYPE_ECC_KEY_PAIR_GENERATE_SECP_R1_384 1
//        #define PSA_ACCEL_KEY_TYPE_ECC_KEY_PAIR_GENERATE_SECP_R1_384 1
//    #endif
//    #if defined(PSA_WANT_KEY_TYPE_ECC_PUBLIC_KEY)
//        #define PSA_NEED_CC3XX_KEY_TYPE_ECC_PUBLIC_KEY_SECP 1
//        #define PSA_NEED_CC3XX_KEY_TYPE_ECC_PUBLIC_KEY_SECP_R1_384 1
//        #define PSA_ACCEL_KEY_TYPE_ECC_PUBLIC_KEY_SECP_R1_384 1
//    #endif
//#endif

//#if defined(PSA_WANT_ECC_SECP_R1_521) && defined(PSA_USE_CC3XX_KEY_MANAGEMENT_DRIVER)
//    #define PSA_NEED_CC3XX_KEY_MANAGEMENT_DRIVER 1
//    #if defined(PSA_WANT_KEY_TYPE_ECC_KEY_PAIR_IMPORT)
//        #define PSA_NEED_CC3XX_KEY_TYPE_ECC_KEY_PAIR_IMPORT_SECP 1
//        #define PSA_NEED_CC3XX_KEY_TYPE_ECC_KEY_PAIR_IMPORT_SECP_R1_521 1
//        #define PSA_ACCEL_KEY_TYPE_ECC_KEY_PAIR_IMPORT_SECP_R1_521 1
//    #endif
//    #if defined(PSA_WANT_KEY_TYPE_ECC_KEY_PAIR_EXPORT)
//        #define PSA_NEED_CC3XX_KEY_TYPE_ECC_KEY_PAIR_EXPORT_SECP 1
//        #define PSA_NEED_CC3XX_KEY_TYPE_ECC_KEY_PAIR_EXPORT_SECP_R1_521 1
//        #define PSA_ACCEL_KEY_TYPE_ECC_KEY_PAIR_EXPORT_SECP_R1_521 1
//    #endif
//    #if defined(PSA_WANT_KEY_TYPE_ECC_KEY_PAIR_GENERATE)
//        #define PSA_NEED_CC3XX_KEY_TYPE_ECC_KEY_PAIR_GENERATE_SECP 1
//        #define PSA_NEED_CC3XX_KEY_TYPE_ECC_KEY_PAIR_GENERATE_SECP_R1_521 1
//        #define PSA_ACCEL_KEY_TYPE_ECC_KEY_PAIR_GENERATE_SECP_R1_521 1
//    #endif
//    #if defined(PSA_WANT_KEY_TYPE_ECC_PUBLIC_KEY)
//        #define PSA_NEED_CC3XX_KEY_TYPE_ECC_PUBLIC_KEY_SECP 1
//        #define PSA_NEED_CC3XX_KEY_TYPE_ECC_PUBLIC_KEY_SECP_R1_521 1
//        #define PSA_ACCEL_KEY_TYPE_ECC_PUBLIC_KEY_SECP_R1_521 1
//    #endif
//#endif

#if defined(PSA_WANT_ECC_MONTGOMERY_255) && defined(PSA_USE_CC3XX_KEY_MANAGEMENT_DRIVER)
    #define PSA_NEED_CC3XX_KEY_MANAGEMENT_DRIVER 1
    #if defined(PSA_WANT_KEY_TYPE_ECC_KEY_PAIR_IMPORT)
        #define PSA_NEED_CC3XX_KEY_TYPE_ECC_KEY_PAIR_IMPORT_MONTGOMERY 1
        #define PSA_NEED_CC3XX_KEY_TYPE_ECC_KEY_PAIR_IMPORT_MONTGOMERY_255 1
        #define PSA_ACCEL_KEY_TYPE_ECC_KEY_PAIR_IMPORT_MONTGOMERY_255 1
    #endif
    #if defined(PSA_WANT_KEY_TYPE_ECC_KEY_PAIR_EXPORT)
        #define PSA_NEED_CC3XX_KEY_TYPE_ECC_KEY_PAIR_EXPORT_MONTGOMERY 1
        #define PSA_NEED_CC3XX_KEY_TYPE_ECC_KEY_PAIR_EXPORT_MONTGOMERY_255 1
        #define PSA_ACCEL_KEY_TYPE_ECC_KEY_PAIR_EXPORT_MONTGOMERY_255 1
    #endif
    #if defined(PSA_WANT_KEY_TYPE_ECC_KEY_PAIR_GENERATE)
        #define PSA_NEED_CC3XX_KEY_TYPE_ECC_KEY_PAIR_GENERATE_MONTGOMERY 1
        #define PSA_NEED_CC3XX_KEY_TYPE_ECC_KEY_PAIR_GENERATE_MONTGOMERY_255 1
        #define PSA_ACCEL_KEY_TYPE_ECC_KEY_PAIR_GENERATE_MONTGOMERY_255 1
    #endif
    #if defined(PSA_WANT_KEY_TYPE_ECC_PUBLIC_KEY)
        #define PSA_NEED_CC3XX_KEY_TYPE_ECC_PUBLIC_KEY_MONTGOMERY 1
        #define PSA_NEED_CC3XX_KEY_TYPE_ECC_PUBLIC_KEY_MONTGOMERY_255 1
        #define PSA_ACCEL_KEY_TYPE_ECC_PUBLIC_KEY_MONTGOMERY_255 1
    #endif
#endif

#if defined(PSA_USE_CC3XX_KEY_MANAGEMENT_DRIVER)
    #define PSA_NEED_CC3XX_KEY_MANAGEMENT_DRIVER 1
    #if defined(PSA_WANT_KEY_TYPE_ECC_KEY_PAIR_IMPORT)
        #define PSA_ACCEL_KEY_TYPE_RSA_KEY_PAIR_IMPORT 1
    #endif
    #if defined(PSA_WANT_KEY_TYPE_ECC_KEY_PAIR_EXPORT)
        #define PSA_ACCEL_KEY_TYPE_RSA_KEY_PAIR_EXPORT 1
    #endif
    #if defined(PSA_WANT_KEY_TYPE_ECC_PUBLIC_KEY)
        #define PSA_ACCEL_KEY_TYPE_RSA_PUBLIC_KEY 1
    #endif
#endif


/* CC3xx MAC Driver */

#if defined(PSA_WANT_ALG_HMAC) && defined(PSA_USE_CC3XX_MAC_DRIVER)
    #define PSA_NEED_CC3XX_MAC_DRIVER 1
    #define PSA_NEED_CC3XX_HMAC 1
    #define PSA_ACCEL_HMAC_SHA_1 1
    #define PSA_ACCEL_HMAC_SHA_224 1
    #define PSA_ACCEL_HMAC_SHA_256 1
#endif

#if defined(PSA_WANT_ALG_CMAC) && defined(PSA_USE_CC3XX_MAC_DRIVER)
    #define PSA_NEED_CC3XX_MAC_DRIVER 1
    #define PSA_NEED_CC3XX_CMAC 1
    #define PSA_ACCEL_CMAC_AES_128 1
    #define PSA_ACCEL_CMAC_AES_192 1
    #define PSA_ACCEL_CMAC_AES_256 1
#endif

/* CC3xx Entropy Driver */

#if defined(PSA_WANT_GENERATE_RANDOM) && defined(PSA_USE_CC3XX_ENTROPY_DRIVER)
    #define PSA_NEED_CC3XX_ENTROPY_DRIVER 1
    #define PSA_ACCEL_GET_ENTROPY 1
#endif

#endif /* CC3XX_PSA_CONFIG_H */
