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

#define PSA_WANT_ALG_ASCON_AEAD128              1
#define PSA_WANT_ALG_ASCON_HASH256              1
#define PSA_WANT_ALG_ASCON_XOF128               1
#define PSA_WANT_ALG_ASCON_CXOF128              1
#define PSA_WANT_ALG_CBC_NO_PADDING             1
#define PSA_WANT_ALG_CBC_PKCS7                  1
#define PSA_WANT_ALG_CCM                        1
#define PSA_WANT_ALG_CCM_STAR_NO_TAG            1
#define PSA_WANT_ALG_CHACHA20_POLY1305          1
#define PSA_WANT_ALG_XCHACHA20_POLY1305         1
#define PSA_WANT_ALG_CMAC                       1
#define PSA_WANT_ALG_CTR                        1
#define PSA_WANT_ALG_DETERMINISTIC_ECDSA        1
#define PSA_WANT_ALG_ECB_NO_PADDING             1
#define PSA_WANT_ALG_ECDH                       1
#define PSA_WANT_ALG_ECDSA                      1
#define PSA_WANT_ALG_GCM                        1
#define PSA_WANT_ALG_HKDF                       1
#define PSA_WANT_ALG_HKDF_EXTRACT               1
#define PSA_WANT_ALG_HKDF_EXPAND                1
#define PSA_WANT_ALG_HMAC                       1
#define PSA_WANT_ALG_HSS                        1
#define PSA_WANT_ALG_JPAKE                      1
#define PSA_WANT_ALG_LMS                        1
#define PSA_WANT_ALG_ML_DSA                     1
#define PSA_WANT_ALG_HASH_ML_DSA                1
#define PSA_WANT_ALG_DETERMINISTIC_ML_DSA       1
#define PSA_WANT_ALG_DETERMINISTIC_HASH_ML_DSA  1
#define PSA_WANT_ALG_ML_KEM                     1
#define PSA_WANT_ALG_PBKDF2_HMAC                1
#define PSA_WANT_ALG_PBKDF2_AES_CMAC_PRF_128    1
#define PSA_WANT_ALG_PURE_EDDSA                 1
#define PSA_WANT_ALG_ED25519PH                  1
#define PSA_WANT_ALG_ED448PH                    1
#define PSA_WANT_ALG_RSA_OAEP                   1
#define PSA_WANT_ALG_RSA_PKCS1V15_CRYPT         1
#define PSA_WANT_ALG_RSA_PKCS1V15_SIGN          1
#define PSA_WANT_ALG_RSA_PSS                    1
#define PSA_WANT_ALG_SHA_1                      1
#define PSA_WANT_ALG_SHA_224                    1
#define PSA_WANT_ALG_SHA_256                    1
#define PSA_WANT_ALG_SHA_384                    1
#define PSA_WANT_ALG_SHA_512                    1
#define PSA_WANT_ALG_SHA_256_192                1
#define PSA_WANT_ALG_SHA3_224                   1
#define PSA_WANT_ALG_SHA3_256                   1
#define PSA_WANT_ALG_SHA3_384                   1
#define PSA_WANT_ALG_SHA3_512                   1
#define PSA_WANT_ALG_SHAKE128_256               1
#define PSA_WANT_ALG_SHAKE256_192               1
#define PSA_WANT_ALG_SHAKE256_256               1
#define PSA_WANT_ALG_SHAKE256_512               1
#define PSA_WANT_ALG_SHAKE128                   1
#define PSA_WANT_ALG_SHAKE256                   1
#define PSA_WANT_ALG_SPAKE2P_HMAC               1
#define PSA_WANT_ALG_SPAKE2P_CMAC               1
#define PSA_WANT_ALG_SPAKE2P_MATTER             1
#define PSA_WANT_ALG_SRP_6                      1
#define PSA_WANT_ALG_SRP_PASSWORD_HASH          1
#define PSA_WANT_ALG_STREAM_CIPHER              1
#define PSA_WANT_ALG_TLS12_ECJPAKE_TO_PMS       1
#define PSA_WANT_ALG_TLS12_PRF                  1
#define PSA_WANT_ALG_TLS12_PSK_TO_MS            1
#define PSA_WANT_ALG_SP800_108_COUNTER_HMAC     1
#define PSA_WANT_ALG_SP800_108_COUNTER_CMAC     1
#define PSA_WANT_ALG_KW                         1
#define PSA_WANT_ALG_KWP                        1
#define PSA_WANT_ALG_WPA3_SAE_FIXED             1
#define PSA_WANT_ALG_WPA3_SAE_GDH               1
#define PSA_WANT_ALG_WPA3_SAE_H2E               1
#define PSA_WANT_ALG_XMSS                       1
#define PSA_WANT_ALG_XMSS_MT                    1

#define PSA_WANT_ECC_MONTGOMERY_255             1
#define PSA_WANT_ECC_MONTGOMERY_448             1
#define PSA_WANT_ECC_TWISTED_EDWARDS_255        1
#define PSA_WANT_ECC_TWISTED_EDWARDS_448        1
#define PSA_WANT_ECC_SECP_R1_224                1
#define PSA_WANT_ECC_SECP_R1_256                1
#define PSA_WANT_ECC_SECP_R1_384                1
#define PSA_WANT_ECC_SECP_R1_521                1
#define PSA_WANT_ECC_SECP_K1_256                1

#define PSA_WANT_KEY_TYPE_DERIVE                1
#define PSA_WANT_KEY_TYPE_PASSWORD              1
#define PSA_WANT_KEY_TYPE_PASSWORD_HASH         1
#define PSA_WANT_KEY_TYPE_HMAC                  1
#define PSA_WANT_KEY_TYPE_AES                   1
#define PSA_WANT_KEY_TYPE_ASCON                 1
#define PSA_WANT_KEY_TYPE_CHACHA20              1
#define PSA_WANT_KEY_TYPE_XCHACHA20             1
//#define PSA_WANT_KEY_TYPE_ECC_KEY_PAIR          1 /* Deprecated */
#define PSA_WANT_KEY_TYPE_ECC_PUBLIC_KEY        1
#define PSA_WANT_KEY_TYPE_HSS_PUBLIC_KEY        1
#define PSA_WANT_KEY_TYPE_LMS_PUBLIC_KEY        1
#define PSA_WANT_KEY_TYPE_XMSS_PUBLIC_KEY       1
#define PSA_WANT_KEY_TYPE_XMSS_MT_PUBLIC_KEY    1
#define PSA_WANT_KEY_TYPE_RAW_DATA              1
//#define PSA_WANT_KEY_TYPE_RSA_KEY_PAIR          1 /* Deprecated */
#define PSA_WANT_KEY_TYPE_RSA_PUBLIC_KEY        1
#define PSA_WANT_KEY_TYPE_SPAKE2P_PUBLIC_KEY    1
#define PSA_WANT_KEY_TYPE_SRP_PUBLIC_KEY        1
#define PSA_WANT_KEY_TYPE_WPA3_SAE              1
#define PSA_WANT_KEY_TYPE_ML_DSA_PUBLIC_KEY     1
#define PSA_WANT_KEY_TYPE_ML_KEM_PUBLIC_KEY     1

#define PSA_WANT_KEY_TYPE_ECC_KEY_PAIR_BASIC    1
#define PSA_WANT_KEY_TYPE_ECC_KEY_PAIR_IMPORT   1
#define PSA_WANT_KEY_TYPE_ECC_KEY_PAIR_EXPORT   1
#define PSA_WANT_KEY_TYPE_ECC_KEY_PAIR_GENERATE 1
#define PSA_WANT_KEY_TYPE_ECC_KEY_PAIR_DERIVE   1

#define PSA_WANT_KEY_TYPE_RSA_KEY_PAIR_BASIC    1
#define PSA_WANT_KEY_TYPE_RSA_KEY_PAIR_IMPORT   1
#define PSA_WANT_KEY_TYPE_RSA_KEY_PAIR_EXPORT   1

#define PSA_WANT_KEY_TYPE_SPAKE2P_KEY_PAIR_BASIC  1
#define PSA_WANT_KEY_TYPE_SPAKE2P_KEY_PAIR_IMPORT 1
#define PSA_WANT_KEY_TYPE_SPAKE2P_KEY_PAIR_EXPORT 1
#define PSA_WANT_KEY_TYPE_SPAKE2P_KEY_PAIR_DERIVE 1

#define PSA_WANT_KEY_TYPE_SRP_KEY_PAIR_BASIC    1
#define PSA_WANT_KEY_TYPE_SRP_KEY_PAIR_IMPORT   1
#define PSA_WANT_KEY_TYPE_SRP_KEY_PAIR_EXPORT   1
#define PSA_WANT_KEY_TYPE_SRP_KEY_PAIR_DERIVE   1

#define PSA_WANT_KEY_TYPE_ML_DSA_KEY_PAIR_BASIC    1
#define PSA_WANT_KEY_TYPE_ML_DSA_KEY_PAIR_IMPORT   1
#define PSA_WANT_KEY_TYPE_ML_DSA_KEY_PAIR_EXPORT   1
#define PSA_WANT_KEY_TYPE_ML_DSA_KEY_PAIR_GENERATE 1
#define PSA_WANT_KEY_TYPE_ML_DSA_KEY_PAIR_DERIVE   1

#define PSA_WANT_KEY_TYPE_ML_KEM_KEY_PAIR_BASIC    1
#define PSA_WANT_KEY_TYPE_ML_KEM_KEY_PAIR_IMPORT   1
#define PSA_WANT_KEY_TYPE_ML_KEM_KEY_PAIR_EXPORT   1
#define PSA_WANT_KEY_TYPE_ML_KEM_KEY_PAIR_GENERATE 1
#define PSA_WANT_KEY_TYPE_ML_KEM_KEY_PAIR_DERIVE   1

// Additional AES key size option
#define PSA_WANT_AES_KEY_SIZE_128               1
#define PSA_WANT_AES_KEY_SIZE_192               1
#define PSA_WANT_AES_KEY_SIZE_256               1

// Additional RSA key size option
#define PSA_WANT_RSA_KEY_SIZE_1024              1
#define PSA_WANT_RSA_KEY_SIZE_1536              1
#define PSA_WANT_RSA_KEY_SIZE_2048              1
#define PSA_WANT_RSA_KEY_SIZE_3072              1
#define PSA_WANT_RSA_KEY_SIZE_4096              1
#define PSA_WANT_RSA_KEY_SIZE_6144              1
#define PSA_WANT_RSA_KEY_SIZE_8192              1

// Additional ML-DSA key size option
#define PSA_WANT_ML_DSA_KEY_SIZE_44             1
#define PSA_WANT_ML_DSA_KEY_SIZE_65             1
#define PSA_WANT_ML_DSA_KEY_SIZE_87             1

// Additional ML-KEM key size option
#define PSA_WANT_ML_KEM_KEY_SIZE_512            1
#define PSA_WANT_ML_KEM_KEY_SIZE_768            1
#define PSA_WANT_ML_KEM_KEY_SIZE_1024           1

// Additional configuration option
#define PSA_WANT_GENERATE_RANDOM                1

// Optimize ML-DSA implementation for maximum speed
//#define OBERON_ML_DSA_FAST 1

// Optimize ML-DSA implementation for minimum RAM usage
//#define OBERON_ML_DSA_SMALL 1

// Moved from mbedtls_config.h

/**
 * \def MBEDTLS_PSA_KEY_SLOT_COUNT
 *
 * When #MBEDTLS_PSA_KEY_STORE_DYNAMIC is disabled,
 * the maximum amount of PSA keys simultaneously in memory. This counts all
 * volatile keys, plus loaded persistent keys.
 *
 * When #MBEDTLS_PSA_KEY_STORE_DYNAMIC is enabled,
 * the maximum number of loaded persistent keys.
 *
 * Currently, persistent keys do not need to be loaded all the time while
 * a multipart operation is in progress, only while the operation is being
 * set up. This may change in future versions of the library.
 *
 * Currently, the library traverses of the whole table on each access to a
 * persistent key. Therefore large values may cause poor performance.
 */
#define MBEDTLS_PSA_KEY_SLOT_COUNT              16

/**
 * \def MBEDTLS_PSA_STATIC_KEY_SLOT_BUFFER_SIZE
 *
 * Define the size (in bytes) of each static key buffer when
 * #MBEDTLS_PSA_STATIC_KEY_SLOTS is set.
 *
 * If not explicitly defined then it's automatically guessed from available PSA
 * keys enabled in the build through PSA_WANT_xxx symbols.
 * Note that automatic size computation / guessing is incomplete. For 'raw keys'
 * (MAC keys, passwords, salt as key, etc.) there is no clear upper limit.
 *
 * If required by the application this parameter can be set to higher values
 * in order to store larger objects (ex: raw keys), but please note that this
 * will increase RAM usage.
 */
//#define MBEDTLS_PSA_STATIC_KEY_SLOT_BUFFER_SIZE 3000


/* Driver usage configuration */

#define PSA_USE_CTR_DRBG_DRIVER                 1
//#define PSA_USE_HMAC_DRBG_DRIVER                1

/* CryptoCell CC3XX driver demonstration */
#define PSA_USE_CC3XX_HASH_DRIVER                   1
#define PSA_USE_CC3XX_AEAD_DRIVER                   1
#define PSA_USE_CC3XX_CIPHER_DRIVER                 1
#define PSA_USE_CC3XX_MAC_DRIVER                    1
#define PSA_USE_CC3XX_KEY_AGREEMENT_DRIVER          1
#define PSA_USE_CC3XX_ASYMMETRIC_SIGNATURE_DRIVER   1
#define PSA_USE_CC3XX_ASYMMETRIC_ENCRYPTION_DRIVER  1
#define PSA_USE_CC3XX_KEY_MANAGEMENT_DRIVER         1
#define PSA_USE_CC3XX_ENTROPY_DRIVER                1

/* Opaque driver demonstration */
#define PSA_USE_DEMO_OPAQUE_DRIVER              1


/**
 * \name SECTION: Platform abstraction layer
 *
 * This section sets platform specific settings.
 * \{
 */

/**
 * \def MBEDTLS_FS_IO
 *
 * Enable functions that use the filesystem.
 */
#define MBEDTLS_FS_IO

/**
 * \def MBEDTLS_HAVE_TIME
 *
 * System has time.h and time().
 * The time does not need to be correct, only time differences are used,
 * by contrast with MBEDTLS_HAVE_TIME_DATE
 *
 * Defining MBEDTLS_HAVE_TIME allows you to specify MBEDTLS_PLATFORM_TIME_ALT,
 * MBEDTLS_PLATFORM_TIME_MACRO, MBEDTLS_PLATFORM_TIME_TYPE_MACRO and
 * MBEDTLS_PLATFORM_STD_TIME.
 *
 * Comment if your system does not support time functions.
 */
#define MBEDTLS_HAVE_TIME

/**
 * \def MBEDTLS_HAVE_TIME_DATE
 *
 * System has time.h, time(), and an implementation for
 * mbedtls_platform_gmtime_r() (see below).
 * The time needs to be correct (not necessarily very accurate, but at least
 * the date should be correct). This is used to verify the validity period of
 * X.509 certificates.
 *
 * Comment if your system does not have a correct clock.
 *
 * \note mbedtls_platform_gmtime_r() is an abstraction in platform_util.h that
 * behaves similarly to the gmtime_r() function from the C standard. Refer to
 * the documentation for mbedtls_platform_gmtime_r() for more information.
 *
 * \note It is possible to configure an implementation for
 * mbedtls_platform_gmtime_r() at compile-time by using the macro
 * MBEDTLS_PLATFORM_GMTIME_R_ALT.
 */
#define MBEDTLS_HAVE_TIME_DATE

/**
 * \def MBEDTLS_PLATFORM_C
 *
 * Enable the platform abstraction layer that allows you to re-assign
 * functions like calloc(), free(), snprintf(), printf(), fprintf(), exit().
 *
 * Enabling MBEDTLS_PLATFORM_C enables to use of MBEDTLS_PLATFORM_XXX_ALT
 * or MBEDTLS_PLATFORM_XXX_MACRO directives, allowing the functions mentioned
 * above to be specified at runtime or compile time respectively.
 *
 * \note This abstraction layer must be enabled on Windows (including MSYS2)
 * as other modules rely on it for a fixed snprintf implementation.
 *
 * Module:  platform/platform.c
 * Caller:  Most other .c files
 *
 * This module enables abstraction of common (libc) functions.
 */
#define MBEDTLS_PLATFORM_C

/**
 * \def MBEDTLS_THREADING_PTHREAD
 *
 * Enable the pthread wrapper layer for the threading layer.
 *
 * Requires: MBEDTLS_THREADING_C
 *
 * Uncomment this to enable pthread mutexes.
 */
//#define MBEDTLS_THREADING_PTHREAD

/**
 * \def MBEDTLS_THREADING_C
 *
 * Enable the threading abstraction layer.
 *
 * \note You must enable this option if TF-PSA-Crypto runs in a
 * multithreaded environment. Otherwise the PSA cryptography subsystem is
 * not thread-safe. As an exception, this option can be disabled if all
 * PSA crypto functions are ever called from a single thread. Note that
 * this includes indirect calls, for example through PK.
 *
 * Module:  platform/threading.c
 *
 * This allows different threading implementations (built-in or
 * provided externally).
 *
 * You will have to enable either #MBEDTLS_THREADING_ALT or
 * #MBEDTLS_THREADING_PTHREAD.
 *
 * Enable this layer to allow use of mutexes within Mbed TLS
 */
//#define MBEDTLS_THREADING_C

/** \} name SECTION: Platform abstraction layer */

/**
 * \name SECTION: General and test configuration options
 *
 * This section sets test specific settings.
 * \{
 */

/**
 * \def MBEDTLS_SELF_TEST
 *
 * Enable the checkup functions (*_self_test).
 */
#define MBEDTLS_SELF_TEST

/**
 * \def TF_PSA_CRYPTO_VERSION
 *
 * Enable run-time version information.
 *
 * This option enables functions for getting the version of TF-PSA-Crypto
 * at runtime defined in include/tf-psa-crypto/version.h.
 */
#define TF_PSA_CRYPTO_VERSION

/** \} name SECTION: General and test configuration options */

/**
 * \name SECTION: Cryptographic mechanism selection (extended API)
 *
 * This section sets cryptographic mechanism settings.
 * \{
 */

/**
 * \def MBEDTLS_MD_C
 *
 * Enable the generic layer for message digest (hashing).
 *
 * Requires: MBEDTLS_PSA_CRYPTO_C with at least one hash.
 * Module:  extras/md.c
 * Caller:  drivers/builtin/src/ecdsa.c
 *          drivers/builtin/src/ecjpake.c
 *          drivers/builtin/src/hmac_drbg.c
 *          drivers/builtin/src/psa_crypto_ecp.c
 *          drivers/builtin/src/psa_crypto_rsa.c
 *          drivers/builtin/src/rsa.c
 *          extras/pk.c
 *          utilities/constant_time.c
 *          utilities/pkcs5.c
 *
 * Uncomment to enable generic message digest wrappers.
 */
#define MBEDTLS_MD_C

/**
 * \def MBEDTLS_NIST_KW_C
 *
 * Enable the 128-bit key wrapping modes from NIST SP 800-38F:
 * KW (also known as RFC 3394) and KWP (RFC 5649).
 * Currently these modes are only supported with AES.
 *
 * Module:  extras/nist_kw.c
 *
 * Auto enables: PSA_WANT_ALG_ECB_NO_PADDING
 */
#define MBEDTLS_NIST_KW_C

/**
 * \def MBEDTLS_PK_C
 *
 * Enable the generic public (asymmetric) key layer.
 *
 * Module:  extras/pk.c
 * Caller:  drivers/builtin/src/psa_crypto_rsa.c
 *
 * Requires: #MBEDTLS_PSA_CRYPTO_CLIENT and at least one between
 *           #PSA_WANT_KEY_TYPE_RSA_PUBLIC_KEY and
 *           #PSA_WANT_KEY_TYPE_ECC_PUBLIC_KEY.
 *
 * Uncomment to enable generic public key wrappers.
 */
#define MBEDTLS_PK_C

/**
 * \def MBEDTLS_PKCS5_C
 *
 * Enable PKCS#5 functions.
 *
 * Module:  utilities/pkcs5.c
 *
 * Auto-enables: MBEDTLS_MD_C
 *
 * This module adds support for the PKCS#5 functions.
 */
#define MBEDTLS_PKCS5_C

/**
 * \def MBEDTLS_PK_PARSE_C
 *
 * Enable the generic public (asymmetric) key parser.
 *
 * Module:  extras/pkparse.c
 *
 * Requires: MBEDTLS_ASN1_PARSE_C, MBEDTLS_PK_C
 *
 * Uncomment to enable generic public key parse functions.
 */
#define MBEDTLS_PK_PARSE_C

/**
 * \def MBEDTLS_PK_PARSE_EC_EXTENDED
 *
 * Enhance support for reading EC keys using variants of SEC1 not allowed by
 * RFC 5915 and RFC 5480.
 *
 * Currently this means parsing the SpecifiedECDomain choice of EC
 * parameters (only known groups are supported, not arbitrary domains, to
 * avoid validation issues).
 *
 * Disable if you only need to support RFC 5915 + 5480 key formats.
 */
#define MBEDTLS_PK_PARSE_EC_EXTENDED

/**
 * \def MBEDTLS_PK_PARSE_EC_COMPRESSED
 *
 * Enable the support for parsing public keys of type Short Weierstrass
 * (PSA_ECC_FAMILY_SECP_XXX and PSA_ECC_FAMILY_BRAINPOOL_XXX) which are using the
 * compressed point format.
 */
#define MBEDTLS_PK_PARSE_EC_COMPRESSED

/**
 * \def MBEDTLS_PK_WRITE_C
 *
 * Enable the generic public (asymmetric) key writer.
 *
 * Module:  extras/pkwrite.c
 *
 * Requires: MBEDTLS_ASN1_WRITE_C, MBEDTLS_PK_C
 *
 * Uncomment to enable generic public key write functions.
 */
#define MBEDTLS_PK_WRITE_C

/** \} name SECTION: Cryptographic mechanism selection (extended API) */

/**
 * \name SECTION: Data format support
 *
 * This section sets data-format specific settings.
 * \{
 */

/**
 * \def MBEDTLS_ASN1_PARSE_C
 *
 * Enable the generic ASN1 parser.
 *
 * Module:  utilities/asn1parse.c
 * Caller:  extras/pkparse.c
 *          utilities/pkcs5.c
 */
#define MBEDTLS_ASN1_PARSE_C

/**
 * \def MBEDTLS_ASN1_WRITE_C
 *
 * Enable the generic ASN1 writer.
 *
 * Module:  utilities/asn1write.c
 * Caller:  drivers/builtin/src/ecdsa.c
 *          extras/pkwrite.c
 */
#define MBEDTLS_ASN1_WRITE_C

/**
 * \def MBEDTLS_BASE64_C
 *
 * Enable the Base64 module.
 *
 * Module:  utilities/base64.c
 * Caller:  utilities/pem.c
 *
 * This module is required for PEM support (required by X.509).
 */
#define MBEDTLS_BASE64_C

/**
 * \def MBEDTLS_PEM_PARSE_C
 *
 * Enable PEM decoding / parsing.
 *
 * Module:  utilities/pem.c
 * Caller:  extras/pkparse.c
 *
 * Requires: MBEDTLS_BASE64_C
 *           optionally PSA_WANT_ALG_MD5
 *
 * This modules adds support for decoding / parsing PEM files.
 */
//#define MBEDTLS_PEM_PARSE_C

/**
 * \def MBEDTLS_PEM_WRITE_C
 *
 * Enable PEM encoding / writing.
 *
 * Module:  utilities/pem.c
 * Caller:  extras/pkwrite.c
 *
 * Requires: MBEDTLS_BASE64_C
 *
 * This modules adds support for encoding / writing PEM files.
 */
//#define MBEDTLS_PEM_WRITE_C

/** \} name SECTION: Data format support */

/**
 * \name SECTION: PSA core
 *
 * This section sets PSA specific settings.
 * \{
 */

/**
 * \def MBEDTLS_PSA_CRYPTO_C
 *
 * Enable the Platform Security Architecture cryptography API.
 *
 * Module:  core/psa_crypto.c
 *
 * Requires: one of the following:
 *           - MBEDTLS_PSA_CRYPTO_EXTERNAL_RNG
 *           - MBEDTLS_CTR_DRBG_C
 *           - MBEDTLS_HMAC_DRBG_C
 *
 *           If MBEDTLS_CTR_DRBG_C or MBEDTLS_HMAC_DRBG_C is used as the PSA
 *           random generator, then either PSA_WANT_ALG_SHA_256 or
 *           PSA_WANT_ALG_SHA_512 must be enabled for the entropy module.
 *
 * \note The PSA crypto subsystem prioritizes DRBG mechanisms as follows:
 *       - #MBEDTLS_PSA_CRYPTO_EXTERNAL_RNG, if enabled
 *       - CTR_DRBG (AES), seeded by the entropy module, if
 *         #MBEDTLS_CTR_DRBG_C is enabled
 *       - HMAC_DRBG, seeded by the entropy module, if
 *         #MBEDTLS_HMAC_DRBG_C is enabled
 *
 *       A future version may reevaluate the prioritization of DRBG mechanisms.
 */
#define MBEDTLS_PSA_CRYPTO_C

/**
 * \def MBEDTLS_PSA_ASSUME_EXCLUSIVE_BUFFERS
 *
 * Assume all buffers passed to PSA functions are owned exclusively by the
 * PSA function and are not stored in shared memory.
 *
 * This option may be enabled if all buffers passed to any PSA function reside
 * in memory that is accessible only to the PSA function during its execution.
 *
 * This option MUST be disabled whenever buffer arguments are in memory shared
 * with an untrusted party, for example where arguments to PSA calls are passed
 * across a trust boundary.
 *
 * \note Enabling this option reduces memory usage and code size.
 *
 * \note Enabling this option causes overlap of input and output buffers
 *       not to be supported by PSA functions.
 */
//#define MBEDTLS_PSA_ASSUME_EXCLUSIVE_BUFFERS

/** \def MBEDTLS_PSA_CRYPTO_BUILTIN_KEYS
 *
 * Enable support for platform built-in keys. If you enable this feature,
 * you must implement the function mbedtls_psa_platform_get_builtin_key().
 * See the documentation of that function for more information.
 *
 * Built-in keys are typically derived from a hardware unique key or
 * stored in a secure element.
 *
 * Requires: MBEDTLS_PSA_CRYPTO_C.
 *
 * \warning This interface is experimental and may change or be removed
 * without notice.
 */
//#define MBEDTLS_PSA_CRYPTO_BUILTIN_KEYS

/** \def MBEDTLS_PSA_CRYPTO_CLIENT
 *
 * Enable support for PSA crypto client.
 *
 * \note This option allows to include the code necessary for a PSA
 *       crypto client when the PSA crypto implementation is not included in
 *       the library (MBEDTLS_PSA_CRYPTO_C disabled). The code included is the
 *       code to set and get PSA key attributes.
 *       The development of PSA drivers partially relying on the library to
 *       fulfill the hardware gaps is another possible usage of this option.
 *
 * \warning This interface is experimental and may change or be removed
 * without notice.
 */
#define MBEDTLS_PSA_CRYPTO_CLIENT

/** \def MBEDTLS_PSA_CRYPTO_EXTERNAL_RNG
 *
 * Make the PSA Crypto module use an external random generator provided
 * by a driver, instead of Mbed TLS's entropy and DRBG modules.
 *
 * \note This random generator must deliver random numbers with cryptographic
 *       quality and high performance. It must supply unpredictable numbers
 *       with a uniform distribution. The implementation of this function
 *       is responsible for ensuring that the random generator is seeded
 *       with sufficient entropy. If you have a hardware TRNG which is slow
 *       or delivers non-uniform output, declare it as an entropy source
 *       with mbedtls_entropy_add_source() instead of enabling this option.
 *
 * If you enable this option, you must configure the type
 * ::mbedtls_psa_external_random_context_t in psa/crypto_platform.h
 * and define a function called mbedtls_psa_external_get_random()
 * with the following prototype:
 * ```
 * psa_status_t mbedtls_psa_external_get_random(
 *     mbedtls_psa_external_random_context_t *context,
 *     uint8_t *output, size_t output_size, size_t *output_length);
 * );
 * ```
 * The \c context value is initialized to 0 before the first call.
 * The function must fill the \c output buffer with \c output_size bytes
 * of random data and set \c *output_length to \c output_size.
 *
 * Requires: MBEDTLS_PSA_CRYPTO_C
 *
 * \warning If you enable this option, code that uses the PSA cryptography
 *          interface will not use any of the entropy sources set up for
 *          the entropy module, nor the NV seed that MBEDTLS_ENTROPY_NV_SEED
 *          enables.
 *
 * \note This option is experimental and may be removed without notice.
 */
//#define MBEDTLS_PSA_CRYPTO_EXTERNAL_RNG

/* MBEDTLS_PSA_CRYPTO_KEY_ID_ENCODES_OWNER
 *
 * Enable key identifiers that encode a key owner identifier.
 *
 * The owner of a key is identified by a value of type ::mbedtls_key_owner_id_t
 * which is currently hard-coded to be int32_t.
 *
 * Note that this option is meant for internal use only and may be removed
 * without notice.
 */
//#define MBEDTLS_PSA_CRYPTO_KEY_ID_ENCODES_OWNER

/**
 * \def MBEDTLS_PSA_CRYPTO_SPM
 *
 * When MBEDTLS_PSA_CRYPTO_SPM is defined, the code is built for SPM (Secure
 * Partition Manager) integration which separates the code into two parts: a
 * NSPE (Non-Secure Process Environment) and an SPE (Secure Process
 * Environment).
 *
 * If you enable this option, your build environment must include a header
 * file `"crypto_spe.h"` (either in the `psa` subdirectory of the Mbed TLS
 * header files, or in another directory on the compiler's include search
 * path). Alternatively, your platform may customize the header
 * `psa/crypto_platform.h`, in which case it can skip or replace the
 * inclusion of `"crypto_spe.h"`.
 *
 * Module:  core/psa_crypto.c
 * Requires: MBEDTLS_PSA_CRYPTO_C
 *
 */
//#define MBEDTLS_PSA_CRYPTO_SPM

/**
 * \def MBEDTLS_PSA_CRYPTO_STORAGE_C
 *
 * Enable the Platform Security Architecture persistent key storage.
 *
 * Module:  core/psa_crypto_storage.c
 *
 * Requires: MBEDTLS_PSA_CRYPTO_C,
 *           either MBEDTLS_PSA_ITS_FILE_C or a native implementation of
 *           the PSA ITS interface
 */
#define MBEDTLS_PSA_CRYPTO_STORAGE_C

/**
 * \def MBEDTLS_PSA_ITS_FILE_C
 *
 * Enable the emulation of the Platform Security Architecture
 * Internal Trusted Storage (PSA ITS) over files.
 *
 * Module:  core/psa_its_file.c
 *
 * Requires: MBEDTLS_FS_IO
 */
#define MBEDTLS_PSA_ITS_FILE_C

/**
 * \def MBEDTLS_PSA_KEY_STORE_DYNAMIC
 *
 * Dynamically resize the PSA key store to accommodate any number of
 * volatile keys (until the heap memory is exhausted).
 *
 * If this option is disabled, the key store has a fixed size
 * #MBEDTLS_PSA_KEY_SLOT_COUNT for volatile keys and loaded persistent keys
 * together.
 *
 * This option has no effect when #MBEDTLS_PSA_CRYPTO_C is disabled.
 *
 * Module:  core/psa_crypto.c
 * Requires: MBEDTLS_PSA_CRYPTO_C
 */
//#define MBEDTLS_PSA_KEY_STORE_DYNAMIC

/**
 * \def MBEDTLS_PSA_STATIC_KEY_SLOTS
 *
 * Statically preallocate memory to store keys' material in PSA instead
 * of allocating it dynamically when required. This allows builds without a
 * heap, if none of the enabled cryptographic implementations or other features
 * require it.
 * This feature affects both volatile and persistent keys which means that
 * it's not possible to persistently store a key which is larger than
 * #MBEDTLS_PSA_STATIC_KEY_SLOT_BUFFER_SIZE.
 *
 * \note This feature comes with a (potentially) higher RAM usage since:
 *       - All the key slots are allocated no matter if they are used or not.
 *       - Each key buffer's length is #MBEDTLS_PSA_STATIC_KEY_SLOT_BUFFER_SIZE bytes.
 *
 * Requires: MBEDTLS_PSA_CRYPTO_C
 *
 */
#define MBEDTLS_PSA_STATIC_KEY_SLOTS


/** \} name SECTION: PSA core */

#endif /* PSA_CRYPTO_CONFIG_H */
