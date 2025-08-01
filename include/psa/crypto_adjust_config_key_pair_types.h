/**
 * \file psa/crypto_adjust_config_key_pair_types.h
 * \brief Adjust PSA configuration for key pair types.
 *
 * This is an internal header. Do not include it directly.
 *
 * See docs/proposed/psa-conditional-inclusion-c.md.
 * - Support non-basic operations in a keypair type implicitly enables basic
 *   support for that keypair type.
 * - Support for a keypair type implicitly enables the corresponding public
 *   key type.
 * - Basic support for a keypair type implicilty enables import/export support
 *   for that keypair type. Warning: this is implementation-specific (mainly
 *   for the benefit of testing) and may change in the future!
 */
/*
 *  Copyright The Mbed TLS Contributors
 *  SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
 */

#ifndef PSA_CRYPTO_ADJUST_KEYPAIR_TYPES_H
#define PSA_CRYPTO_ADJUST_KEYPAIR_TYPES_H

#if !defined(MBEDTLS_CONFIG_FILES_READ)
#error "Do not include psa/crypto_adjust_*.h manually! This can lead to problems, " \
    "up to and including runtime errors such as buffer overflows. " \
    "If you're trying to fix a complaint from check_config.h, just remove " \
    "it from your configuration file: since Mbed TLS 3.0, it is included " \
    "automatically at the right point."
#endif /* */

/*****************************************************************
 * ANYTHING -> BASIC
 ****************************************************************/

#if defined(PSA_WANT_KEY_TYPE_ECC_KEY_PAIR_IMPORT) || \
    defined(PSA_WANT_KEY_TYPE_ECC_KEY_PAIR_EXPORT) || \
    defined(PSA_WANT_KEY_TYPE_ECC_KEY_PAIR_GENERATE) || \
    defined(PSA_WANT_KEY_TYPE_ECC_KEY_PAIR_DERIVE)
#define PSA_WANT_KEY_TYPE_ECC_KEY_PAIR_BASIC 1
#endif

#if defined(PSA_WANT_KEY_TYPE_RSA_KEY_PAIR_IMPORT) || \
    defined(PSA_WANT_KEY_TYPE_RSA_KEY_PAIR_EXPORT) || \
    defined(PSA_WANT_KEY_TYPE_RSA_KEY_PAIR_GENERATE) || \
    defined(PSA_WANT_KEY_TYPE_RSA_KEY_PAIR_DERIVE)
#define PSA_WANT_KEY_TYPE_RSA_KEY_PAIR_BASIC 1
#endif

#if defined(PSA_WANT_KEY_TYPE_DH_KEY_PAIR_IMPORT) || \
    defined(PSA_WANT_KEY_TYPE_DH_KEY_PAIR_EXPORT) || \
    defined(PSA_WANT_KEY_TYPE_DH_KEY_PAIR_GENERATE) || \
    defined(PSA_WANT_KEY_TYPE_DH_KEY_PAIR_DERIVE)
#define PSA_WANT_KEY_TYPE_DH_KEY_PAIR_BASIC 1
#endif

#if defined(PSA_WANT_KEY_TYPE_SPAKE2P_KEY_PAIR_IMPORT) || \
    defined(PSA_WANT_KEY_TYPE_SPAKE2P_KEY_PAIR_EXPORT) || \
    defined(PSA_WANT_KEY_TYPE_SPAKE2P_KEY_PAIR_GENERATE) || \
    defined(PSA_WANT_KEY_TYPE_SPAKE2P_KEY_PAIR_DERIVE)
#define PSA_WANT_KEY_TYPE_SPAKE2P_KEY_PAIR_BASIC 1
#endif

#if defined(PSA_WANT_KEY_TYPE_SRP_KEY_PAIR_IMPORT) || \
    defined(PSA_WANT_KEY_TYPE_SRP_KEY_PAIR_EXPORT) || \
    defined(PSA_WANT_KEY_TYPE_SRP_KEY_PAIR_GENERATE) || \
    defined(PSA_WANT_KEY_TYPE_SRP_KEY_PAIR_DERIVE)
#define PSA_WANT_KEY_TYPE_SRP_KEY_PAIR_BASIC 1
#endif

#if defined(PSA_WANT_KEY_TYPE_ML_DSA_KEY_PAIR_IMPORT) || \
    defined(PSA_WANT_KEY_TYPE_ML_DSA_KEY_PAIR_EXPORT) || \
    defined(PSA_WANT_KEY_TYPE_ML_DSA_KEY_PAIR_GENERATE) || \
    defined(PSA_WANT_KEY_TYPE_ML_DSA_KEY_PAIR_DERIVE)
#define PSA_WANT_KEY_TYPE_ML_DSA_KEY_PAIR_BASIC 1
#endif

#if defined(PSA_WANT_KEY_TYPE_ML_KEM_KEY_PAIR_IMPORT) || \
    defined(PSA_WANT_KEY_TYPE_ML_KEM_KEY_PAIR_EXPORT) || \
    defined(PSA_WANT_KEY_TYPE_ML_KEM_KEY_PAIR_GENERATE) || \
    defined(PSA_WANT_KEY_TYPE_ML_KEM_KEY_PAIR_DERIVE)
#define PSA_WANT_KEY_TYPE_ML_KEM_KEY_PAIR_BASIC 1
#endif

/*****************************************************************
 * BASIC -> corresponding PUBLIC
 ****************************************************************/

#if defined(PSA_WANT_KEY_TYPE_ECC_KEY_PAIR_BASIC)
#define PSA_WANT_KEY_TYPE_ECC_PUBLIC_KEY 1
#endif

#if defined(PSA_WANT_KEY_TYPE_RSA_KEY_PAIR_BASIC)
#define PSA_WANT_KEY_TYPE_RSA_PUBLIC_KEY 1
#endif

#if defined(PSA_WANT_KEY_TYPE_DH_KEY_PAIR_BASIC)
#define PSA_WANT_KEY_TYPE_DH_PUBLIC_KEY 1
#endif

#if defined(PSA_WANT_KEY_TYPE_SPAKE2P_KEY_PAIR_BASIC)
#define PSA_WANT_KEY_TYPE_SPAKE2P_PUBLIC_KEY 1
#endif

#if defined(PSA_WANT_KEY_TYPE_SRP_KEY_PAIR_BASIC)
#define PSA_WANT_KEY_TYPE_SRP_PUBLIC_KEY 1
#endif

#endif /* PSA_CRYPTO_ADJUST_KEYPAIR_TYPES_H */
