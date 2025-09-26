/*
 *  PSA crypto layer on top of Mbed TLS crypto
 */
/*
 *  Copyright The Mbed TLS Contributors
 *  SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
 */

/*
 * NOTICE: This file has been modified by Oberon microsystems AG.
 */

#include "oberon_psa_common.h"
#include "psa_crypto_core_common.h"

#if defined(MBEDTLS_PSA_CRYPTO_C)

#if defined(MBEDTLS_PSA_CRYPTO_CONFIG)
#include "check_crypto_config.h"
#endif

#include "psa/crypto.h"
#include "psa/crypto_values.h"
#include "psa_crypto_core.h"
#include "psa_crypto_driver_wrappers.h"
#include "psa_crypto_driver_wrappers_no_static.h"
#include "psa_crypto_slot_management.h"
/* Include internal declarations that are useful for implementing persistently
 * stored keys. */
#include "psa_crypto_storage.h"

#include "psa_crypto_random_impl.h"

#include <stdlib.h>
#include <string.h>
#include "mbedtls/platform.h"
#include "mbedtls/constant_time.h"
#include "mbedtls/cipher.h"  // mbedtls_operation_t


#if defined(PSA_CRYPTO_DRIVER_TFM_BUILTIN_KEY_LOADER)
#include "tfm_builtin_key_loader.h"
#endif /* PSA_CRYPTO_DRIVER_TFM_BUILTIN_KEY_LOADER */

/****************************************************************/
/* Global data, support functions and library management */
/****************************************************************/

static int key_type_is_raw_bytes(psa_key_type_t type)
{
    return PSA_KEY_TYPE_IS_UNSTRUCTURED(type);
}

/* Values for psa_global_data_t::rng_state */
#define RNG_NOT_INITIALIZED 0
#define RNG_INITIALIZED 1
#define RNG_SEEDED 2

/* Initialization flags for global_data::initialized */
#define PSA_CRYPTO_SUBSYSTEM_DRIVER_WRAPPERS_INITIALIZED    0x01
#define PSA_CRYPTO_SUBSYSTEM_KEY_SLOTS_INITIALIZED          0x02
#define PSA_CRYPTO_SUBSYSTEM_TRANSACTION_INITIALIZED        0x04

#define PSA_CRYPTO_SUBSYSTEM_ALL_INITIALISED                ( \
        PSA_CRYPTO_SUBSYSTEM_DRIVER_WRAPPERS_INITIALIZED | \
        PSA_CRYPTO_SUBSYSTEM_KEY_SLOTS_INITIALIZED | \
        PSA_CRYPTO_SUBSYSTEM_TRANSACTION_INITIALIZED)

typedef struct {
    uint8_t initialized;
    uint8_t rng_state;
    psa_driver_random_context_t rng;
} psa_global_data_t;

static psa_global_data_t global_data;

#ifdef MBEDTLS_PSA_CRYPTO_EXTERNAL_RNG
void* const mbedtls_psa_random_state = NULL; /* !!OM - used by some tests */
#else
mbedtls_psa_drbg_context_t *const mbedtls_psa_random_state = NULL; /* !!OM - used by some tests */
#endif

static uint8_t psa_get_initialized(void)
{
    uint8_t initialized;

#if defined(MBEDTLS_THREADING_C)
    mbedtls_mutex_lock(&mbedtls_threading_psa_rngdata_mutex);
#endif /* defined(MBEDTLS_THREADING_C) */

    initialized = global_data.rng_state == RNG_SEEDED;

#if defined(MBEDTLS_THREADING_C)
    mbedtls_mutex_unlock(&mbedtls_threading_psa_rngdata_mutex);
#endif /* defined(MBEDTLS_THREADING_C) */

#if defined(MBEDTLS_THREADING_C)
    mbedtls_mutex_lock(&mbedtls_threading_psa_globaldata_mutex);
#endif /* defined(MBEDTLS_THREADING_C) */

    initialized =
        (initialized && (global_data.initialized == PSA_CRYPTO_SUBSYSTEM_ALL_INITIALISED));

#if defined(MBEDTLS_THREADING_C)
    mbedtls_mutex_unlock(&mbedtls_threading_psa_globaldata_mutex);
#endif /* defined(MBEDTLS_THREADING_C) */

    return initialized;
}

static uint8_t psa_get_drivers_initialized(void)
{
    uint8_t initialized;

#if defined(MBEDTLS_THREADING_C)
    mbedtls_mutex_lock(&mbedtls_threading_psa_globaldata_mutex);
#endif /* defined(MBEDTLS_THREADING_C) */

    initialized = (global_data.initialized & PSA_CRYPTO_SUBSYSTEM_DRIVER_WRAPPERS_INITIALIZED) != 0;

#if defined(MBEDTLS_THREADING_C)
    mbedtls_mutex_unlock(&mbedtls_threading_psa_globaldata_mutex);
#endif /* defined(MBEDTLS_THREADING_C) */

    return initialized;
}

#define GUARD_MODULE_INITIALIZED        \
    if (psa_get_initialized() == 0)     \
    return PSA_ERROR_BAD_STATE;

int psa_can_do_hash(psa_algorithm_t hash_alg)
{
    (void) hash_alg;
    return psa_get_drivers_initialized();
}

int psa_can_do_cipher(psa_key_type_t key_type, psa_algorithm_t cipher_alg)
{
    (void) key_type;
    (void) cipher_alg;
    return psa_get_drivers_initialized();
}


/**
 * \brief                       For output buffers which contain "tags"
 *                              (outputs that may be checked for validity like
 *                              hashes, MACs and signatures), fill the unused
 *                              part of the output buffer (the whole buffer on
 *                              error, the trailing part on success) with
 *                              something that isn't a valid tag (barring an
 *                              attack on the tag and deliberately-crafted
 *                              input), in case the caller doesn't check the
 *                              return status properly.
 *
 * \param output_buffer         Pointer to buffer to wipe. May not be NULL
 *                              unless \p output_buffer_size is zero.
 * \param status                Status of function called to generate
 *                              output_buffer originally
 * \param output_buffer_size    Size of output buffer. If zero, \p output_buffer
 *                              could be NULL.
 * \param output_buffer_length  Length of data written to output_buffer, must be
 *                              less than \p output_buffer_size
 */
static void psa_wipe_tag_output_buffer(uint8_t *output_buffer, psa_status_t status,
                                       size_t output_buffer_size, size_t output_buffer_length)
{
    size_t offset = 0;

    if (output_buffer_size == 0) {
        /* If output_buffer_size is 0 then we have nothing to do. We must not
           call memset because output_buffer may be NULL in this case */
        return;
    }

    if (status == PSA_SUCCESS) {
        offset = output_buffer_length;
    }

    memset(output_buffer + offset, '!', output_buffer_size - offset);
}


/****************************************************************/
/* Key management */
/****************************************************************/

psa_status_t psa_validate_unstructured_key_bit_size(psa_key_type_t type,
                                                    size_t bits)
{
    /* Check that the bit size is acceptable for the key type */
    switch (type) {
        case PSA_KEY_TYPE_RAW_DATA:
        case PSA_KEY_TYPE_HMAC:
        case PSA_KEY_TYPE_DERIVE:
        case PSA_KEY_TYPE_PASSWORD:
        case PSA_KEY_TYPE_PASSWORD_HASH:
        case PSA_KEY_TYPE_PEPPER:
            break;
#if defined(PSA_WANT_KEY_TYPE_AES)
        case PSA_KEY_TYPE_AES:
            if (bits != 128 && bits != 192 && bits != 256) {
                return PSA_ERROR_INVALID_ARGUMENT;
            }
            break;
#endif
#if defined(PSA_WANT_KEY_TYPE_ARIA)
        case PSA_KEY_TYPE_ARIA:
            if (bits != 128 && bits != 192 && bits != 256) {
                return PSA_ERROR_INVALID_ARGUMENT;
            }
            break;
#endif
#if defined(PSA_WANT_KEY_TYPE_CAMELLIA)
        case PSA_KEY_TYPE_CAMELLIA:
            if (bits != 128 && bits != 192 && bits != 256) {
                return PSA_ERROR_INVALID_ARGUMENT;
            }
            break;
#endif
#if defined(PSA_WANT_KEY_TYPE_DES)
        case PSA_KEY_TYPE_DES:
            if (bits != 64 && bits != 128 && bits != 192) {
                return PSA_ERROR_INVALID_ARGUMENT;
            }
            break;
#endif
#if defined(PSA_WANT_KEY_TYPE_CHACHA20) || defined(PSA_WANT_KEY_TYPE_XCHACHA20)
        case PSA_KEY_TYPE_CHACHA20:
        case PSA_KEY_TYPE_XCHACHA20:
            if (bits != 256) {
                return PSA_ERROR_INVALID_ARGUMENT;
            }
            break;
#endif
        default:
            return PSA_ERROR_NOT_SUPPORTED;
    }
    if (bits % 8 != 0) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    return PSA_SUCCESS;
}

/** Check whether a given key type is valid for use with a given MAC algorithm
 *
 * Upon successful return of this function, the behavior of #PSA_MAC_LENGTH
 * when called with the validated \p algorithm and \p key_type is well-defined.
 *
 * \param[in] algorithm     The specific MAC algorithm (can be wildcard).
 * \param[in] key_type      The key type of the key to be used with the
 *                          \p algorithm.
 *
 * \retval #PSA_SUCCESS
 *         The \p key_type is valid for use with the \p algorithm
 * \retval #PSA_ERROR_INVALID_ARGUMENT
 *         The \p key_type is not valid for use with the \p algorithm
 */
MBEDTLS_STATIC_TESTABLE psa_status_t psa_mac_key_can_do(
    psa_algorithm_t algorithm,
    psa_key_type_t key_type)
{
    if (PSA_ALG_IS_HMAC(algorithm)) {
        if (key_type == PSA_KEY_TYPE_HMAC) {
            return PSA_SUCCESS;
        }
    }

    if (PSA_ALG_IS_BLOCK_CIPHER_MAC(algorithm)) {
        /* Check that we're calling PSA_BLOCK_CIPHER_BLOCK_LENGTH with a cipher
         * key. */
        if ((key_type & PSA_KEY_TYPE_CATEGORY_MASK) ==
            PSA_KEY_TYPE_CATEGORY_SYMMETRIC) {
            /* PSA_BLOCK_CIPHER_BLOCK_LENGTH returns 1 for stream ciphers and
             * the block length (larger than 1) for block ciphers. */
            if (PSA_BLOCK_CIPHER_BLOCK_LENGTH(key_type) > 1) {
                return PSA_SUCCESS;
            }
        }
    }

    return PSA_ERROR_INVALID_ARGUMENT;
}

psa_status_t psa_allocate_buffer_to_slot(psa_key_slot_t *slot,
                                         size_t buffer_length)
{
#if defined(MBEDTLS_PSA_STATIC_KEY_SLOTS)
    if (buffer_length > ((size_t) MBEDTLS_PSA_STATIC_KEY_SLOT_BUFFER_SIZE)) {
        return PSA_ERROR_NOT_SUPPORTED;
    }
#else
    if (slot->key.data != NULL) {
        return PSA_ERROR_ALREADY_EXISTS;
    }

    slot->key.data = mbedtls_calloc(1, buffer_length);
    if (slot->key.data == NULL) {
        return PSA_ERROR_INSUFFICIENT_MEMORY;
    }
#endif

    slot->key.bytes = buffer_length;
    return PSA_SUCCESS;
}

psa_status_t psa_copy_key_material_into_slot(psa_key_slot_t *slot,
                                             const uint8_t *data,
                                             size_t data_length)
{
    psa_status_t status = psa_allocate_buffer_to_slot(slot,
                                                      data_length);
    if (status != PSA_SUCCESS) {
        return status;
    }

    memcpy(slot->key.data, data, data_length);
    return PSA_SUCCESS;
}

psa_status_t psa_import_key_into_slot(
    const psa_key_attributes_t *attributes,
    const uint8_t *data, size_t data_length,
    uint8_t *key_buffer, size_t key_buffer_size,
    size_t *key_buffer_length, size_t *bits)
{
    psa_status_t status = PSA_ERROR_CORRUPTION_DETECTED;
    psa_key_type_t type = attributes->type;

    /* zero-length keys are never supported. */
    if (data_length == 0) {
        return PSA_ERROR_NOT_SUPPORTED;
    }

    if (key_type_is_raw_bytes(type)) {
        *bits = PSA_BYTES_TO_BITS(data_length);

        status = psa_validate_unstructured_key_bit_size(attributes->type,
                                                        *bits);
        if (status != PSA_SUCCESS) {
            return status;
        }

        /* Copy the key material. */
        memcpy(key_buffer, data, data_length);
        *key_buffer_length = data_length;
        (void) key_buffer_size;

        return PSA_SUCCESS;
    }

    return PSA_ERROR_NOT_SUPPORTED;
}

/** Calculate the intersection of two algorithm usage policies.
 *
 * Return 0 (which allows no operation) on incompatibility.
 */
static psa_algorithm_t psa_key_policy_algorithm_intersection(
    psa_key_type_t key_type,
    psa_algorithm_t alg1,
    psa_algorithm_t alg2)
{
    /* Common case: both sides actually specify the same policy. */
    if (alg1 == alg2) {
        return alg1;
    }
    /* If the policies are from the same hash-and-sign family, check
     * if one is a wildcard. If so the other has the specific algorithm. */
    if (PSA_ALG_IS_SIGN_HASH(alg1) &&
        PSA_ALG_IS_SIGN_HASH(alg2) &&
        (alg1 & ~PSA_ALG_HASH_MASK) == (alg2 & ~PSA_ALG_HASH_MASK)) {
        if (PSA_ALG_SIGN_GET_HASH(alg1) == PSA_ALG_ANY_HASH) {
            return alg2;
        }
        if (PSA_ALG_SIGN_GET_HASH(alg2) == PSA_ALG_ANY_HASH) {
            return alg1;
        }
    }
    /* If the policies are from the same AEAD family, check whether
     * one of them is a minimum-tag-length wildcard. Calculate the most
     * restrictive tag length. */
    if (PSA_ALG_IS_AEAD(alg1) && PSA_ALG_IS_AEAD(alg2) &&
        (PSA_ALG_AEAD_WITH_SHORTENED_TAG(alg1, 0) ==
         PSA_ALG_AEAD_WITH_SHORTENED_TAG(alg2, 0))) {
        size_t alg1_len = PSA_ALG_AEAD_GET_TAG_LENGTH(alg1);
        size_t alg2_len = PSA_ALG_AEAD_GET_TAG_LENGTH(alg2);
        size_t restricted_len = alg1_len > alg2_len ? alg1_len : alg2_len;

        /* If both are wildcards, return most restrictive wildcard */
        if (((alg1 & PSA_ALG_AEAD_AT_LEAST_THIS_LENGTH_FLAG) != 0) &&
            ((alg2 & PSA_ALG_AEAD_AT_LEAST_THIS_LENGTH_FLAG) != 0)) {
            return PSA_ALG_AEAD_WITH_AT_LEAST_THIS_LENGTH_TAG(
                alg1, restricted_len);
        }
        /* If only one is a wildcard, return specific algorithm if compatible. */
        if (((alg1 & PSA_ALG_AEAD_AT_LEAST_THIS_LENGTH_FLAG) != 0) &&
            (alg1_len <= alg2_len)) {
            return alg2;
        }
        if (((alg2 & PSA_ALG_AEAD_AT_LEAST_THIS_LENGTH_FLAG) != 0) &&
            (alg2_len <= alg1_len)) {
            return alg1;
        }
    }
    /* If the policies are from the same MAC family, check whether one
     * of them is a minimum-MAC-length policy. Calculate the most
     * restrictive tag length. */
    if (PSA_ALG_IS_MAC(alg1) && PSA_ALG_IS_MAC(alg2) &&
        (PSA_ALG_FULL_LENGTH_MAC(alg1) ==
         PSA_ALG_FULL_LENGTH_MAC(alg2))) {
        /* Validate the combination of key type and algorithm. Since the base
         * algorithm of alg1 and alg2 are the same, we only need this once. */
        if (PSA_SUCCESS != psa_mac_key_can_do(alg1, key_type)) {
            return 0;
        }

        /* Get the (exact or at-least) output lengths for both sides of the
         * requested intersection. None of the currently supported algorithms
         * have an output length dependent on the actual key size, so setting it
         * to a bogus value of 0 is currently OK.
         *
         * Note that for at-least-this-length wildcard algorithms, the output
         * length is set to the shortest allowed length, which allows us to
         * calculate the most restrictive tag length for the intersection. */
        size_t alg1_len = PSA_MAC_LENGTH(key_type, 0, alg1);
        size_t alg2_len = PSA_MAC_LENGTH(key_type, 0, alg2);
        size_t restricted_len = alg1_len > alg2_len ? alg1_len : alg2_len;

        /* If both are wildcards, return most restrictive wildcard */
        if (((alg1 & PSA_ALG_MAC_AT_LEAST_THIS_LENGTH_FLAG) != 0) &&
            ((alg2 & PSA_ALG_MAC_AT_LEAST_THIS_LENGTH_FLAG) != 0)) {
            return PSA_ALG_AT_LEAST_THIS_LENGTH_MAC(alg1, restricted_len);
        }

        /* If only one is an at-least-this-length policy, the intersection would
         * be the other (fixed-length) policy as long as said fixed length is
         * equal to or larger than the shortest allowed length. */
        if ((alg1 & PSA_ALG_MAC_AT_LEAST_THIS_LENGTH_FLAG) != 0) {
            return (alg1_len <= alg2_len) ? alg2 : 0;
        }
        if ((alg2 & PSA_ALG_MAC_AT_LEAST_THIS_LENGTH_FLAG) != 0) {
            return (alg2_len <= alg1_len) ? alg1 : 0;
        }

        /* If none of them are wildcards, check whether they define the same tag
         * length. This is still possible here when one is default-length and
         * the other specific-length. Ensure to always return the
         * specific-length version for the intersection. */
        if (alg1_len == alg2_len) {
            return PSA_ALG_TRUNCATED_MAC(alg1, alg1_len);
        }
    }
    /* If the policies are incompatible, allow nothing. */
    return 0;
}

static int psa_key_algorithm_permits(psa_key_type_t key_type,
                                     psa_algorithm_t policy_alg,
                                     psa_algorithm_t requested_alg)
{
    /* Common case: the policy only allows requested_alg. */
    if (requested_alg == policy_alg) {
        return 1;
    }
    /* If policy_alg is a hash-and-sign with a wildcard for the hash,
     * and requested_alg is the same hash-and-sign family with any hash,
     * then requested_alg is compliant with policy_alg. */
    if (PSA_ALG_IS_SIGN_HASH(requested_alg) &&
        PSA_ALG_SIGN_GET_HASH(policy_alg) == PSA_ALG_ANY_HASH) {
        return (policy_alg & ~PSA_ALG_HASH_MASK) ==
               (requested_alg & ~PSA_ALG_HASH_MASK);
    }
    /* If policy_alg is a wildcard AEAD algorithm of the same base as
     * the requested algorithm, check the requested tag length to be
     * equal-length or longer than the wildcard-specified length. */
    if (PSA_ALG_IS_AEAD(policy_alg) &&
        PSA_ALG_IS_AEAD(requested_alg) &&
        (PSA_ALG_AEAD_WITH_SHORTENED_TAG(policy_alg, 0) ==
         PSA_ALG_AEAD_WITH_SHORTENED_TAG(requested_alg, 0)) &&
        ((policy_alg & PSA_ALG_AEAD_AT_LEAST_THIS_LENGTH_FLAG) != 0)) {
        return PSA_ALG_AEAD_GET_TAG_LENGTH(policy_alg) <=
               PSA_ALG_AEAD_GET_TAG_LENGTH(requested_alg);
    }
   /* If the policy is the PSA_ALG_CCM_STAR_ANY_TAG wildcard algorithm,
    * the the key can be used with the PSA_ALG_CCM_STAR_NO_TAG
    * unauthenticated cipher, the PSA_ALG_CCM AEAD algorithm, and truncated
    * PSA_ALG_CCM AEAD algorithms. */
    if (policy_alg == PSA_ALG_CCM_STAR_ANY_TAG) {
        return requested_alg == PSA_ALG_CCM_STAR_NO_TAG ||
            (PSA_ALG_AEAD_WITH_SHORTENED_TAG(requested_alg, 0) ==
             PSA_ALG_AEAD_WITH_SHORTENED_TAG(PSA_ALG_CCM, 0));
    }
    /* If policy_alg is a MAC algorithm of the same base as the requested
     * algorithm, check whether their MAC lengths are compatible. */
    if (PSA_ALG_IS_MAC(policy_alg) &&
        PSA_ALG_IS_MAC(requested_alg) &&
        (PSA_ALG_FULL_LENGTH_MAC(policy_alg) ==
         PSA_ALG_FULL_LENGTH_MAC(requested_alg))) {
        /* Validate the combination of key type and algorithm. Since the policy
         * and requested algorithms are the same, we only need this once. */
        if (PSA_SUCCESS != psa_mac_key_can_do(policy_alg, key_type)) {
            return 0;
        }

        /* Get both the requested output length for the algorithm which is to be
         * verified, and the default output length for the base algorithm.
         * Note that none of the currently supported algorithms have an output
         * length dependent on actual key size, so setting it to a bogus value
         * of 0 is currently OK. */
        size_t requested_output_length = PSA_MAC_LENGTH(
            key_type, 0, requested_alg);
        size_t default_output_length = PSA_MAC_LENGTH(
            key_type, 0,
            PSA_ALG_FULL_LENGTH_MAC(requested_alg));

        /* If the policy is default-length, only allow an algorithm with
         * a declared exact-length matching the default. */
        if (PSA_MAC_TRUNCATED_LENGTH(policy_alg) == 0) {
            return requested_output_length == default_output_length;
        }

        /* If the requested algorithm is default-length, allow it if the policy
         * length exactly matches the default length. */
        if (PSA_MAC_TRUNCATED_LENGTH(requested_alg) == 0 &&
            PSA_MAC_TRUNCATED_LENGTH(policy_alg) == default_output_length) {
            return 1;
        }

        /* If policy_alg is an at-least-this-length wildcard MAC algorithm,
         * check for the requested MAC length to be equal to or longer than the
         * minimum allowed length. */
        if ((policy_alg & PSA_ALG_MAC_AT_LEAST_THIS_LENGTH_FLAG) != 0) {
            return PSA_MAC_TRUNCATED_LENGTH(policy_alg) <=
                   requested_output_length;
        }
    }
    /* If policy_alg is a generic key agreement operation, then using it for
     * a key derivation with that key agreement should also be allowed. This
     * behaviour is expected to be defined in a future specification version. */
    if (PSA_ALG_IS_RAW_KEY_AGREEMENT(policy_alg) &&
        PSA_ALG_IS_KEY_AGREEMENT(requested_alg)) {
        return PSA_ALG_KEY_AGREEMENT_GET_BASE(requested_alg) ==
               policy_alg;
    }
    /* If it isn't explicitly permitted, it's forbidden. */
    return 0;
}

/** Test whether a policy permits an algorithm.
 *
 * The caller must test usage flags separately.
 *
 * \note This function requires providing the key type for which the policy is
 *       being validated, since some algorithm policy definitions (e.g. MAC)
 *       have different properties depending on what kind of cipher it is
 *       combined with.
 *
 * \retval PSA_SUCCESS                  When \p alg is a specific algorithm
 *                                      allowed by the \p policy.
 * \retval PSA_ERROR_INVALID_ARGUMENT   When \p alg is not a specific algorithm
 * \retval PSA_ERROR_NOT_PERMITTED      When \p alg is a specific algorithm, but
 *                                      the \p policy does not allow it.
 */
static psa_status_t psa_key_policy_permits(const psa_key_policy_t *policy,
                                           psa_key_type_t key_type,
                                           psa_algorithm_t alg)
{
    /* '0' is not a valid algorithm */
    if (alg == 0) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    /* A requested algorithm cannot be a wildcard. */
    if (PSA_ALG_IS_WILDCARD(alg)) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    if (psa_key_algorithm_permits(key_type, policy->alg, alg) ||
        psa_key_algorithm_permits(key_type, policy->alg2, alg)) {
        return PSA_SUCCESS;
    } else {
        return PSA_ERROR_NOT_PERMITTED;
    }
}

/** Restrict a key policy based on a constraint.
 *
 * \note This function requires providing the key type for which the policy is
 *       being restricted, since some algorithm policy definitions (e.g. MAC)
 *       have different properties depending on what kind of cipher it is
 *       combined with.
 *
 * \param[in] key_type      The key type for which to restrict the policy
 * \param[in,out] policy    The policy to restrict.
 * \param[in] constraint    The policy constraint to apply.
 *
 * \retval #PSA_SUCCESS
 *         \c *policy contains the intersection of the original value of
 *         \c *policy and \c *constraint.
 * \retval #PSA_ERROR_INVALID_ARGUMENT
 *         \c key_type, \c *policy and \c *constraint are incompatible.
 *         \c *policy is unchanged.
 */
static psa_status_t psa_restrict_key_policy(
    psa_key_type_t key_type,
    psa_key_policy_t *policy,
    const psa_key_policy_t *constraint)
{
    psa_algorithm_t intersection_alg =
        psa_key_policy_algorithm_intersection(key_type, policy->alg,
                                              constraint->alg);
    psa_algorithm_t intersection_alg2 =
        psa_key_policy_algorithm_intersection(key_type, policy->alg2,
                                              constraint->alg2);
    if (intersection_alg == 0 && policy->alg != 0 && constraint->alg != 0) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }
    if (intersection_alg2 == 0 && policy->alg2 != 0 && constraint->alg2 != 0) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }
    policy->usage &= constraint->usage;
    policy->alg = intersection_alg;
    policy->alg2 = intersection_alg2;
    return PSA_SUCCESS;
}

/** Get the description of a key given its identifier and policy constraints
 *  and lock it.
 *
 * The key must have allow all the usage flags set in \p usage. If \p alg is
 * nonzero, the key must allow operations with this algorithm. If \p alg is
 * zero, the algorithm is not checked.
 *
 * In case of a persistent key, the function loads the description of the key
 * into a key slot if not already done.
 *
 * On success, the returned key slot has been registered for reading.
 * It is the responsibility of the caller to then unregister
 * once they have finished reading the contents of the slot.
 * The caller unregisters by calling psa_unregister_read() or
 * psa_unregister_read_under_mutex(). psa_unregister_read() must be called
 * if and only if the caller already holds the global key slot mutex
 * (when mutexes are enabled). psa_unregister_read_under_mutex() encapsulates
 * the unregister with mutex lock and unlock operations.
 */
static psa_status_t psa_get_and_lock_key_slot_with_policy(
    mbedtls_svc_key_id_t key,
    psa_key_slot_t **p_slot,
    psa_key_usage_t usage,
    psa_algorithm_t alg)
{
    psa_status_t status = PSA_ERROR_CORRUPTION_DETECTED;
    psa_key_slot_t *slot = NULL;

    status = psa_get_and_lock_key_slot(key, p_slot);
    if (status != PSA_SUCCESS) {
        return status;
    }
    slot = *p_slot;

    /* Enforce that usage policy for the key slot contains all the flags
     * required by the usage parameter. There is one exception: public
     * keys can always be exported, so we treat public key objects as
     * if they had the export flag. */
    if (PSA_KEY_TYPE_IS_PUBLIC_KEY(slot->attr.type)) {
        usage &= ~PSA_KEY_USAGE_EXPORT;
    }

    if ((slot->attr.policy.usage & usage) != usage) {
        status = PSA_ERROR_NOT_PERMITTED;
        goto error;
    }

    /* Enforce that the usage policy permits the requested algorithm. */
    if (alg != 0) {
        status = psa_key_policy_permits(&slot->attr.policy,
                                        slot->attr.type,
                                        alg);
        if (status != PSA_SUCCESS) {
            goto error;
        }
    }

    return PSA_SUCCESS;

error:
    *p_slot = NULL;
    psa_unregister_read_under_mutex(slot);

    return status;
}

psa_status_t psa_remove_key_data_from_memory(psa_key_slot_t *slot)
{
#if defined(MBEDTLS_PSA_STATIC_KEY_SLOTS)
    if (slot->key.bytes > 0) {
        mbedtls_platform_zeroize(slot->key.data, MBEDTLS_PSA_STATIC_KEY_SLOT_BUFFER_SIZE);
    }
#else
    if (slot->key.data != NULL) {
        mbedtls_zeroize_and_free(slot->key.data, slot->key.bytes);
    }

    slot->key.data = NULL;
#endif /* MBEDTLS_PSA_STATIC_KEY_SLOTS */

    slot->key.bytes = 0;

    return PSA_SUCCESS;
}

/** Completely wipe a slot in memory, including its policy.
 * Persistent storage is not affected. */
psa_status_t psa_wipe_key_slot(psa_key_slot_t *slot)
{
    psa_status_t status = psa_remove_key_data_from_memory(slot);

    /*
     * As the return error code may not be handled in case of multiple errors,
     * do our best to report an unexpected amount of registered readers or
     * an unexpected state.
     * Assert with MBEDTLS_TEST_HOOK_TEST_ASSERT that the slot is valid for
     * wiping.
     * if the MBEDTLS_TEST_HOOKS configuration option is enabled and the
     * function is called as part of the execution of a test suite, the
     * execution of the test suite is stopped in error if the assertion fails.
     */
    switch (slot->state) {
        case PSA_SLOT_FULL:
        /* In this state psa_wipe_key_slot() must only be called if the
         * caller is the last reader. */
        case PSA_SLOT_PENDING_DELETION:
            /* In this state psa_wipe_key_slot() must only be called if the
             * caller is the last reader. */
            if (slot->var.occupied.registered_readers != 1) {
                MBEDTLS_TEST_HOOK_TEST_ASSERT(slot->var.occupied.registered_readers == 1);
                status = PSA_ERROR_CORRUPTION_DETECTED;
            }
            break;
        case PSA_SLOT_FILLING:
            /* In this state registered_readers must be 0. */
            if (slot->var.occupied.registered_readers != 0) {
                MBEDTLS_TEST_HOOK_TEST_ASSERT(slot->var.occupied.registered_readers == 0);
                status = PSA_ERROR_CORRUPTION_DETECTED;
            }
            break;
        case PSA_SLOT_EMPTY:
            /* The slot is already empty, it cannot be wiped. */
            MBEDTLS_TEST_HOOK_TEST_ASSERT(slot->state != PSA_SLOT_EMPTY);
            status = PSA_ERROR_CORRUPTION_DETECTED;
            break;
        default:
            /* The slot's state is invalid. */
            status = PSA_ERROR_CORRUPTION_DETECTED;
    }

#if defined(MBEDTLS_PSA_KEY_STORE_DYNAMIC)
    size_t slice_index = slot->slice_index;
#endif /* MBEDTLS_PSA_KEY_STORE_DYNAMIC */


    /* Multipart operations may still be using the key. This is safe
     * because all multipart operation objects are independent from
     * the key slot: if they need to access the key after the setup
     * phase, they have a copy of the key. Note that this means that
     * key material can linger until all operations are completed. */
    /* At this point, key material and other type-specific content has
     * been wiped. Clear remaining metadata. We can call memset and not
     * zeroize because the metadata is not particularly sensitive.
     * This memset also sets the slot's state to PSA_SLOT_EMPTY. */
    memset(slot, 0, sizeof(*slot));

#if defined(MBEDTLS_PSA_KEY_STORE_DYNAMIC)
    /* If the slot is already corrupted, something went deeply wrong,
     * like a thread still using the slot or a stray pointer leading
     * to the slot's memory being used for another object. Let the slot
     * leak rather than make the corruption worse. */
    if (status == PSA_SUCCESS) {
        status = psa_free_key_slot(slice_index, slot);
    }
#endif /* MBEDTLS_PSA_KEY_STORE_DYNAMIC */

    return status;
}

psa_status_t psa_destroy_key(mbedtls_svc_key_id_t key)
{
    psa_key_slot_t *slot;
    psa_status_t status; /* status of the last operation */
    psa_status_t overall_status = PSA_SUCCESS;

    if (mbedtls_svc_key_id_is_null(key)) {
        return PSA_SUCCESS;
    }

    /*
     * Get the description of the key in a key slot, and register to read it.
     * In the case of a persistent key, this will load the key description
     * from persistent memory if not done yet.
     * We cannot avoid this loading as without it we don't know if
     * the key is operated by an SE or not and this information is needed by
     * the current implementation. */
    status = psa_get_and_lock_key_slot(key, &slot);
    if (status != PSA_SUCCESS) {
        return status;
    }

#if defined(MBEDTLS_THREADING_C)
    /* We cannot unlock between setting the state to PENDING_DELETION
     * and destroying the key in storage, as otherwise another thread
     * could load the key into a new slot and the key will not be
     * fully destroyed. */
    PSA_THREADING_CHK_GOTO_EXIT(mbedtls_mutex_lock(
                                    &mbedtls_threading_key_slot_mutex));

    if (slot->state == PSA_SLOT_PENDING_DELETION) {
        /* Another thread has destroyed the key between us locking the slot
         * and us gaining the mutex. Unregister from the slot,
         * and report that the key does not exist. */
        status = psa_unregister_read(slot);

        PSA_THREADING_CHK_RET(mbedtls_mutex_unlock(
                                  &mbedtls_threading_key_slot_mutex));
        return (status == PSA_SUCCESS) ? PSA_ERROR_INVALID_HANDLE : status;
    }
#endif
    /* Set the key slot containing the key description's state to
     * PENDING_DELETION. This stops new operations from registering
     * to read the slot. Current readers can safely continue to access
     * the key within the slot; the last registered reader will
     * automatically wipe the slot when they call psa_unregister_read().
     * If the key is persistent, we can now delete the copy of the key
     * from memory. If the key is opaque, we require the driver to
     * deal with the deletion. */
    overall_status = psa_key_slot_state_transition(slot, PSA_SLOT_FULL,
                                                   PSA_SLOT_PENDING_DELETION);

    if (overall_status != PSA_SUCCESS) {
        goto exit;
    }

    if (PSA_KEY_LIFETIME_IS_READ_ONLY(slot->attr.lifetime)) {
        /* Refuse the destruction of a read-only key (which may or may not work
         * if we attempt it, depending on whether the key is merely read-only
         * by policy or actually physically read-only).
         * Just do the best we can, which is to wipe the copy in memory
         * (done in this function's cleanup code). */
        overall_status = PSA_ERROR_NOT_PERMITTED;
        goto exit;
    }

#if defined(MBEDTLS_PSA_CRYPTO_STORAGE_C)
    if (!PSA_KEY_LIFETIME_IS_VOLATILE(slot->attr.lifetime)
#if defined(MBEDTLS_PSA_CRYPTO_BUILTIN_KEYS)
    && !psa_key_id_is_builtin(MBEDTLS_SVC_KEY_ID_GET_KEY_ID(slot->attr.id))
#endif
    ) {
        /* Destroy the copy of the persistent key from storage.
         * The slot will still hold a copy of the key until the last reader
         * unregisters. */
        status = psa_destroy_persistent_key(slot->attr.id);
        if (overall_status == PSA_SUCCESS) {
            overall_status = status;
        }

    }
#endif /* defined(MBEDTLS_PSA_CRYPTO_STORAGE_C) */

#if defined(MBEDTLS_PSA_CRYPTO_BUILTIN_KEYS)
    if (psa_key_id_is_builtin(MBEDTLS_SVC_KEY_ID_GET_KEY_ID(slot->attr.id))) {
        status = psa_driver_wrapper_destroy_builtin_key(&slot->attr);
        if (overall_status == PSA_SUCCESS) {
            overall_status = status;
        }
    }
#endif /* defined(MBEDTLS_PSA_CRYPTO_BUILTIN_KEYS) */

exit:
    /* Unregister from reading the slot. If we are the last active reader
     * then this will wipe the slot. */
    status = psa_unregister_read(slot);
    /* Prioritize CORRUPTION_DETECTED from unregistering over
     * a storage error. */
    if (status != PSA_SUCCESS) {
        overall_status = status;
    }

#if defined(MBEDTLS_THREADING_C)
    /* Don't overwrite existing errors if the unlock fails. */
    status = overall_status;
    PSA_THREADING_CHK_RET(mbedtls_mutex_unlock(
                              &mbedtls_threading_key_slot_mutex));
#endif

    return overall_status;
}

/** Retrieve all the publicly-accessible attributes of a key.
 */
psa_status_t psa_get_key_attributes(mbedtls_svc_key_id_t key,
                                    psa_key_attributes_t *attributes)
{
    psa_status_t status = PSA_ERROR_CORRUPTION_DETECTED;
    psa_key_slot_t *slot;

    psa_reset_key_attributes(attributes);

    status = psa_get_and_lock_key_slot_with_policy(key, &slot, 0, 0);
    if (status != PSA_SUCCESS) {
        return status;
    }

    *attributes = slot->attr;

    return psa_unregister_read_under_mutex(slot);
}

static psa_status_t psa_export_key_buffer_internal(const uint8_t *key_buffer,
                                                   size_t key_buffer_size,
                                                   uint8_t *data,
                                                   size_t data_size,
                                                   size_t *data_length)
{
    if (key_buffer_size > data_size) {
        return PSA_ERROR_BUFFER_TOO_SMALL;
    }
    memcpy(data, key_buffer, key_buffer_size);
    memset(data + key_buffer_size, 0,
           data_size - key_buffer_size);
    *data_length = key_buffer_size;
    return PSA_SUCCESS;
}

psa_status_t psa_export_key_internal(
    const psa_key_attributes_t *attributes,
    const uint8_t *key_buffer, size_t key_buffer_size,
    uint8_t *data, size_t data_size, size_t *data_length)
{
    psa_key_type_t type = attributes->type;

    if (key_type_is_raw_bytes(type)   ||
        PSA_KEY_TYPE_IS_RSA(type)     ||
        PSA_KEY_TYPE_IS_ECC(type)     ||
        PSA_KEY_TYPE_IS_SPAKE2P(type) ||
        PSA_KEY_TYPE_IS_SRP(type)     ||
        PSA_KEY_TYPE_IS_WPA3_SAE_PT(type)) {
        return psa_export_key_buffer_internal(
            key_buffer, key_buffer_size,
            data, data_size, data_length);
    } else {
        /* This shouldn't happen in the reference implementation, but
           it is valid for a special-purpose implementation to omit
           support for exporting certain key types. */
        return PSA_ERROR_NOT_SUPPORTED;
    }
}

psa_status_t psa_export_key(mbedtls_svc_key_id_t key,
                            uint8_t *data,
                            size_t data_size,
                            size_t *data_length)
{
    psa_status_t status = PSA_ERROR_CORRUPTION_DETECTED;
    psa_status_t unlock_status = PSA_ERROR_CORRUPTION_DETECTED;
    psa_key_slot_t *slot;

    /* Reject a zero-length output buffer now, since this can never be a
     * valid key representation. This way we know that data must be a valid
     * pointer and we can do things like memset(data, ..., data_size). */
    if (data_size == 0) {
        return PSA_ERROR_BUFFER_TOO_SMALL;
    }

    /* Set the key to empty now, so that even when there are errors, we always
     * set data_length to a value between 0 and data_size. On error, setting
     * the key to empty is a good choice because an empty key representation is
     * unlikely to be accepted anywhere. */
    *data_length = 0;

    /* Export requires the EXPORT flag. There is an exception for public keys,
     * which don't require any flag, but
     * psa_get_and_lock_key_slot_with_policy() takes care of this.
     */
    status = psa_get_and_lock_key_slot_with_policy(key, &slot,
                                                   PSA_KEY_USAGE_EXPORT, 0);
    if (status != PSA_SUCCESS) {
        return status;
    }

    status = psa_driver_wrapper_export_key(&slot->attr,
                                           slot->key.data, slot->key.bytes,
                                           data, data_size, data_length);

    unlock_status = psa_unregister_read_under_mutex(slot);

    return (status == PSA_SUCCESS) ? unlock_status : status;
}

psa_status_t psa_export_public_key_internal(
    const psa_key_attributes_t *attributes,
    const uint8_t *key_buffer,
    size_t key_buffer_size,
    uint8_t *data,
    size_t data_size,
    size_t *data_length)
{
    psa_key_type_t type = attributes->type;

    if (PSA_KEY_TYPE_IS_PUBLIC_KEY(type) &&
        (PSA_KEY_TYPE_IS_RSA(type) || PSA_KEY_TYPE_IS_ECC(type) ||
         PSA_KEY_TYPE_IS_DH(type) || PSA_KEY_TYPE_IS_SPAKE2P(type) ||
         PSA_KEY_TYPE_IS_SRP(type))) {
        /* Exporting public -> public */
        return psa_export_key_buffer_internal(
            key_buffer, key_buffer_size,
            data, data_size, data_length);
    } else if (PSA_KEY_TYPE_IS_RSA(type)) {
        /* We don't know how to convert a private RSA key to public. */
        return PSA_ERROR_NOT_SUPPORTED;
    } else if (PSA_KEY_TYPE_IS_ECC(type)) {
        /* We don't know how to convert a private ECC key to public */
        return PSA_ERROR_NOT_SUPPORTED;
    } else if (PSA_KEY_TYPE_IS_DH(type)) {
        return PSA_ERROR_NOT_SUPPORTED;
    } else {
        (void) key_buffer;
        (void) key_buffer_size;
        (void) data;
        (void) data_size;
        (void) data_length;
        return PSA_ERROR_NOT_SUPPORTED;
    }
}

psa_status_t psa_export_public_key(mbedtls_svc_key_id_t key,
                                   uint8_t *data,
                                   size_t data_size,
                                   size_t *data_length)
{
    psa_status_t status = PSA_ERROR_CORRUPTION_DETECTED;
    psa_status_t unlock_status = PSA_ERROR_CORRUPTION_DETECTED;
    psa_key_slot_t *slot;

    /* Reject a zero-length output buffer now, since this can never be a
     * valid key representation. This way we know that data must be a valid
     * pointer and we can do things like memset(data, ..., data_size). */
    if (data_size == 0) {
        return PSA_ERROR_BUFFER_TOO_SMALL;
    }

    /* Set the key to empty now, so that even when there are errors, we always
     * set data_length to a value between 0 and data_size. On error, setting
     * the key to empty is a good choice because an empty key representation is
     * unlikely to be accepted anywhere. */
    *data_length = 0;

    /* Exporting a public key doesn't require a usage flag. */
    status = psa_get_and_lock_key_slot_with_policy(key, &slot, 0, 0);
    if (status != PSA_SUCCESS) {
        return status;
    }

    if (!PSA_KEY_TYPE_IS_ASYMMETRIC(slot->attr.type)) {
        status = PSA_ERROR_INVALID_ARGUMENT;
        goto exit;
    }

    status = psa_driver_wrapper_export_public_key(
        &slot->attr, slot->key.data, slot->key.bytes,
        data, data_size, data_length);

exit:
    unlock_status = psa_unregister_read_under_mutex(slot);

    return (status == PSA_SUCCESS) ? unlock_status : status;
}

/** Validate that a key policy is internally well-formed.
 *
 * This function only rejects invalid policies. It does not validate the
 * consistency of the policy with respect to other attributes of the key
 * such as the key type.
 */
static psa_status_t psa_validate_key_policy(const psa_key_policy_t *policy)
{
    if ((policy->usage & ~(PSA_KEY_USAGE_EXPORT |
                           PSA_KEY_USAGE_COPY |
                           PSA_KEY_USAGE_ENCRYPT |
                           PSA_KEY_USAGE_DECRYPT |
                           PSA_KEY_USAGE_SIGN_MESSAGE |
                           PSA_KEY_USAGE_VERIFY_MESSAGE |
                           PSA_KEY_USAGE_SIGN_HASH |
                           PSA_KEY_USAGE_VERIFY_HASH |
                           PSA_KEY_USAGE_VERIFY_DERIVATION |
                           PSA_KEY_USAGE_DERIVE |
                           PSA_KEY_USAGE_WRAP |
                           PSA_KEY_USAGE_UNWRAP)) != 0) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    return PSA_SUCCESS;
}

/** Validate the internal consistency of key attributes.
 *
 * This function only rejects invalid attribute values. If does not
 * validate the consistency of the attributes with any key data that may
 * be involved in the creation of the key.
 *
 * Call this function early in the key creation process.
 *
 * \param[in] attributes    Key attributes for the new key.
 * \param[out] p_drv        On any return, the driver for the key, if any.
 *                          NULL for a transparent key.
 *
 */
static psa_status_t psa_validate_key_attributes(
    const psa_key_attributes_t *attributes,
    psa_se_drv_table_entry_t **p_drv)
{
    psa_status_t status = PSA_ERROR_INVALID_ARGUMENT;
    psa_key_lifetime_t lifetime = psa_get_key_lifetime(attributes);
    mbedtls_svc_key_id_t key = psa_get_key_id(attributes);

    status = psa_validate_key_location(lifetime, p_drv);
    if (status != PSA_SUCCESS) {
        return status;
    }

    status = psa_validate_key_persistence(lifetime);
    if (status != PSA_SUCCESS) {
        return status;
    }

    if (PSA_KEY_LIFETIME_IS_VOLATILE(lifetime)) {
        if (MBEDTLS_SVC_KEY_ID_GET_KEY_ID(key) != 0) {
            return PSA_ERROR_INVALID_ARGUMENT;
        }
    } else {
        if (!psa_is_valid_key_id(psa_get_key_id(attributes), 1)) {
            return PSA_ERROR_INVALID_ARGUMENT;
        }
    }

    status = psa_validate_key_policy(&attributes->policy);
    if (status != PSA_SUCCESS) {
        return status;
    }

    /* Refuse to create overly large keys.
     * Note that this doesn't trigger on import if the attributes don't
     * explicitly specify a size (so psa_get_key_bits returns 0), so
     * psa_import_key() needs its own checks. */
    if (psa_get_key_bits(attributes) > PSA_MAX_KEY_BITS) {
        return PSA_ERROR_NOT_SUPPORTED;
    }

    return PSA_SUCCESS;
}

/** Prepare a key slot to receive key material.
 *
 * This function allocates a key slot and sets its metadata.
 *
 * If this function fails, call psa_fail_key_creation().
 *
 * This function is intended to be used as follows:
 * -# Call psa_start_key_creation() to allocate a key slot, prepare
 *    it with the specified attributes, and in case of a volatile key assign it
 *    a volatile key identifier.
 * -# Populate the slot with the key material.
 * -# Call psa_finish_key_creation() to finalize the creation of the slot.
 * In case of failure at any step, stop the sequence and call
 * psa_fail_key_creation().
 *
 * On success, the key slot's state is PSA_SLOT_FILLING.
 * It is the responsibility of the caller to change the slot's state to
 * PSA_SLOT_EMPTY/FULL once key creation has finished.
 *
 * \param method            An identification of the calling function.
 * \param[in] attributes    Key attributes for the new key.
 * \param[out] p_slot       On success, a pointer to the prepared slot.
 * \param[out] p_drv        On any return, the driver for the key, if any.
 *                          NULL for a transparent key.
 *
 * \retval #PSA_SUCCESS
 *         The key slot is ready to receive key material.
 * \return If this function fails, the key slot is an invalid state.
 *         You must call psa_fail_key_creation() to wipe and free the slot.
 */
static psa_status_t psa_start_key_creation(
    psa_key_creation_method_t method,
    const psa_key_attributes_t *attributes,
    psa_key_slot_t **p_slot,
    psa_se_drv_table_entry_t **p_drv)
{
    psa_status_t status;

    (void) method;
    *p_drv = NULL;

    status = psa_validate_key_attributes(attributes, p_drv);
    if (status != PSA_SUCCESS) {
        return status;
    }

    int key_is_volatile = PSA_KEY_LIFETIME_IS_VOLATILE(attributes->lifetime);
    psa_key_id_t volatile_key_id;

#if defined(MBEDTLS_THREADING_C)
    PSA_THREADING_CHK_RET(mbedtls_mutex_lock(
                              &mbedtls_threading_key_slot_mutex));
#endif
    status = psa_reserve_free_key_slot(
        key_is_volatile ? &volatile_key_id : NULL,
        p_slot);
#if defined(MBEDTLS_THREADING_C)
    PSA_THREADING_CHK_RET(mbedtls_mutex_unlock(
                              &mbedtls_threading_key_slot_mutex));
#endif
    if (status != PSA_SUCCESS) {
        return status;
    }
    psa_key_slot_t *slot = *p_slot;

    /* We're storing the declared bit-size of the key. It's up to each
     * creation mechanism to verify that this information is correct.
     * It's automatically correct for mechanisms that use the bit-size as
     * an input (generate, device) but not for those where the bit-size
     * is optional (import, copy). In case of a volatile key, assign it the
     * volatile key identifier associated to the slot returned to contain its
     * definition. */

    slot->attr = *attributes;
    if (key_is_volatile) {
#if !defined(MBEDTLS_PSA_CRYPTO_KEY_ID_ENCODES_OWNER)
        slot->attr.id = volatile_key_id;
#else
        slot->attr.id.key_id = volatile_key_id;
#endif
    }

    return PSA_SUCCESS;
}

/** Finalize the creation of a key once its key material has been set.
 *
 * This entails writing the key to persistent storage.
 *
 * If this function fails, call psa_fail_key_creation().
 * See the documentation of psa_start_key_creation() for the intended use
 * of this function.
 *
 * If the finalization succeeds, the function sets the key slot's state to
 * PSA_SLOT_FULL, and the key slot can no longer be accessed as part of the
 * key creation process.
 *
 * \param[in,out] slot  Pointer to the slot with key material.
 * \param[in] driver    The secure element driver for the key,
 *                      or NULL for a transparent key.
 * \param[out] key      On success, identifier of the key. Note that the
 *                      key identifier is also stored in the key slot.
 *
 * \retval #PSA_SUCCESS
 *         The key was successfully created.
 * \retval #PSA_ERROR_INSUFFICIENT_MEMORY \emptydescription
 * \retval #PSA_ERROR_INSUFFICIENT_STORAGE \emptydescription
 * \retval #PSA_ERROR_ALREADY_EXISTS \emptydescription
 * \retval #PSA_ERROR_DATA_INVALID \emptydescription
 * \retval #PSA_ERROR_DATA_CORRUPT \emptydescription
 * \retval #PSA_ERROR_STORAGE_FAILURE \emptydescription
 *
 * \return If this function fails, the key slot is an invalid state.
 *         You must call psa_fail_key_creation() to wipe and free the slot.
 */
static psa_status_t psa_finish_key_creation(
    psa_key_slot_t *slot,
    psa_se_drv_table_entry_t *driver,
    mbedtls_svc_key_id_t *key)
{
    psa_status_t status = PSA_SUCCESS;
    (void) slot;
    (void) driver;

#if defined(MBEDTLS_THREADING_C)
    PSA_THREADING_CHK_RET(mbedtls_mutex_lock(
                              &mbedtls_threading_key_slot_mutex));
#endif

#if defined(MBEDTLS_PSA_CRYPTO_STORAGE_C)
    if (!PSA_KEY_LIFETIME_IS_VOLATILE(slot->attr.lifetime)
#if defined(MBEDTLS_PSA_CRYPTO_BUILTIN_KEYS)
    && !psa_key_id_is_builtin(MBEDTLS_SVC_KEY_ID_GET_KEY_ID(slot->attr.id))
#endif
    ) {
        /* Key material is saved in export representation in the slot, so
         * just pass the slot buffer for storage. */
        status = psa_save_persistent_key(&slot->attr,
                                         slot->key.data,
                                         slot->key.bytes);
    }
#endif /* defined(MBEDTLS_PSA_CRYPTO_STORAGE_C) */

    if (status == PSA_SUCCESS) {
        *key = slot->attr.id;
        status = psa_key_slot_state_transition(slot, PSA_SLOT_FILLING,
                                               PSA_SLOT_FULL);
        if (status != PSA_SUCCESS) {
            *key = MBEDTLS_SVC_KEY_ID_INIT;
        }
    }

#if defined(MBEDTLS_THREADING_C)
    PSA_THREADING_CHK_RET(mbedtls_mutex_unlock(
                              &mbedtls_threading_key_slot_mutex));
#endif
    return status;
}

/** Abort the creation of a key.
 *
 * You may call this function after calling psa_start_key_creation(),
 * or after psa_finish_key_creation() fails. In other circumstances, this
 * function may not clean up persistent storage.
 * See the documentation of psa_start_key_creation() for the intended use
 * of this function. Sets the slot's state to PSA_SLOT_EMPTY.
 *
 * \param[in,out] slot  Pointer to the slot with key material.
 * \param[in] driver    The secure element driver for the key,
 *                      or NULL for a transparent key.
 */
static void psa_fail_key_creation(psa_key_slot_t *slot,
                                  psa_se_drv_table_entry_t *driver)
{
    (void) driver;

    if (slot == NULL) {
        return;
    }

#if defined(MBEDTLS_THREADING_C)
    /* If the lock operation fails we still wipe the slot.
     * Operations will no longer work after a failed lock,
     * but we still need to wipe the slot of confidential data. */
    mbedtls_mutex_lock(&mbedtls_threading_key_slot_mutex);
#endif

    psa_wipe_key_slot(slot);

#if defined(MBEDTLS_THREADING_C)
    mbedtls_mutex_unlock(&mbedtls_threading_key_slot_mutex);
#endif
}

/** Validate optional attributes during key creation.
 *
 * Some key attributes are optional during key creation. If they are
 * specified in the attributes structure, check that they are consistent
 * with the data in the slot.
 *
 * This function should be called near the end of key creation, after
 * the slot in memory is fully populated but before saving persistent data.
 */
static psa_status_t psa_validate_optional_attributes(
    const psa_key_slot_t *slot,
    const psa_key_attributes_t *attributes)
{
    if (attributes->type != 0) {
        if (attributes->type != slot->attr.type) {
            return PSA_ERROR_INVALID_ARGUMENT;
        }
    }

    if (attributes->bits != 0) {
        if (attributes->bits != slot->attr.bits) {
            return PSA_ERROR_INVALID_ARGUMENT;
        }
    }

    return PSA_SUCCESS;
}

static psa_status_t psa_validate_ecc_key_attr(const psa_key_attributes_t *attributes)
{
    psa_algorithm_t alg = psa_get_key_algorithm(attributes);
    size_t key_bits_attr = psa_get_key_bits(attributes);
    psa_key_type_t type = psa_get_key_type(attributes);

    /* Without algorithm we can't evaluate more fields */
    if (alg == PSA_ALG_NONE) {
        return PSA_SUCCESS;
    }

    /* It is not mandatory to set the key bits field, so zero is valid*/
    if (key_bits_attr == 0) {
        return PSA_SUCCESS;
    }

    /* Check if the size matches the curve family */
    switch (PSA_KEY_TYPE_ECC_GET_FAMILY(type)) {
        case PSA_ECC_FAMILY_SECP_K1:
            if (key_bits_attr != 192 && key_bits_attr != 225 && key_bits_attr != 256) {
                return PSA_ERROR_INVALID_ARGUMENT;
            }
            break;
        case PSA_ECC_FAMILY_SECP_R1:
            if (key_bits_attr != 192 && key_bits_attr != 224 && key_bits_attr != 256 &&
                key_bits_attr != 384 && key_bits_attr != 521) {
                return PSA_ERROR_INVALID_ARGUMENT;
            }
            break;
        case PSA_ECC_FAMILY_SECT_K1:
            if (key_bits_attr != 233 && key_bits_attr != 239 && key_bits_attr != 283 &&
                key_bits_attr != 409 && key_bits_attr != 571) {
                return PSA_ERROR_INVALID_ARGUMENT;
            }
            break;
        case PSA_ECC_FAMILY_SECT_R1:
            if (key_bits_attr != 233 && key_bits_attr != 283 && key_bits_attr != 409 &&
                key_bits_attr != 571) {
                return PSA_ERROR_INVALID_ARGUMENT;
            }
            break;
        case PSA_ECC_FAMILY_BRAINPOOL_P_R1:
            if (key_bits_attr != 192 && key_bits_attr != 224 && key_bits_attr != 256 &&
                key_bits_attr != 320 && key_bits_attr != 384 && key_bits_attr != 512) {
                return PSA_ERROR_INVALID_ARGUMENT;
            }
            break;
        case PSA_ECC_FAMILY_TWISTED_EDWARDS:
        case PSA_ECC_FAMILY_MONTGOMERY:
            if (key_bits_attr != 255 && key_bits_attr != 448) {
                return PSA_ERROR_INVALID_ARGUMENT;
            }
            break;
        default:
            return PSA_ERROR_NOT_SUPPORTED;
    }

    return PSA_SUCCESS;
}

static psa_status_t psa_validate_ecc_key_data_length(const psa_key_attributes_t *attributes,
                                                     size_t data_length)
{
    psa_algorithm_t alg = psa_get_key_algorithm(attributes);
    psa_key_type_t type = psa_get_key_type(attributes);
    size_t key_bits_attr = psa_get_key_bits(attributes);


    /* Without  algorithm we can't evaluate more fields */
    if (alg == PSA_ALG_NONE) {
        return PSA_SUCCESS;
    }

        /* It is not mandatory to set the key bits field, so zero is valid */
    if (key_bits_attr == 0) {
        return PSA_SUCCESS;
    }

    /* Check if the size matches the curve family */
    switch (PSA_KEY_TYPE_ECC_GET_FAMILY(type)) {
        case PSA_ECC_FAMILY_SECP_R1:
            /* secpr1p521 can be encoded in 65(first byte = 0) or 66 bytes therefore checking for
             * 65 bytes is enough
             */
            if (key_bits_attr == 521) {
                if (data_length < 65) {
                    return PSA_ERROR_INVALID_ARGUMENT;
                } else {
                    return PSA_SUCCESS;
                }
            }
            /* else we can do the same check than for all other curves */
        case PSA_ECC_FAMILY_SECT_K1:
        case PSA_ECC_FAMILY_SECT_R1:
        case PSA_ECC_FAMILY_BRAINPOOL_P_R1:
        case PSA_ECC_FAMILY_TWISTED_EDWARDS:
        case PSA_ECC_FAMILY_MONTGOMERY:
            if (data_length < PSA_BITS_TO_BYTES(key_bits_attr)){
                return PSA_ERROR_INVALID_ARGUMENT;
            }
            break;
        default:
            break;
    }

    return PSA_SUCCESS;
}

static psa_status_t psa_ecc_key_zero_check(const uint8_t *data, size_t data_length)
{
    uint8_t zero = 0;

    for (size_t i = 0; i < data_length; i++) {
        zero |= data[i];
    }

    if (zero == 0) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    return PSA_SUCCESS;
}

psa_status_t psa_import_key(const psa_key_attributes_t *attributes,
                            const uint8_t *data,
                            size_t data_length,
                            mbedtls_svc_key_id_t *key)
{
    psa_status_t status;
    psa_key_slot_t *slot = NULL;
    psa_se_drv_table_entry_t *driver = NULL;
    size_t bits;
    size_t storage_size = data_length;
    psa_key_type_t key_type = psa_get_key_type(attributes);

    *key = MBEDTLS_SVC_KEY_ID_INIT;

    /* Reject zero-length symmetric keys (including raw data key objects).
     * This also rejects any key which might be encoded as an empty string,
     * which is never valid. */
    if (data_length == 0) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    /* Ensure that the bytes-to-bits conversion cannot overflow. */
    if (data_length > SIZE_MAX / 8) {
        return PSA_ERROR_NOT_SUPPORTED;
    }

    /* Check the ecc keys for plausibility */
    if(PSA_KEY_TYPE_IS_ECC_KEY_PAIR(key_type) || PSA_KEY_TYPE_IS_ECC_PUBLIC_KEY(key_type)) {
        status = psa_validate_ecc_key_attr(attributes);
        if (status != PSA_SUCCESS) {
            return status;
        }
        status = psa_validate_ecc_key_data_length(attributes, data_length);
        if (status != PSA_SUCCESS) {
            return status;
        }
        status = psa_ecc_key_zero_check(data, data_length);
        if (status != PSA_SUCCESS) {
            return status;
        }
    }

    status = psa_start_key_creation(PSA_KEY_CREATION_IMPORT, attributes,
                                    &slot, &driver);
    if (status != PSA_SUCCESS) {
        goto exit;
    }

    /* In the case of a transparent key or an opaque key stored in local
     * storage ( thus not in the case of importing a key in a secure element
     * with storage ( MBEDTLS_PSA_CRYPTO_SE_C ) ),we have to allocate a
     * buffer to hold the imported key material. */
    if (slot->key.bytes == 0) {
        if (psa_key_lifetime_is_external(attributes->lifetime)) {
            status = psa_driver_wrapper_get_key_buffer_size_from_key_data(
                attributes, data, data_length, &storage_size);
            if (status != PSA_SUCCESS) {
                goto exit;
            }
        }
        status = psa_allocate_buffer_to_slot(slot, storage_size);
        if (status != PSA_SUCCESS) {
            goto exit;
        }
    }

    bits = slot->attr.bits;
    status = psa_driver_wrapper_import_key(attributes,
                                           data, data_length,
                                           slot->key.data,
                                           slot->key.bytes,
                                           &slot->key.bytes, &bits);
    if (status != PSA_SUCCESS) {
        goto exit;
    }

    if (slot->attr.bits == 0) {
        slot->attr.bits = (psa_key_bits_t) bits;
    } else if (bits != slot->attr.bits) {
        status = PSA_ERROR_INVALID_ARGUMENT;
        goto exit;
    }

    /* Enforce a size limit, and in particular ensure that the bit
     * size fits in its representation type.*/
    if (bits > PSA_MAX_KEY_BITS) {
        status = PSA_ERROR_NOT_SUPPORTED;
        goto exit;
    }
    status = psa_validate_optional_attributes(slot, attributes);
    if (status != PSA_SUCCESS) {
        goto exit;
    }

    status = psa_finish_key_creation(slot, driver, key);
exit:
    if (status != PSA_SUCCESS) {
        psa_fail_key_creation(slot, driver);
    }

    return status;
}

psa_status_t psa_copy_key(mbedtls_svc_key_id_t source_key,
                          const psa_key_attributes_t *specified_attributes,
                          mbedtls_svc_key_id_t *target_key)
{
    psa_status_t status = PSA_ERROR_CORRUPTION_DETECTED;
    psa_status_t unlock_status = PSA_ERROR_CORRUPTION_DETECTED;
    psa_key_slot_t *source_slot = NULL;
    psa_key_slot_t *target_slot = NULL;
    psa_key_attributes_t actual_attributes = *specified_attributes;
    psa_se_drv_table_entry_t *driver = NULL;
    size_t storage_size = 0;

    *target_key = MBEDTLS_SVC_KEY_ID_INIT;

    status = psa_get_and_lock_key_slot_with_policy(
        source_key, &source_slot, PSA_KEY_USAGE_COPY, 0);
    if (status != PSA_SUCCESS) {
        goto exit;
    }

    status = psa_validate_optional_attributes(source_slot,
                                              specified_attributes);
    if (status != PSA_SUCCESS) {
        goto exit;
    }

    /* The target key type and number of bits have been validated by
     * psa_validate_optional_attributes() to be either equal to zero or
     * equal to the ones of the source key. So it is safe to inherit
     * them from the source key now."
     * */
    actual_attributes.bits = source_slot->attr.bits;
    actual_attributes.type = source_slot->attr.type;


    status = psa_restrict_key_policy(source_slot->attr.type,
                                     &actual_attributes.policy,
                                     &source_slot->attr.policy);
    if (status != PSA_SUCCESS) {
        goto exit;
    }

    status = psa_start_key_creation(PSA_KEY_CREATION_COPY, &actual_attributes,
                                    &target_slot, &driver);
    if (status != PSA_SUCCESS) {
        goto exit;
    }
    if (PSA_KEY_LIFETIME_GET_LOCATION(target_slot->attr.lifetime) !=
        PSA_KEY_LIFETIME_GET_LOCATION(source_slot->attr.lifetime)) {
        /*
         * If the source and target keys are stored in different locations,
         * the source key would need to be exported as plaintext and re-imported
         * in the other location. This has security implications which have not
         * been fully mapped. For now, this can be achieved through
         * appropriate API invocations from the application, if needed.
         * */
        status = PSA_ERROR_NOT_SUPPORTED;
        goto exit;
    }
    /*
     * When the source and target keys are within the same location,
     * - For transparent keys it is a blind copy without any driver invocation,
     * - For opaque keys this translates to an invocation of the drivers'
     *   copy_key entry point through the dispatch layer.
     * */
    if (psa_key_lifetime_is_external(actual_attributes.lifetime)) {
        status = psa_driver_wrapper_get_key_buffer_size(&actual_attributes,
                                                        &storage_size);
        if (status != PSA_SUCCESS) {
            goto exit;
        }

        status = psa_allocate_buffer_to_slot(target_slot, storage_size);
        if (status != PSA_SUCCESS) {
            goto exit;
        }

        status = psa_driver_wrapper_copy_key(&actual_attributes,
                                             source_slot->key.data,
                                             source_slot->key.bytes,
                                             target_slot->key.data,
                                             target_slot->key.bytes,
                                             &target_slot->key.bytes);
        if (status != PSA_SUCCESS) {
            goto exit;
        }
    } else {
        status = psa_copy_key_material_into_slot(target_slot,
                                                 source_slot->key.data,
                                                 source_slot->key.bytes);
        if (status != PSA_SUCCESS) {
            goto exit;
        }
    }
    status = psa_finish_key_creation(target_slot, driver, target_key);
exit:
    if (status != PSA_SUCCESS) {
        psa_fail_key_creation(target_slot, driver);
    }

    unlock_status = psa_unregister_read_under_mutex(source_slot);

    return (status == PSA_SUCCESS) ? unlock_status : status;
}



/****************************************************************/
/* Message digests */
/****************************************************************/

psa_status_t psa_hash_abort(psa_hash_operation_t *operation)
{
    /* Aborting a non-active operation is allowed */
    if (operation->id == 0) {
        return PSA_SUCCESS;
    }

    psa_status_t status = psa_driver_wrapper_hash_abort(operation);
    operation->id = 0;

    return status;
}

psa_status_t psa_hash_setup(psa_hash_operation_t *operation,
                            psa_algorithm_t alg)
{
    psa_status_t status = PSA_ERROR_CORRUPTION_DETECTED;

    /* A context must be freshly initialized before it can be set up. */
    if (operation->id != 0) {
        status = PSA_ERROR_BAD_STATE;
        goto exit;
    }

    if (!PSA_ALG_IS_HASH(alg)) {
        status = PSA_ERROR_INVALID_ARGUMENT;
        goto exit;
    }

    /* Make sure the driver-dependent part of the operation is zeroed.
     * This is a guarantee we make to drivers. Initializing the operation
     * does not necessarily take care of it, since the context is a
     * union and initializing a union does not necessarily initialize
     * all of its members. */
    memset(&operation->ctx, 0, sizeof(operation->ctx));

    status = psa_driver_wrapper_hash_setup(operation, alg);

exit:
    if (status != PSA_SUCCESS) {
        psa_hash_abort(operation);
    }

    return status;
}

psa_status_t psa_hash_update(psa_hash_operation_t *operation,
                             const uint8_t *input,
                             size_t input_length)
{
    psa_status_t status = PSA_ERROR_CORRUPTION_DETECTED;

    if (operation->id == 0) {
        status = PSA_ERROR_BAD_STATE;
        goto exit;
    }

    /* Don't require hash implementations to behave correctly on a
     * zero-length input, which may have an invalid pointer. */
    if (input_length == 0) {
        return PSA_SUCCESS;
    }

    status = psa_driver_wrapper_hash_update(operation, input, input_length);

exit:
    if (status != PSA_SUCCESS) {
        psa_hash_abort(operation);
    }

    return status;
}

psa_status_t psa_hash_finish(psa_hash_operation_t *operation,
                             uint8_t *hash,
                             size_t hash_size,
                             size_t *hash_length)
{
    *hash_length = 0;
    if (operation->id == 0) {
        return PSA_ERROR_BAD_STATE;
    }

    psa_status_t status = psa_driver_wrapper_hash_finish(
        operation, hash, hash_size, hash_length);
    psa_hash_abort(operation);
    return status;
}

psa_status_t psa_hash_verify(psa_hash_operation_t *operation,
                             const uint8_t *hash,
                             size_t hash_length)
{
    uint8_t actual_hash[PSA_HASH_MAX_SIZE];
    size_t actual_hash_length;
    psa_status_t status = psa_hash_finish(
        operation,
        actual_hash, sizeof(actual_hash),
        &actual_hash_length);

    if (status != PSA_SUCCESS) {
        goto exit;
    }

    if (actual_hash_length != hash_length) {
        status = PSA_ERROR_INVALID_SIGNATURE;
        goto exit;
    }

    if (mbedtls_ct_memcmp(hash, actual_hash, actual_hash_length) != 0) {
        status = PSA_ERROR_INVALID_SIGNATURE;
    }

exit:
    mbedtls_platform_zeroize(actual_hash, sizeof(actual_hash));
    if (status != PSA_SUCCESS) {
        psa_hash_abort(operation);
    }

    return status;
}

psa_status_t psa_hash_compute(psa_algorithm_t alg,
                              const uint8_t *input, size_t input_length,
                              uint8_t *hash, size_t hash_size,
                              size_t *hash_length)
{
    *hash_length = 0;
    if (!PSA_ALG_IS_HASH(alg)) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    return psa_driver_wrapper_hash_compute(alg, input, input_length,
                                           hash, hash_size, hash_length);
}

psa_status_t psa_hash_compare(psa_algorithm_t alg,
                              const uint8_t *input, size_t input_length,
                              const uint8_t *hash, size_t hash_length)
{
    uint8_t actual_hash[PSA_HASH_MAX_SIZE];
    size_t actual_hash_length;

    if (!PSA_ALG_IS_HASH(alg)) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    psa_status_t status = psa_driver_wrapper_hash_compute(
        alg, input, input_length,
        actual_hash, sizeof(actual_hash),
        &actual_hash_length);
    if (status != PSA_SUCCESS) {
        goto exit;
    }
    if (actual_hash_length != hash_length) {
        status = PSA_ERROR_INVALID_SIGNATURE;
        goto exit;
    }
    if (mbedtls_ct_memcmp(hash, actual_hash, actual_hash_length) != 0) {
        status = PSA_ERROR_INVALID_SIGNATURE;
    }

exit:
    mbedtls_platform_zeroize(actual_hash, sizeof(actual_hash));
    return status;
}

psa_status_t psa_hash_clone(const psa_hash_operation_t *source_operation,
                            psa_hash_operation_t *target_operation)
{
    if (source_operation->id == 0 ||
        target_operation->id != 0) {
        return PSA_ERROR_BAD_STATE;
    }

    /* Make sure the driver-dependent part of the operation is zeroed.
     * This is a guarantee we make to drivers. Initializing the operation
     * does not necessarily take care of it, since the context is a
     * union and initializing a union does not necessarily initialize
     * all of its members. */
    memset(&target_operation->ctx, 0, sizeof(target_operation->ctx));

    psa_status_t status = psa_driver_wrapper_hash_clone(source_operation,
                                                        target_operation);
    if (status != PSA_SUCCESS) {
        psa_hash_abort(target_operation);
    }

    return status;
}


/****************************************************************/
/* MAC */
/****************************************************************/

psa_status_t psa_mac_abort(psa_mac_operation_t *operation)
{
    /* Aborting a non-active operation is allowed */
    if (operation->id == 0) {
        return PSA_SUCCESS;
    }

    psa_status_t status = psa_driver_wrapper_mac_abort(operation);
    operation->mac_size = 0;
    operation->is_sign = 0;
    operation->id = 0;

    return status;
}

static psa_status_t psa_mac_finalize_alg_and_key_validation(
    psa_algorithm_t alg,
    const psa_key_attributes_t *attributes,
    uint8_t *mac_size)
{
    psa_status_t status = PSA_ERROR_CORRUPTION_DETECTED;
    psa_key_type_t key_type = psa_get_key_type(attributes);
    size_t key_bits = psa_get_key_bits(attributes);

    if (!PSA_ALG_IS_MAC(alg)) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    /* Validate the combination of key type and algorithm */
    status = psa_mac_key_can_do(alg, key_type);
    if (status != PSA_SUCCESS) {
        return status;
    }

    /* Get the output length for the algorithm and key combination */
    *mac_size = PSA_MAC_LENGTH(key_type, key_bits, alg);

    if (*mac_size < 4) {
        /* A very short MAC is too short for security since it can be
         * brute-forced. Ancient protocols with 32-bit MACs do exist,
         * so we make this our minimum, even though 32 bits is still
         * too small for security. */
        return PSA_ERROR_NOT_SUPPORTED;
    }

    if (*mac_size > PSA_MAC_LENGTH(key_type, key_bits,
                                   PSA_ALG_FULL_LENGTH_MAC(alg))) {
        /* It's impossible to "truncate" to a larger length than the full length
         * of the algorithm. */
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    if (*mac_size > PSA_MAC_MAX_SIZE) {
        /* PSA_MAC_LENGTH returns the correct length even for a MAC algorithm
         * that is disabled in the compile-time configuration. The result can
         * therefore be larger than PSA_MAC_MAX_SIZE, which does take the
         * configuration into account. In this case, force a return of
         * PSA_ERROR_NOT_SUPPORTED here. Otherwise psa_mac_verify(), or
         * psa_mac_compute(mac_size=PSA_MAC_MAX_SIZE), would return
         * PSA_ERROR_BUFFER_TOO_SMALL for an unsupported algorithm whose MAC size
         * is larger than PSA_MAC_MAX_SIZE, which is misleading and which breaks
         * systematically generated tests. */
        return PSA_ERROR_NOT_SUPPORTED;
    }

    return PSA_SUCCESS;
}

static psa_status_t psa_mac_setup(psa_mac_operation_t *operation,
                                  mbedtls_svc_key_id_t key,
                                  psa_algorithm_t alg,
                                  int is_sign)
{
    psa_status_t status = PSA_ERROR_CORRUPTION_DETECTED;
    psa_status_t unlock_status = PSA_ERROR_CORRUPTION_DETECTED;
    psa_key_slot_t *slot = NULL;

    /* A context must be freshly initialized before it can be set up. */
    if (operation->id != 0) {
        status = PSA_ERROR_BAD_STATE;
        goto exit;
    }

    /* Make sure the driver-dependent part of the operation is zeroed.
     * This is a guarantee we make to drivers. Initializing the operation
     * does not necessarily take care of it, since the context is a
     * union and initializing a union does not necessarily initialize
     * all of its members. */
    memset(&operation->ctx, 0, sizeof(operation->ctx));

    status = psa_get_and_lock_key_slot_with_policy(
        key,
        &slot,
        is_sign ? PSA_KEY_USAGE_SIGN_MESSAGE : PSA_KEY_USAGE_VERIFY_MESSAGE,
        alg);
    if (status != PSA_SUCCESS) {
        goto exit;
    }

    status = psa_mac_finalize_alg_and_key_validation(alg, &slot->attr,
                                                     &operation->mac_size);
    if (status != PSA_SUCCESS) {
        goto exit;
    }

    operation->is_sign = is_sign;
    /* Dispatch the MAC setup call with validated input */
    if (is_sign) {
        status = psa_driver_wrapper_mac_sign_setup(operation,
                                                   &slot->attr,
                                                   slot->key.data,
                                                   slot->key.bytes,
                                                   alg);
    } else {
        status = psa_driver_wrapper_mac_verify_setup(operation,
                                                     &slot->attr,
                                                     slot->key.data,
                                                     slot->key.bytes,
                                                     alg);
    }

exit:
    if (status != PSA_SUCCESS) {
        psa_mac_abort(operation);
    }

    unlock_status = psa_unregister_read_under_mutex(slot);

    return (status == PSA_SUCCESS) ? unlock_status : status;
}

psa_status_t psa_mac_sign_setup(psa_mac_operation_t *operation,
                                mbedtls_svc_key_id_t key,
                                psa_algorithm_t alg)
{
    return psa_mac_setup(operation, key, alg, 1);
}

psa_status_t psa_mac_verify_setup(psa_mac_operation_t *operation,
                                  mbedtls_svc_key_id_t key,
                                  psa_algorithm_t alg)
{
    return psa_mac_setup(operation, key, alg, 0);
}

psa_status_t psa_mac_update(psa_mac_operation_t *operation,
                            const uint8_t *input,
                            size_t input_length)
{
    if (operation->id == 0) {
        return PSA_ERROR_BAD_STATE;
    }

    /* Don't require hash implementations to behave correctly on a
     * zero-length input, which may have an invalid pointer. */
    if (input_length == 0) {
        return PSA_SUCCESS;
    }

    psa_status_t status = psa_driver_wrapper_mac_update(operation,
                                                        input, input_length);
    if (status != PSA_SUCCESS) {
        psa_mac_abort(operation);
    }

    return status;
}

psa_status_t psa_mac_sign_finish(psa_mac_operation_t *operation,
                                 uint8_t *mac,
                                 size_t mac_size,
                                 size_t *mac_length)
{
    psa_status_t status = PSA_ERROR_CORRUPTION_DETECTED;
    psa_status_t abort_status = PSA_ERROR_CORRUPTION_DETECTED;

    if (operation->id == 0) {
        status = PSA_ERROR_BAD_STATE;
        goto exit;
    }

    if (!operation->is_sign) {
        status = PSA_ERROR_BAD_STATE;
        goto exit;
    }

    /* Sanity check. This will guarantee that mac_size != 0 (and so mac != NULL)
     * once all the error checks are done. */
    if (operation->mac_size == 0) {
        status = PSA_ERROR_BAD_STATE;
        goto exit;
    }

    if (mac_size < operation->mac_size) {
        status = PSA_ERROR_BUFFER_TOO_SMALL;
        goto exit;
    }

    status = psa_driver_wrapper_mac_sign_finish(operation,
                                                mac, operation->mac_size,
                                                mac_length);

exit:
    /* In case of success, set the potential excess room in the output buffer
     * to an invalid value, to avoid potentially leaking a longer MAC.
     * In case of error, set the output length and content to a safe default,
     * such that in case the caller misses an error check, the output would be
     * an unachievable MAC.
     */
    if (status != PSA_SUCCESS) {
        *mac_length = mac_size;
        operation->mac_size = 0;
    }

    if (mac != NULL) {
        psa_wipe_tag_output_buffer(mac, status, mac_size, *mac_length);
    }

    abort_status = psa_mac_abort(operation);

    return status == PSA_SUCCESS ? abort_status : status;
}

psa_status_t psa_mac_verify_finish(psa_mac_operation_t *operation,
                                   const uint8_t *mac,
                                   size_t mac_length)
{
    psa_status_t status = PSA_ERROR_CORRUPTION_DETECTED;
    psa_status_t abort_status = PSA_ERROR_CORRUPTION_DETECTED;

    if (operation->id == 0) {
        status = PSA_ERROR_BAD_STATE;
        goto exit;
    }

    if (operation->is_sign) {
        status = PSA_ERROR_BAD_STATE;
        goto exit;
    }

    if (operation->mac_size != mac_length) {
        status = PSA_ERROR_INVALID_SIGNATURE;
        goto exit;
    }

    status = psa_driver_wrapper_mac_verify_finish(operation,
                                                  mac, mac_length);

exit:
    abort_status = psa_mac_abort(operation);

    return status == PSA_SUCCESS ? abort_status : status;
}

static psa_status_t psa_mac_compute_internal(mbedtls_svc_key_id_t key,
                                             psa_algorithm_t alg,
                                             const uint8_t *input,
                                             size_t input_length,
                                             uint8_t *mac,
                                             size_t mac_size,
                                             size_t *mac_length,
                                             int is_sign)
{
    psa_status_t status = PSA_ERROR_CORRUPTION_DETECTED;
    psa_status_t unlock_status = PSA_ERROR_CORRUPTION_DETECTED;
    psa_key_slot_t *slot;
    uint8_t operation_mac_size = 0;

    status = psa_get_and_lock_key_slot_with_policy(
        key,
        &slot,
        is_sign ? PSA_KEY_USAGE_SIGN_MESSAGE : PSA_KEY_USAGE_VERIFY_MESSAGE,
        alg);
    if (status != PSA_SUCCESS) {
        goto exit;
    }

    status = psa_mac_finalize_alg_and_key_validation(alg, &slot->attr,
                                                     &operation_mac_size);
    if (status != PSA_SUCCESS) {
        goto exit;
    }

    if (mac_size < operation_mac_size) {
        status = PSA_ERROR_BUFFER_TOO_SMALL;
        goto exit;
    }

    status = psa_driver_wrapper_mac_compute(
        &slot->attr,
        slot->key.data, slot->key.bytes,
        alg,
        input, input_length,
        mac, operation_mac_size, mac_length);

exit:
    /* In case of success, set the potential excess room in the output buffer
     * to an invalid value, to avoid potentially leaking a longer MAC.
     * In case of error, set the output length and content to a safe default,
     * such that in case the caller misses an error check, the output would be
     * an unachievable MAC.
     */
    if (status != PSA_SUCCESS) {
        *mac_length = mac_size;
        operation_mac_size = 0;
    }

    psa_wipe_tag_output_buffer(mac, status, mac_size, *mac_length);

    unlock_status = psa_unregister_read_under_mutex(slot);

    return (status == PSA_SUCCESS) ? unlock_status : status;
}

psa_status_t psa_mac_compute(mbedtls_svc_key_id_t key,
                             psa_algorithm_t alg,
                             const uint8_t *input,
                             size_t input_length,
                             uint8_t *mac,
                             size_t mac_size,
                             size_t *mac_length)
{
    return psa_mac_compute_internal(key, alg,
                                    input, input_length,
                                    mac, mac_size, mac_length, 1);
}

psa_status_t psa_mac_verify(mbedtls_svc_key_id_t key,
                            psa_algorithm_t alg,
                            const uint8_t *input,
                            size_t input_length,
                            const uint8_t *mac,
                            size_t mac_length)
{
    psa_status_t status = PSA_ERROR_CORRUPTION_DETECTED;
    uint8_t actual_mac[PSA_MAC_MAX_SIZE];
    size_t actual_mac_length;

    status = psa_mac_compute_internal(key, alg,
                                      input, input_length,
                                      actual_mac, sizeof(actual_mac),
                                      &actual_mac_length, 0);
    if (status != PSA_SUCCESS) {
        goto exit;
    }

    if (mac_length != actual_mac_length) {
        status = PSA_ERROR_INVALID_SIGNATURE;
        goto exit;
    }
    if (mbedtls_ct_memcmp(mac, actual_mac, actual_mac_length) != 0) {
        status = PSA_ERROR_INVALID_SIGNATURE;
        goto exit;
    }

exit:
    mbedtls_platform_zeroize(actual_mac, sizeof(actual_mac));

    return status;
}

/****************************************************************/
/* Asymmetric cryptography */
/****************************************************************/

static psa_status_t psa_sign_verify_check_alg(int input_is_message,
                                              psa_algorithm_t alg)
{
    if (input_is_message) {
        if (!PSA_ALG_IS_SIGN_MESSAGE(alg)) {
            return PSA_ERROR_INVALID_ARGUMENT;
        }

        if (PSA_ALG_IS_SIGN_HASH(alg)) {
            if (!PSA_ALG_IS_HASH(PSA_ALG_SIGN_GET_HASH(alg))) {
                return PSA_ERROR_INVALID_ARGUMENT;
            }
        }
    } else {
        if (!PSA_ALG_IS_SIGN_HASH(alg)) {
            return PSA_ERROR_INVALID_ARGUMENT;
        }
    }

    return PSA_SUCCESS;
}

static psa_status_t psa_sign_internal(mbedtls_svc_key_id_t key,
                                      int input_is_message,
                                      psa_algorithm_t alg,
                                      const uint8_t *input,
                                      size_t input_length,
                                      uint8_t *signature,
                                      size_t signature_size,
                                      size_t *signature_length)
{
    psa_status_t status = PSA_ERROR_CORRUPTION_DETECTED;
    psa_status_t unlock_status = PSA_ERROR_CORRUPTION_DETECTED;
    psa_key_slot_t *slot;

    *signature_length = 0;

    status = psa_sign_verify_check_alg(input_is_message, alg);
    if (status != PSA_SUCCESS) {
        return status;
    }

    /* Immediately reject a zero-length signature buffer. This guarantees
     * that signature must be a valid pointer. (On the other hand, the input
     * buffer can in principle be empty since it doesn't actually have
     * to be a hash.) */
    if (signature_size == 0) {
        return PSA_ERROR_BUFFER_TOO_SMALL;
    }

    status = psa_get_and_lock_key_slot_with_policy(
        key, &slot,
        input_is_message ? PSA_KEY_USAGE_SIGN_MESSAGE :
        PSA_KEY_USAGE_SIGN_HASH,
        alg);

    if (status != PSA_SUCCESS) {
        goto exit;
    }

    if (!PSA_KEY_TYPE_IS_KEY_PAIR(slot->attr.type)) {
        status = PSA_ERROR_INVALID_ARGUMENT;
        goto exit;
    }

    if (input_is_message) {
        status = psa_driver_wrapper_sign_message(
            &slot->attr, slot->key.data, slot->key.bytes,
            alg, input, input_length,
            signature, signature_size, signature_length);
    } else {

        status = psa_driver_wrapper_sign_hash(
            &slot->attr, slot->key.data, slot->key.bytes,
            alg, input, input_length,
            signature, signature_size, signature_length);
    }


exit:
    psa_wipe_tag_output_buffer(signature, status, signature_size,
                               *signature_length);

    unlock_status = psa_unregister_read_under_mutex(slot);

    return (status == PSA_SUCCESS) ? unlock_status : status;
}

static psa_status_t psa_verify_internal(mbedtls_svc_key_id_t key,
                                        int input_is_message,
                                        psa_algorithm_t alg,
                                        const uint8_t *input,
                                        size_t input_length,
                                        const uint8_t *signature,
                                        size_t signature_length)
{
    psa_status_t status = PSA_ERROR_CORRUPTION_DETECTED;
    psa_status_t unlock_status = PSA_ERROR_CORRUPTION_DETECTED;
    psa_key_slot_t *slot;

    status = psa_sign_verify_check_alg(input_is_message, alg);
    if (status != PSA_SUCCESS) {
        return status;
    }

    status = psa_get_and_lock_key_slot_with_policy(
        key, &slot,
        input_is_message ? PSA_KEY_USAGE_VERIFY_MESSAGE :
        PSA_KEY_USAGE_VERIFY_HASH,
        alg);

    if (status != PSA_SUCCESS) {
        return status;
    }

    if (input_is_message) {
        status = psa_driver_wrapper_verify_message(
            &slot->attr, slot->key.data, slot->key.bytes,
            alg, input, input_length,
            signature, signature_length);
    } else {
        status = psa_driver_wrapper_verify_hash(
            &slot->attr, slot->key.data, slot->key.bytes,
            alg, input, input_length,
            signature, signature_length);
    }

    unlock_status = psa_unregister_read_under_mutex(slot);

    return (status == PSA_SUCCESS) ? unlock_status : status;

}

psa_status_t psa_sign_message_builtin(
    const psa_key_attributes_t *attributes,
    const uint8_t *key_buffer,
    size_t key_buffer_size,
    psa_algorithm_t alg,
    const uint8_t *input,
    size_t input_length,
    uint8_t *signature,
    size_t signature_size,
    size_t *signature_length)
{
    psa_status_t status = PSA_ERROR_CORRUPTION_DETECTED;

    if (PSA_ALG_IS_SIGN_HASH(alg)) {
        size_t hash_length;
        uint8_t hash[PSA_HASH_MAX_SIZE];

        status = psa_driver_wrapper_hash_compute(
            PSA_ALG_SIGN_GET_HASH(alg),
            input, input_length,
            hash, sizeof(hash), &hash_length);

        if (status != PSA_SUCCESS) {
            return status;
        }

        return psa_driver_wrapper_sign_hash(
            attributes, key_buffer, key_buffer_size,
            alg, hash, hash_length,
            signature, signature_size, signature_length);
    }

    return PSA_ERROR_NOT_SUPPORTED;
}

psa_status_t psa_sign_message(mbedtls_svc_key_id_t key,
                              psa_algorithm_t alg,
                              const uint8_t *input,
                              size_t input_length,
                              uint8_t *signature,
                              size_t signature_size,
                              size_t *signature_length)
{
    return psa_sign_internal(
        key, 1, alg, input, input_length,
        signature, signature_size, signature_length);
}

psa_status_t psa_verify_message_builtin(
    const psa_key_attributes_t *attributes,
    const uint8_t *key_buffer,
    size_t key_buffer_size,
    psa_algorithm_t alg,
    const uint8_t *input,
    size_t input_length,
    const uint8_t *signature,
    size_t signature_length)
{
    psa_status_t status = PSA_ERROR_CORRUPTION_DETECTED;

    if (PSA_ALG_IS_SIGN_HASH(alg)) {
        size_t hash_length;
        uint8_t hash[PSA_HASH_MAX_SIZE];

        status = psa_driver_wrapper_hash_compute(
            PSA_ALG_SIGN_GET_HASH(alg),
            input, input_length,
            hash, sizeof(hash), &hash_length);

        if (status != PSA_SUCCESS) {
            return status;
        }

        return psa_driver_wrapper_verify_hash(
            attributes, key_buffer, key_buffer_size,
            alg, hash, hash_length,
            signature, signature_length);
    }

    return PSA_ERROR_NOT_SUPPORTED;
}

psa_status_t psa_verify_message(mbedtls_svc_key_id_t key,
                                psa_algorithm_t alg,
                                const uint8_t *input,
                                size_t input_length,
                                const uint8_t *signature,
                                size_t signature_length)
{
    return psa_verify_internal(
        key, 1, alg, input, input_length,
        signature, signature_length);
}

psa_status_t psa_sign_hash(mbedtls_svc_key_id_t key,
                           psa_algorithm_t alg,
                           const uint8_t *hash,
                           size_t hash_length,
                           uint8_t *signature,
                           size_t signature_size,
                           size_t *signature_length)
{
    return psa_sign_internal(
        key, 0, alg, hash, hash_length,
        signature, signature_size, signature_length);
}

psa_status_t psa_verify_hash(mbedtls_svc_key_id_t key,
                             psa_algorithm_t alg,
                             const uint8_t *hash,
                             size_t hash_length,
                             const uint8_t *signature,
                             size_t signature_length)
{
    return psa_verify_internal(
        key, 0, alg, hash, hash_length,
        signature, signature_length);
}

psa_status_t psa_asymmetric_encrypt(mbedtls_svc_key_id_t key,
                                    psa_algorithm_t alg,
                                    const uint8_t *input,
                                    size_t input_length,
                                    const uint8_t *salt,
                                    size_t salt_length,
                                    uint8_t *output,
                                    size_t output_size,
                                    size_t *output_length)
{
    psa_status_t status = PSA_ERROR_CORRUPTION_DETECTED;
    psa_status_t unlock_status = PSA_ERROR_CORRUPTION_DETECTED;
    psa_key_slot_t *slot;

    (void) input;
    (void) input_length;
    (void) salt;
    (void) output;
    (void) output_size;

    *output_length = 0;

    if (!PSA_ALG_IS_RSA_OAEP(alg) && salt_length != 0) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    status = psa_get_and_lock_key_slot_with_policy(
        key, &slot, PSA_KEY_USAGE_ENCRYPT, alg);
    if (status != PSA_SUCCESS) {
        return status;
    }
    if (!(PSA_KEY_TYPE_IS_PUBLIC_KEY(slot->attr.type) ||
          PSA_KEY_TYPE_IS_KEY_PAIR(slot->attr.type))) {
        status = PSA_ERROR_INVALID_ARGUMENT;
        goto exit;
    }

    status = psa_driver_wrapper_asymmetric_encrypt(
        &slot->attr, slot->key.data, slot->key.bytes,
        alg, input, input_length, salt, salt_length,
        output, output_size, output_length);
exit:
    unlock_status = psa_unregister_read_under_mutex(slot);

    return (status == PSA_SUCCESS) ? unlock_status : status;
}

psa_status_t psa_asymmetric_decrypt(mbedtls_svc_key_id_t key,
                                    psa_algorithm_t alg,
                                    const uint8_t *input,
                                    size_t input_length,
                                    const uint8_t *salt,
                                    size_t salt_length,
                                    uint8_t *output,
                                    size_t output_size,
                                    size_t *output_length)
{
    psa_status_t status = PSA_ERROR_CORRUPTION_DETECTED;
    psa_status_t unlock_status = PSA_ERROR_CORRUPTION_DETECTED;
    psa_key_slot_t *slot;

    (void) input;
    (void) input_length;
    (void) salt;
    (void) output;
    (void) output_size;

    *output_length = 0;

    if (!PSA_ALG_IS_RSA_OAEP(alg) && salt_length != 0) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    status = psa_get_and_lock_key_slot_with_policy(
        key, &slot, PSA_KEY_USAGE_DECRYPT, alg);
    if (status != PSA_SUCCESS) {
        return status;
    }
    if (!PSA_KEY_TYPE_IS_KEY_PAIR(slot->attr.type)) {
        status = PSA_ERROR_INVALID_ARGUMENT;
        goto exit;
    }

    status = psa_driver_wrapper_asymmetric_decrypt(
        &slot->attr, slot->key.data, slot->key.bytes,
        alg, input, input_length, salt, salt_length,
        output, output_size, output_length);

exit:
    unlock_status = psa_unregister_read_under_mutex(slot);

    return (status == PSA_SUCCESS) ? unlock_status : status;
}

/****************************************************************/
/* Key encapsulation */
/****************************************************************/

psa_status_t psa_key_encapsulate(mbedtls_svc_key_id_t key,
    psa_algorithm_t alg,
    const psa_key_attributes_t *attributes,
    mbedtls_svc_key_id_t *output_key,
    uint8_t *ciphertext,
    size_t ciphertext_size,
    size_t *ciphertext_length)
{
    psa_status_t status = PSA_ERROR_CORRUPTION_DETECTED;
    psa_status_t unlock_status = PSA_ERROR_CORRUPTION_DETECTED;
    psa_key_slot_t *slot = NULL, *new_slot = NULL;
    psa_se_drv_table_entry_t *driver = NULL;
    size_t storage_size;

    *ciphertext_length = 0;

    if (!PSA_ALG_IS_KEY_ENCAPSULATION(alg)) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    status = psa_get_and_lock_key_slot_with_policy(
        key, &slot, PSA_KEY_USAGE_ENCRYPT, alg);
    if (status != PSA_SUCCESS) {
        return status;
    }
    if (!(PSA_KEY_TYPE_IS_PUBLIC_KEY(slot->attr.type) ||
        PSA_KEY_TYPE_IS_KEY_PAIR(slot->attr.type))) {
        status = PSA_ERROR_INVALID_ARGUMENT;
        goto exit;
    }

    status = psa_start_key_creation(
        PSA_KEY_CREATION_IMPORT, attributes, &new_slot, &driver);
    if (status != PSA_SUCCESS) goto exit;

    storage_size = PSA_KEY_ENCAPSULATE_OUTPUT_SIZE(slot->attr.type, slot->attr.bits);

    status = psa_allocate_buffer_to_slot(new_slot, storage_size);
    if (status != PSA_SUCCESS) goto exit;

    if (!PSA_KEY_TYPE_IS_UNSTRUCTURED(new_slot->attr.type)) {
        status = PSA_ERROR_INVALID_ARGUMENT;
        goto exit;
    }

    status = psa_driver_wrapper_key_encapsulate(
        &slot->attr, slot->key.data, slot->key.bytes,
        alg, attributes, 
        new_slot->key.data, new_slot->key.bytes, &new_slot->key.bytes,
        ciphertext, ciphertext_size, ciphertext_length);
    if (status != PSA_SUCCESS) goto exit;

    if (new_slot->attr.bits != 0 && PSA_BITS_TO_BYTES(new_slot->attr.bits) != new_slot->key.bytes) {
        status = PSA_ERROR_INVALID_ARGUMENT;
        goto exit;
    }

    status = psa_finish_key_creation(new_slot, driver, output_key);
exit:
    unlock_status = psa_unregister_read_under_mutex(slot);
    if (status == PSA_SUCCESS) status = unlock_status;

    if (status != PSA_SUCCESS) {
        psa_fail_key_creation(new_slot, driver);
        *output_key = MBEDTLS_SVC_KEY_ID_INIT;
    }

    return status;
}

psa_status_t psa_key_decapsulate(mbedtls_svc_key_id_t key,
    psa_algorithm_t alg,
    const uint8_t *ciphertext,
    size_t ciphertext_length,
    const psa_key_attributes_t *attributes,
    mbedtls_svc_key_id_t *output_key)
{
    psa_status_t status = PSA_ERROR_CORRUPTION_DETECTED;
    psa_status_t unlock_status = PSA_ERROR_CORRUPTION_DETECTED;
    psa_key_slot_t *slot = NULL, *new_slot = NULL;
    psa_se_drv_table_entry_t *driver = NULL;
    size_t storage_size;

    if (!PSA_ALG_IS_KEY_ENCAPSULATION(alg)) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    status = psa_get_and_lock_key_slot_with_policy(
        key, &slot, PSA_KEY_USAGE_DECRYPT, alg);
    if (status != PSA_SUCCESS) {
        return status;
    }
    if (!PSA_KEY_TYPE_IS_KEY_PAIR(slot->attr.type)) {
        status = PSA_ERROR_INVALID_ARGUMENT;
        goto exit;
    }

    status = psa_start_key_creation(
        PSA_KEY_CREATION_IMPORT, attributes, &new_slot, &driver);
    if (status != PSA_SUCCESS) goto exit;

    storage_size = PSA_KEY_ENCAPSULATE_OUTPUT_SIZE(slot->attr.type, slot->attr.bits);

    status = psa_allocate_buffer_to_slot(new_slot, storage_size);
    if (status != PSA_SUCCESS) goto exit;

    if (!PSA_KEY_TYPE_IS_UNSTRUCTURED(new_slot->attr.type)) {
        status = PSA_ERROR_INVALID_ARGUMENT;
        goto exit;
    }

    status = psa_driver_wrapper_key_decapsulate(
        &slot->attr, slot->key.data, slot->key.bytes,
        alg, ciphertext, ciphertext_length, attributes, 
        new_slot->key.data, new_slot->key.bytes, &new_slot->key.bytes);
    if (status != PSA_SUCCESS) goto exit;

    if (new_slot->attr.bits != 0 && PSA_BITS_TO_BYTES(new_slot->attr.bits) != new_slot->key.bytes) {
        status = PSA_ERROR_INVALID_ARGUMENT;
        goto exit;
    }

    status = psa_finish_key_creation(new_slot, driver, output_key);
exit:
    unlock_status = psa_unregister_read_under_mutex(slot);
    if (status == PSA_SUCCESS) status = unlock_status;

    if (status != PSA_SUCCESS) {
        psa_fail_key_creation(new_slot, driver);
        *output_key = MBEDTLS_SVC_KEY_ID_INIT;
    }

    return status;
}

/****************************************************************/
/* Asymmetric interruptible cryptography                        */
/****************************************************************/

psa_status_t psa_sign_hash_start(
    psa_sign_hash_interruptible_operation_t *operation,
    mbedtls_svc_key_id_t key, psa_algorithm_t alg,
    const uint8_t *hash, size_t hash_length)
{
    (void)operation;
    (void)key;
    (void)alg;
    (void)hash;
    (void)hash_length;
    return PSA_ERROR_NOT_SUPPORTED;
}

psa_status_t psa_sign_hash_abort(
    psa_sign_hash_interruptible_operation_t *operation)
{
    (void)operation;
    return PSA_SUCCESS;
}

psa_status_t psa_verify_hash_start(
    psa_verify_hash_interruptible_operation_t *operation,
    mbedtls_svc_key_id_t key, psa_algorithm_t alg,
    const uint8_t *hash, size_t hash_length,
    const uint8_t *signature, size_t signature_length)
{
    (void)operation;
    (void)key;
    (void)alg;
    (void)hash;
    (void)hash_length;
    (void)signature;
    (void)signature_length;
    return PSA_ERROR_NOT_SUPPORTED;
}

psa_status_t psa_verify_hash_abort(
    psa_verify_hash_interruptible_operation_t *operation)
{
    (void)operation;
    return PSA_SUCCESS;
}

/****************************************************************/
/* Symmetric cryptography */
/****************************************************************/

static psa_status_t psa_cipher_setup(psa_cipher_operation_t *operation,
                                     mbedtls_svc_key_id_t key,
                                     psa_algorithm_t alg,
                                     mbedtls_operation_t cipher_operation)
{
    psa_status_t status = PSA_ERROR_CORRUPTION_DETECTED;
    psa_status_t unlock_status = PSA_ERROR_CORRUPTION_DETECTED;
    psa_key_slot_t *slot = NULL;
    psa_key_usage_t usage = (cipher_operation == MBEDTLS_ENCRYPT ?
                             PSA_KEY_USAGE_ENCRYPT :
                             PSA_KEY_USAGE_DECRYPT);

    /* A context must be freshly initialized before it can be set up. */
    if (operation->id != 0) {
        status = PSA_ERROR_BAD_STATE;
        goto exit;
    }

    if (!PSA_ALG_IS_CIPHER(alg)) {
        status = PSA_ERROR_INVALID_ARGUMENT;
        goto exit;
    }

    status = psa_get_and_lock_key_slot_with_policy(key, &slot, usage, alg);
    if (status != PSA_SUCCESS) {
        goto exit;
    }

    /* Initialize the operation struct members, except for id. The id member
     * is used to indicate to psa_cipher_abort that there are resources to free,
     * so we only set it (in the driver wrapper) after resources have been
     * allocated/initialized. */
    operation->iv_set = 0;
    if (alg == PSA_ALG_ECB_NO_PADDING) {
        operation->iv_required = 0;
    } else {
        operation->iv_required = 1;
    }
    operation->default_iv_length = PSA_CIPHER_IV_LENGTH(slot->attr.type, alg);


    /* Make sure the driver-dependent part of the operation is zeroed.
     * This is a guarantee we make to drivers. Initializing the operation
     * does not necessarily take care of it, since the context is a
     * union and initializing a union does not necessarily initialize
     * all of its members. */
    memset(&operation->ctx, 0, sizeof(operation->ctx));

    /* Try doing the operation through a driver before using software fallback. */
    if (cipher_operation == MBEDTLS_ENCRYPT) {
        status = psa_driver_wrapper_cipher_encrypt_setup(operation,
                                                         &slot->attr,
                                                         slot->key.data,
                                                         slot->key.bytes,
                                                         alg);
    } else {
        status = psa_driver_wrapper_cipher_decrypt_setup(operation,
                                                         &slot->attr,
                                                         slot->key.data,
                                                         slot->key.bytes,
                                                         alg);
    }

exit:
    if (status != PSA_SUCCESS) {
        psa_cipher_abort(operation);
    }

    unlock_status = psa_unregister_read_under_mutex(slot);

    return (status == PSA_SUCCESS) ? unlock_status : status;
}

psa_status_t psa_cipher_encrypt_setup(psa_cipher_operation_t *operation,
                                      mbedtls_svc_key_id_t key,
                                      psa_algorithm_t alg)
{
    return psa_cipher_setup(operation, key, alg, MBEDTLS_ENCRYPT);
}

psa_status_t psa_cipher_decrypt_setup(psa_cipher_operation_t *operation,
                                      mbedtls_svc_key_id_t key,
                                      psa_algorithm_t alg)
{
    return psa_cipher_setup(operation, key, alg, MBEDTLS_DECRYPT);
}

psa_status_t psa_cipher_generate_iv(psa_cipher_operation_t *operation,
                                    uint8_t *iv,
                                    size_t iv_size,
                                    size_t *iv_length)
{
    psa_status_t status = PSA_ERROR_CORRUPTION_DETECTED;
    uint8_t local_iv[PSA_CIPHER_IV_MAX_SIZE];
    size_t default_iv_length = 0;

    if (operation->id == 0) {
        status = PSA_ERROR_BAD_STATE;
        goto exit;
    }

    if (operation->iv_set || !operation->iv_required) {
        status = PSA_ERROR_BAD_STATE;
        goto exit;
    }

    default_iv_length = operation->default_iv_length;
    if (iv_size < default_iv_length) {
        status = PSA_ERROR_BUFFER_TOO_SMALL;
        goto exit;
    }

    if (default_iv_length > PSA_CIPHER_IV_MAX_SIZE) {
        status = PSA_ERROR_GENERIC_ERROR;
        goto exit;
    }

    status = psa_generate_random(local_iv, default_iv_length);
    if (status != PSA_SUCCESS) {
        goto exit;
    }

    status = psa_driver_wrapper_cipher_set_iv(operation,
                                              local_iv, default_iv_length);

exit:
    if (status == PSA_SUCCESS) {
        memcpy(iv, local_iv, default_iv_length);
        *iv_length = default_iv_length;
        operation->iv_set = 1;
    } else {
        *iv_length = 0;
        psa_cipher_abort(operation);
        if (iv != NULL) {
            mbedtls_platform_zeroize(iv, default_iv_length);
        }
    }

    return status;
}

psa_status_t psa_cipher_set_iv(psa_cipher_operation_t *operation,
                               const uint8_t *iv,
                               size_t iv_length)
{
    psa_status_t status = PSA_ERROR_CORRUPTION_DETECTED;

    if (operation->id == 0) {
        status = PSA_ERROR_BAD_STATE;
        goto exit;
    }

    if (operation->iv_set || !operation->iv_required) {
        status = PSA_ERROR_BAD_STATE;
        goto exit;
    }

    if (iv_length > PSA_CIPHER_IV_MAX_SIZE) {
        status = PSA_ERROR_INVALID_ARGUMENT;
        goto exit;
    }

    status = psa_driver_wrapper_cipher_set_iv(operation,
                                              iv,
                                              iv_length);

exit:
    if (status == PSA_SUCCESS) {
        operation->iv_set = 1;
    } else {
        psa_cipher_abort(operation);
    }
    return status;
}

psa_status_t psa_cipher_update(psa_cipher_operation_t *operation,
                               const uint8_t *input,
                               size_t input_length,
                               uint8_t *output,
                               size_t output_size,
                               size_t *output_length)
{
    psa_status_t status = PSA_ERROR_CORRUPTION_DETECTED;

    if (operation->id == 0) {
        status = PSA_ERROR_BAD_STATE;
        goto exit;
    }

    if (operation->iv_required && !operation->iv_set) {
        status = PSA_ERROR_BAD_STATE;
        goto exit;
    }

    status = psa_driver_wrapper_cipher_update(operation,
                                              input,
                                              input_length,
                                              output,
                                              output_size,
                                              output_length);

exit:
    if (status != PSA_SUCCESS) {
        psa_cipher_abort(operation);
    }

    return status;
}

psa_status_t psa_cipher_finish(psa_cipher_operation_t *operation,
                               uint8_t *output,
                               size_t output_size,
                               size_t *output_length)
{
    psa_status_t abort_status, status = PSA_ERROR_GENERIC_ERROR;
    int32_t mask;

    if (operation->id == 0) {
        status = PSA_ERROR_BAD_STATE;
        goto exit;
    }

    if (operation->iv_required && !operation->iv_set) {
        status = PSA_ERROR_BAD_STATE;
        goto exit;
    }

    status = psa_driver_wrapper_cipher_finish(operation,
                                              output,
                                              output_size,
                                              output_length);

exit:
    // constant-time error handling to avoid padding oracle attacks
    mask = status >> 31; // SUCCESS: 0, error: -1
    abort_status = psa_cipher_abort(operation);
    return (status & mask) | (abort_status & ~mask);
}

psa_status_t psa_cipher_abort(psa_cipher_operation_t *operation)
{
    if (operation->id == 0) {
        /* The object has (apparently) been initialized but it is not (yet)
         * in use. It's ok to call abort on such an object, and there's
         * nothing to do. */
        return PSA_SUCCESS;
    }

    psa_driver_wrapper_cipher_abort(operation);

    operation->id = 0;
    operation->iv_set = 0;
    operation->iv_required = 0;

    return PSA_SUCCESS;
}

psa_status_t psa_cipher_encrypt(mbedtls_svc_key_id_t key,
                                psa_algorithm_t alg,
                                const uint8_t *input,
                                size_t input_length,
                                uint8_t *output,
                                size_t output_size,
                                size_t *output_length)
{
    psa_status_t status = PSA_ERROR_CORRUPTION_DETECTED;
    psa_status_t unlock_status = PSA_ERROR_CORRUPTION_DETECTED;
    psa_key_slot_t *slot = NULL;
    uint8_t local_iv[PSA_CIPHER_IV_MAX_SIZE];
    size_t default_iv_length = 0;

    if (!PSA_ALG_IS_CIPHER(alg)) {
        status = PSA_ERROR_INVALID_ARGUMENT;
        goto exit;
    }

    status = psa_get_and_lock_key_slot_with_policy(key, &slot,
                                                   PSA_KEY_USAGE_ENCRYPT,
                                                   alg);
    if (status != PSA_SUCCESS) {
        goto exit;
    }

    default_iv_length = PSA_CIPHER_IV_LENGTH(slot->attr.type, alg);
    if (default_iv_length > PSA_CIPHER_IV_MAX_SIZE) {
        status = PSA_ERROR_GENERIC_ERROR;
        goto exit;
    }

    if (default_iv_length > 0) {
        if (output_size < default_iv_length) {
            status = PSA_ERROR_BUFFER_TOO_SMALL;
            goto exit;
        }

        status = psa_generate_random(local_iv, default_iv_length);
        if (status != PSA_SUCCESS) {
            goto exit;
        }
    }

    status = psa_driver_wrapper_cipher_encrypt(
        &slot->attr, slot->key.data, slot->key.bytes,
        alg, local_iv, default_iv_length, input, input_length,
        psa_crypto_buffer_offset(output, default_iv_length),
        output_size - default_iv_length, output_length);

exit:
    unlock_status = psa_unregister_read_under_mutex(slot);
    if (status == PSA_SUCCESS) {
        status = unlock_status;
    }

    if (status == PSA_SUCCESS) {
        if (default_iv_length > 0) {
            memcpy(output, local_iv, default_iv_length);
        }
        *output_length += default_iv_length;
    } else {
        *output_length = 0;
    }

    return status;
}

psa_status_t psa_cipher_decrypt(mbedtls_svc_key_id_t key,
                                psa_algorithm_t alg,
                                const uint8_t *input,
                                size_t input_length,
                                uint8_t *output,
                                size_t output_size,
                                size_t *output_length)
{
    psa_status_t status = PSA_ERROR_CORRUPTION_DETECTED;
    psa_status_t unlock_status = PSA_ERROR_CORRUPTION_DETECTED;
    psa_key_slot_t *slot = NULL;

    if (!PSA_ALG_IS_CIPHER(alg)) {
        status = PSA_ERROR_INVALID_ARGUMENT;
        goto exit;
    }

    status = psa_get_and_lock_key_slot_with_policy(key, &slot,
                                                   PSA_KEY_USAGE_DECRYPT,
                                                   alg);
    if (status != PSA_SUCCESS) {
        goto exit;
    }

    if (input_length < PSA_CIPHER_IV_LENGTH(slot->attr.type, alg)) {
        status = PSA_ERROR_INVALID_ARGUMENT;
        goto exit;
    }

    status = psa_driver_wrapper_cipher_decrypt(
        &slot->attr, slot->key.data, slot->key.bytes,
        alg, input, input_length,
        output, output_size, output_length);

exit:
    unlock_status = psa_unregister_read_under_mutex(slot);
    if (status == PSA_SUCCESS) {
        status = unlock_status;
    }

    if (status != PSA_SUCCESS) {
        *output_length = 0;
    }

    return status;
}


/****************************************************************/
/* AEAD */
/****************************************************************/

/* Helper function to get the base algorithm from its variants. */
static psa_algorithm_t psa_aead_get_base_algorithm(psa_algorithm_t alg)
{
    return PSA_ALG_AEAD_WITH_DEFAULT_LENGTH_TAG(alg);
}

/* Helper function to perform common nonce length checks. */
static psa_status_t psa_aead_check_nonce_length(psa_algorithm_t alg,
                                                size_t nonce_length)
{
    psa_algorithm_t base_alg = psa_aead_get_base_algorithm(alg);

    switch (base_alg) {
#if defined(PSA_WANT_ALG_GCM)
        case PSA_ALG_GCM:
            /* Not checking max nonce size here as GCM spec allows almost
             * arbitrarily large nonces. Please note that we do not generally
             * recommend the usage of nonces of greater length than
             * PSA_AEAD_NONCE_MAX_SIZE, as large nonces are hashed to a shorter
             * size, which can then lead to collisions if you encrypt a very
             * large number of messages.*/
            if (nonce_length != 0) {
                return PSA_SUCCESS;
            }
            break;
#endif /* PSA_WANT_ALG_GCM */
#if defined(PSA_WANT_ALG_CCM)
        case PSA_ALG_CCM:
            if (nonce_length >= 7 && nonce_length <= 13) {
                return PSA_SUCCESS;
            }
            break;
#endif /* PSA_WANT_ALG_CCM */
#if defined(PSA_WANT_ALG_CHACHA20_POLY1305)
        case PSA_ALG_CHACHA20_POLY1305:
            if (nonce_length == 12) {
                return PSA_SUCCESS;
            } else if (nonce_length == 8) {
                return PSA_ERROR_NOT_SUPPORTED;
            }
            break;
#endif /* PSA_WANT_ALG_CHACHA20_POLY1305 */
#if defined(PSA_WANT_ALG_XCHACHA20_POLY1305)
        case PSA_ALG_XCHACHA20_POLY1305:
            if (nonce_length == 24) {
                return PSA_SUCCESS;
            }
            break;
#endif /* PSA_WANT_ALG_XCHACHA20_POLY1305 */
        default:
            (void) nonce_length;
            return PSA_ERROR_NOT_SUPPORTED;
    }

    return PSA_ERROR_INVALID_ARGUMENT;
}

static psa_status_t psa_aead_check_algorithm(psa_algorithm_t alg)
{
    if (!PSA_ALG_IS_AEAD(alg) || PSA_ALG_IS_WILDCARD(alg)) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    return PSA_SUCCESS;
}

psa_status_t psa_aead_encrypt(mbedtls_svc_key_id_t key,
                              psa_algorithm_t alg,
                              const uint8_t *nonce,
                              size_t nonce_length,
                              const uint8_t *additional_data,
                              size_t additional_data_length,
                              const uint8_t *plaintext,
                              size_t plaintext_length,
                              uint8_t *ciphertext,
                              size_t ciphertext_size,
                              size_t *ciphertext_length)
{
    psa_status_t status = PSA_ERROR_CORRUPTION_DETECTED;
    psa_key_slot_t *slot;

    *ciphertext_length = 0;

    status = psa_aead_check_algorithm(alg);
    if (status != PSA_SUCCESS) {
        return status;
    }

    status = psa_get_and_lock_key_slot_with_policy(
        key, &slot, PSA_KEY_USAGE_ENCRYPT, alg);
    if (status != PSA_SUCCESS) {
        return status;
    }

    status = psa_aead_check_nonce_length(alg, nonce_length);
    if (status != PSA_SUCCESS) {
        goto exit;
    }

    status = psa_driver_wrapper_aead_encrypt(
        &slot->attr, slot->key.data, slot->key.bytes,
        alg,
        nonce, nonce_length,
        additional_data, additional_data_length,
        plaintext, plaintext_length,
        ciphertext, ciphertext_size, ciphertext_length);

    if (status != PSA_SUCCESS && ciphertext_size != 0) {
        memset(ciphertext, 0, ciphertext_size);
    }

exit:
    psa_unregister_read_under_mutex(slot);

    return status;
}

psa_status_t psa_aead_decrypt(mbedtls_svc_key_id_t key,
                              psa_algorithm_t alg,
                              const uint8_t *nonce,
                              size_t nonce_length,
                              const uint8_t *additional_data,
                              size_t additional_data_length,
                              const uint8_t *ciphertext,
                              size_t ciphertext_length,
                              uint8_t *plaintext,
                              size_t plaintext_size,
                              size_t *plaintext_length)
{
    psa_status_t status = PSA_ERROR_CORRUPTION_DETECTED;
    psa_key_slot_t *slot;

    *plaintext_length = 0;

    status = psa_aead_check_algorithm(alg);
    if (status != PSA_SUCCESS) {
        return status;
    }

    status = psa_get_and_lock_key_slot_with_policy(
        key, &slot, PSA_KEY_USAGE_DECRYPT, alg);
    if (status != PSA_SUCCESS) {
        return status;
    }

    status = psa_aead_check_nonce_length(alg, nonce_length);
    if (status != PSA_SUCCESS) {
        goto exit;
    }

    status = psa_driver_wrapper_aead_decrypt(
        &slot->attr, slot->key.data, slot->key.bytes,
        alg,
        nonce, nonce_length,
        additional_data, additional_data_length,
        ciphertext, ciphertext_length,
        plaintext, plaintext_size, plaintext_length);

    if (status != PSA_SUCCESS && plaintext_size != 0) {
        memset(plaintext, 0, plaintext_size);
    }

exit:
    psa_unregister_read_under_mutex(slot);

    return status;
}

static psa_status_t psa_validate_tag_length(psa_algorithm_t alg)
{
    const uint8_t tag_len = PSA_ALG_AEAD_GET_TAG_LENGTH(alg);

    switch (PSA_ALG_AEAD_WITH_SHORTENED_TAG(alg, 0)) {
#if defined(PSA_WANT_ALG_CCM)
        case PSA_ALG_AEAD_WITH_SHORTENED_TAG(PSA_ALG_CCM, 0):
            /* CCM allows the following tag lengths: 4, 6, 8, 10, 12, 14, 16.*/
            if (tag_len < 4 || tag_len > 16 || tag_len % 2) {
                return PSA_ERROR_INVALID_ARGUMENT;
            }
            break;
#endif /* PSA_WANT_ALG_CCM */

#if defined(PSA_WANT_ALG_GCM)
        case PSA_ALG_AEAD_WITH_SHORTENED_TAG(PSA_ALG_GCM, 0):
            /* GCM allows the following tag lengths: 4, 8, 12, 13, 14, 15, 16. */
            if (tag_len != 4 && tag_len != 8 && (tag_len < 12 || tag_len > 16)) {
                return PSA_ERROR_INVALID_ARGUMENT;
            }
            break;
#endif /* PSA_WANT_ALG_GCM */

#if defined(PSA_WANT_ALG_CHACHA20_POLY1305) || defined(PSA_WANT_ALG_XCHACHA20_POLY1305)
        case PSA_ALG_AEAD_WITH_SHORTENED_TAG(PSA_ALG_CHACHA20_POLY1305, 0):
        case PSA_ALG_AEAD_WITH_SHORTENED_TAG(PSA_ALG_XCHACHA20_POLY1305, 0):
            /* We only support the default tag length. */
            if (tag_len != 16) {
                return PSA_ERROR_INVALID_ARGUMENT;
            }
            break;
#endif /* PSA_WANT_ALG_CHACHA20_POLY1305 || PSA_WANT_ALG_XCHACHA20_POLY1305 */

        default:
            (void) tag_len;
            return PSA_ERROR_NOT_SUPPORTED;
    }
    return PSA_SUCCESS;
}

/* Set the key for a multipart authenticated operation. */
static psa_status_t psa_aead_setup(psa_aead_operation_t *operation,
                                   int is_encrypt,
                                   mbedtls_svc_key_id_t key,
                                   psa_algorithm_t alg)
{
    psa_status_t status = PSA_ERROR_CORRUPTION_DETECTED;
    psa_status_t unlock_status = PSA_ERROR_CORRUPTION_DETECTED;
    psa_key_slot_t *slot = NULL;
    psa_key_usage_t key_usage = 0;

    status = psa_aead_check_algorithm(alg);
    if (status != PSA_SUCCESS) {
        goto exit;
    }

    if (operation->id != 0) {
        status = PSA_ERROR_BAD_STATE;
        goto exit;
    }

    if (operation->nonce_set || operation->lengths_set ||
        operation->ad_started || operation->body_started) {
        status = PSA_ERROR_BAD_STATE;
        goto exit;
    }

    /* Make sure the driver-dependent part of the operation is zeroed.
     * This is a guarantee we make to drivers. Initializing the operation
     * does not necessarily take care of it, since the context is a
     * union and initializing a union does not necessarily initialize
     * all of its members. */
    memset(&operation->ctx, 0, sizeof(operation->ctx));

    if (is_encrypt) {
        key_usage = PSA_KEY_USAGE_ENCRYPT;
    } else {
        key_usage = PSA_KEY_USAGE_DECRYPT;
    }

    status = psa_get_and_lock_key_slot_with_policy(key, &slot, key_usage,
                                                   alg);
    if (status != PSA_SUCCESS) {
        goto exit;
    }

    if ((status = psa_validate_tag_length(alg)) != PSA_SUCCESS) {
        goto exit;
    }

    if (is_encrypt) {
        status = psa_driver_wrapper_aead_encrypt_setup(operation,
                                                       &slot->attr,
                                                       slot->key.data,
                                                       slot->key.bytes,
                                                       alg);
    } else {
        status = psa_driver_wrapper_aead_decrypt_setup(operation,
                                                       &slot->attr,
                                                       slot->key.data,
                                                       slot->key.bytes,
                                                       alg);
    }
    if (status != PSA_SUCCESS) {
        goto exit;
    }

    operation->key_type = psa_get_key_type(&slot->attr);

exit:
    unlock_status = psa_unregister_read_under_mutex(slot);

    if (status == PSA_SUCCESS) {
        status = unlock_status;
        operation->alg = psa_aead_get_base_algorithm(alg);
        operation->is_encrypt = is_encrypt;
    } else {
        psa_aead_abort(operation);
    }

    return status;
}

/* Set the key for a multipart authenticated encryption operation. */
psa_status_t psa_aead_encrypt_setup(psa_aead_operation_t *operation,
                                    mbedtls_svc_key_id_t key,
                                    psa_algorithm_t alg)
{
    return psa_aead_setup(operation, 1, key, alg);
}

/* Set the key for a multipart authenticated decryption operation. */
psa_status_t psa_aead_decrypt_setup(psa_aead_operation_t *operation,
                                    mbedtls_svc_key_id_t key,
                                    psa_algorithm_t alg)
{
    return psa_aead_setup(operation, 0, key, alg);
}

/* Generate a random nonce / IV for multipart AEAD operation */
psa_status_t psa_aead_generate_nonce(psa_aead_operation_t *operation,
                                     uint8_t *nonce,
                                     size_t nonce_size,
                                     size_t *nonce_length)
{
    psa_status_t status = PSA_ERROR_CORRUPTION_DETECTED;
    uint8_t local_nonce[PSA_AEAD_NONCE_MAX_SIZE];
    size_t required_nonce_size = 0;

    *nonce_length = 0;

    if (operation->id == 0) {
        status = PSA_ERROR_BAD_STATE;
        goto exit;
    }

    if (operation->nonce_set || !operation->is_encrypt) {
        status = PSA_ERROR_BAD_STATE;
        goto exit;
    }

    /* For CCM, this size may not be correct according to the PSA
     * specification. The PSA Crypto 1.0.1 specification states:
     *
     * CCM encodes the plaintext length pLen in L octets, with L the smallest
     * integer >= 2 where pLen < 2^(8L). The nonce length is then 15 - L bytes.
     *
     * However this restriction that L has to be the smallest integer is not
     * applied in practice, and it is not implementable here since the
     * plaintext length may or may not be known at this time. */
    required_nonce_size = PSA_AEAD_NONCE_LENGTH(operation->key_type,
                                                operation->alg);
    if (nonce_size < required_nonce_size) {
        status = PSA_ERROR_BUFFER_TOO_SMALL;
        goto exit;
    }

    status = psa_generate_random(local_nonce, required_nonce_size);
    if (status != PSA_SUCCESS) {
        goto exit;
    }

    status = psa_aead_set_nonce(operation, local_nonce, required_nonce_size);

exit:
    if (status == PSA_SUCCESS) {
        memcpy(nonce, local_nonce, required_nonce_size);
        *nonce_length = required_nonce_size;
    } else {
        psa_aead_abort(operation);
    }

    return status;
}

/* Set the nonce for a multipart authenticated encryption or decryption
   operation.*/
psa_status_t psa_aead_set_nonce(psa_aead_operation_t *operation,
                                const uint8_t *nonce,
                                size_t nonce_length)
{
    psa_status_t status = PSA_ERROR_CORRUPTION_DETECTED;

    if (operation->id == 0) {
        status = PSA_ERROR_BAD_STATE;
        goto exit;
    }

    if (operation->nonce_set) {
        status = PSA_ERROR_BAD_STATE;
        goto exit;
    }

    status = psa_aead_check_nonce_length(operation->alg, nonce_length);
    if (status != PSA_SUCCESS) {
        status = PSA_ERROR_INVALID_ARGUMENT;
        goto exit;
    }

    status = psa_driver_wrapper_aead_set_nonce(operation, nonce,
                                               nonce_length);

exit:
    if (status == PSA_SUCCESS) {
        operation->nonce_set = 1;
    } else {
        psa_aead_abort(operation);
    }

    return status;
}

/* Declare the lengths of the message and additional data for multipart AEAD. */
psa_status_t psa_aead_set_lengths(psa_aead_operation_t *operation,
                                  size_t ad_length,
                                  size_t plaintext_length)
{
    psa_status_t status = PSA_ERROR_CORRUPTION_DETECTED;

    if (operation->id == 0) {
        status = PSA_ERROR_BAD_STATE;
        goto exit;
    }

    if (operation->lengths_set || operation->ad_started ||
        operation->body_started) {
        status = PSA_ERROR_BAD_STATE;
        goto exit;
    }

    switch (operation->alg) {
#if defined(PSA_WANT_ALG_GCM)
        case PSA_ALG_GCM:
            /* Lengths can only be too large for GCM if size_t is bigger than 32
             * bits. Without the guard this code will generate warnings on 32bit
             * builds. */
#if SIZE_MAX > UINT32_MAX
            if (((uint64_t) ad_length) >> 61 != 0 ||
                ((uint64_t) plaintext_length) > 0xFFFFFFFE0ull) {
                status = PSA_ERROR_INVALID_ARGUMENT;
                goto exit;
            }
#endif
            break;
#endif /* PSA_WANT_ALG_GCM */
#if defined(PSA_WANT_ALG_CCM)
        case PSA_ALG_CCM:
            if (ad_length > 0xFF00) {
                status = PSA_ERROR_INVALID_ARGUMENT;
                goto exit;
            }
            break;
#endif /* PSA_WANT_ALG_CCM */
#if defined(PSA_WANT_ALG_CHACHA20_POLY1305) || defined(PSA_WANT_ALG_XCHACHA20_POLY1305)
        case PSA_ALG_CHACHA20_POLY1305:
        case PSA_ALG_XCHACHA20_POLY1305:
            /* No length restrictions for ChaChaPoly. */
            break;
#endif /* PSA_WANT_ALG_CHACHA20_POLY1305 || PSA_WANT_ALG_XCHACHA20_POLY1305 */
        default:
            break;
    }

    status = psa_driver_wrapper_aead_set_lengths(operation, ad_length,
                                                 plaintext_length);

exit:
    if (status == PSA_SUCCESS) {
        operation->ad_remaining = ad_length;
        operation->body_remaining = plaintext_length;
        operation->lengths_set = 1;
    } else {
        psa_aead_abort(operation);
    }

    return status;
}

/* Pass additional data to an active multipart AEAD operation. */
psa_status_t psa_aead_update_ad(psa_aead_operation_t *operation,
                                const uint8_t *input,
                                size_t input_length)
{
    psa_status_t status = PSA_ERROR_CORRUPTION_DETECTED;

    if (operation->id == 0) {
        status = PSA_ERROR_BAD_STATE;
        goto exit;
    }

    if (!operation->nonce_set || operation->body_started) {
        status = PSA_ERROR_BAD_STATE;
        goto exit;
    }

    /* No input to add (zero length), nothing to do. */
    if (input_length == 0) {
        status = PSA_SUCCESS;
        goto exit;
    }

    if (operation->lengths_set) {
        if (operation->ad_remaining < input_length) {
            status = PSA_ERROR_INVALID_ARGUMENT;
            goto exit;
        }

        operation->ad_remaining -= input_length;
    }
#if defined(PSA_WANT_ALG_CCM)
    else if (operation->alg == PSA_ALG_CCM) {
        status = PSA_ERROR_BAD_STATE;
        goto exit;
    }
#endif /* PSA_WANT_ALG_CCM */

    status = psa_driver_wrapper_aead_update_ad(operation, input,
                                               input_length);

exit:
    if (status == PSA_SUCCESS) {
        operation->ad_started = 1;
    } else {
        psa_aead_abort(operation);
    }

    return status;
}

/* Encrypt or decrypt a message fragment in an active multipart AEAD
   operation.*/
psa_status_t psa_aead_update(psa_aead_operation_t *operation,
                             const uint8_t *input,
                             size_t input_length,
                             uint8_t *output,
                             size_t output_size,
                             size_t *output_length)
{
    psa_status_t status = PSA_ERROR_CORRUPTION_DETECTED;

    *output_length = 0;

    if (operation->id == 0) {
        status = PSA_ERROR_BAD_STATE;
        goto exit;
    }

    if (!operation->nonce_set) {
        status = PSA_ERROR_BAD_STATE;
        goto exit;
    }

    if (operation->lengths_set) {
        /* Additional data length was supplied, but not all the additional
           data was supplied.*/
        if (operation->ad_remaining != 0) {
            status = PSA_ERROR_INVALID_ARGUMENT;
            goto exit;
        }

        /* Too much data provided. */
        if (operation->body_remaining < input_length) {
            status = PSA_ERROR_INVALID_ARGUMENT;
            goto exit;
        }

        operation->body_remaining -= input_length;
    }
#if defined(PSA_WANT_ALG_CCM)
    else if (operation->alg == PSA_ALG_CCM) {
        status = PSA_ERROR_BAD_STATE;
        goto exit;
    }
#endif /* PSA_WANT_ALG_CCM */

    status = psa_driver_wrapper_aead_update(operation, input, input_length,
                                            output, output_size,
                                            output_length);

exit:
    if (status == PSA_SUCCESS) {
        operation->body_started = 1;
    } else {
        psa_aead_abort(operation);
    }

    return status;
}

static psa_status_t psa_aead_final_checks(const psa_aead_operation_t *operation)
{
    if (operation->id == 0 || !operation->nonce_set) {
        return PSA_ERROR_BAD_STATE;
    }

    if (operation->lengths_set && (operation->ad_remaining != 0 ||
                                   operation->body_remaining != 0)) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    return PSA_SUCCESS;
}

/* Finish encrypting a message in a multipart AEAD operation. */
psa_status_t psa_aead_finish(psa_aead_operation_t *operation,
                             uint8_t *ciphertext,
                             size_t ciphertext_size,
                             size_t *ciphertext_length,
                             uint8_t *tag,
                             size_t tag_size,
                             size_t *tag_length)
{
    psa_status_t status = PSA_ERROR_CORRUPTION_DETECTED;

    *ciphertext_length = 0;
    *tag_length = tag_size;

    status = psa_aead_final_checks(operation);
    if (status != PSA_SUCCESS) {
        goto exit;
    }

    if (!operation->is_encrypt) {
        status = PSA_ERROR_BAD_STATE;
        goto exit;
    }

    status = psa_driver_wrapper_aead_finish(operation, ciphertext,
                                            ciphertext_size,
                                            ciphertext_length,
                                            tag, tag_size, tag_length);

exit:


    /* In case the operation fails and the user fails to check for failure or
     * the zero tag size, make sure the tag is set to something implausible.
     * Even if the operation succeeds, make sure we clear the rest of the
     * buffer to prevent potential leakage of anything previously placed in
     * the same buffer.*/
    psa_wipe_tag_output_buffer(tag, status, tag_size, *tag_length);

    psa_aead_abort(operation);

    return status;
}

/* Finish authenticating and decrypting a message in a multipart AEAD
   operation.*/
psa_status_t psa_aead_verify(psa_aead_operation_t *operation,
                             uint8_t *plaintext,
                             size_t plaintext_size,
                             size_t *plaintext_length,
                             const uint8_t *tag,
                             size_t tag_length)
{
    psa_status_t status = PSA_ERROR_CORRUPTION_DETECTED;

    *plaintext_length = 0;

    status = psa_aead_final_checks(operation);
    if (status != PSA_SUCCESS) {
        goto exit;
    }

    if (operation->is_encrypt) {
        status = PSA_ERROR_BAD_STATE;
        goto exit;
    }

    status = psa_driver_wrapper_aead_verify(operation, plaintext,
                                            plaintext_size,
                                            plaintext_length,
                                            tag, tag_length);

exit:
    psa_aead_abort(operation);

    return status;
}

/* Abort an AEAD operation. */
psa_status_t psa_aead_abort(psa_aead_operation_t *operation)
{
    psa_status_t status = PSA_ERROR_CORRUPTION_DETECTED;

    if (operation->id == 0) {
        /* The object has (apparently) been initialized but it is not (yet)
         * in use. It's ok to call abort on such an object, and there's
         * nothing to do. */
        return PSA_SUCCESS;
    }

    status = psa_driver_wrapper_aead_abort(operation);

    memset(operation, 0, sizeof(*operation));

    return status;
}

/****************************************************************/
/* Generators */
/****************************************************************/

psa_status_t psa_key_derivation_abort(psa_key_derivation_operation_t *operation)
{
    psa_status_t status = PSA_SUCCESS;
    if (operation->alg != 0) {
        status = psa_driver_wrapper_key_derivation_abort(operation);
    }
    mbedtls_platform_zeroize(operation, sizeof(*operation));
    return status;
}

psa_status_t psa_key_derivation_get_capacity(const psa_key_derivation_operation_t *operation,
                                             size_t *capacity)
{
    if (operation->alg == 0) {
        /* This is a blank key derivation operation. */
        return PSA_ERROR_BAD_STATE;
    }

    *capacity = operation->capacity;
    return PSA_SUCCESS;
}

psa_status_t psa_key_derivation_set_capacity(psa_key_derivation_operation_t *operation,
                                             size_t capacity)
{
    if (operation->alg == 0) {
        return PSA_ERROR_BAD_STATE;
    }
    if (capacity > operation->capacity) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }
    operation->capacity = capacity;
    return psa_driver_wrapper_key_derivation_set_capacity(operation, capacity);
}

#define PSA_KEY_DERIVATION_OUTPUT -1  // used as step below

static psa_status_t psa_key_derivation_check_state(
    psa_key_derivation_operation_t *operation,
    int step)
{
    psa_algorithm_t alg = operation->alg;
    if (alg == 0) return PSA_ERROR_BAD_STATE;
    if (PSA_ALG_IS_KEY_AGREEMENT(alg)) alg = PSA_ALG_KEY_AGREEMENT_GET_KDF(alg);
    if (step != PSA_KEY_DERIVATION_OUTPUT && operation->no_input) return PSA_ERROR_BAD_STATE;

#ifdef PSA_WANT_ALG_HKDF
    if (PSA_ALG_IS_HKDF(alg)) {
        switch (step) {
        case PSA_KEY_DERIVATION_INPUT_SALT:
            if (operation->salt_set || operation->secret_set) return PSA_ERROR_BAD_STATE;
            operation->salt_set = 1;
            break;
        case PSA_KEY_DERIVATION_INPUT_SECRET:
            if (operation->secret_set) return PSA_ERROR_BAD_STATE;
            operation->secret_set = 1;
            break;
        case PSA_KEY_DERIVATION_INPUT_INFO:
            if (operation->info_set) return PSA_ERROR_BAD_STATE;
            operation->info_set = 1;
            break;
        case PSA_KEY_DERIVATION_OUTPUT:
            if (!operation->secret_set || !operation->info_set) return PSA_ERROR_BAD_STATE;
            operation->no_input = 1;
            break;
        default:
            return PSA_ERROR_INVALID_ARGUMENT;
        }
    } else
#endif /* PSA_WANT_ALG_HKDF */

#ifdef PSA_WANT_ALG_HKDF_EXTRACT
    if (PSA_ALG_IS_HKDF_EXTRACT(alg)) {
        switch (step) {
        case PSA_KEY_DERIVATION_INPUT_SALT:
            if (operation->salt_set) return PSA_ERROR_BAD_STATE;
            operation->salt_set = 1;
            break;
        case PSA_KEY_DERIVATION_INPUT_SECRET:
            if (operation->secret_set || !operation->salt_set) return PSA_ERROR_BAD_STATE;
            operation->secret_set = 1;
            break;
        case PSA_KEY_DERIVATION_OUTPUT:
            if (!operation->secret_set) return PSA_ERROR_BAD_STATE;
            operation->no_input = 1;
            break;
        default:
            return PSA_ERROR_INVALID_ARGUMENT;
        }
    } else
#endif /* PSA_WANT_ALG_HKDF_EXTRACT */

#ifdef PSA_WANT_ALG_HKDF_EXPAND
    if (PSA_ALG_IS_HKDF_EXPAND(alg)) {
        switch (step) {
        case PSA_KEY_DERIVATION_INPUT_SECRET:
            if (operation->secret_set) return PSA_ERROR_BAD_STATE;
            operation->secret_set = 1;
            break;
        case PSA_KEY_DERIVATION_INPUT_INFO:
            if (operation->info_set || !operation->secret_set) return PSA_ERROR_BAD_STATE;
            operation->info_set = 1;
            break;
        case PSA_KEY_DERIVATION_OUTPUT:
            if (!operation->info_set) return PSA_ERROR_BAD_STATE;
            operation->no_input = 1;
            break;
        default:
            return PSA_ERROR_INVALID_ARGUMENT;
        }
    } else
#endif /* PSA_WANT_ALG_HKDF_EXPAND */

#if defined(PSA_WANT_ALG_TLS12_PRF) || defined(PSA_WANT_ALG_TLS12_PSK_TO_MS)
    if (PSA_ALG_IS_TLS12_PRF(alg) || PSA_ALG_IS_TLS12_PSK_TO_MS(alg)) {
        switch (step) {
        case PSA_KEY_DERIVATION_INPUT_SEED:
            if (operation->seed_set) return PSA_ERROR_BAD_STATE;
            operation->seed_set = 1;
            break;
        case PSA_KEY_DERIVATION_INPUT_OTHER_SECRET:
            if (PSA_ALG_IS_TLS12_PRF(alg)) return PSA_ERROR_INVALID_ARGUMENT;
            if (!operation->seed_set || operation->secret_set || operation->passw_set) return PSA_ERROR_BAD_STATE;
            operation->passw_set = 1;
            break;
        case PSA_KEY_DERIVATION_INPUT_SECRET:
            if (!operation->seed_set || operation->secret_set) return PSA_ERROR_BAD_STATE;
            operation->secret_set = 1;
            break;
        case PSA_KEY_DERIVATION_INPUT_LABEL:
            if (!operation->secret_set || operation->label_set) return PSA_ERROR_BAD_STATE;
            operation->label_set = 1;
            break;
        case PSA_KEY_DERIVATION_OUTPUT:
            if (!operation->label_set) return PSA_ERROR_BAD_STATE;
            operation->no_input = 1;
            break;
        default:
            return PSA_ERROR_INVALID_ARGUMENT;
        }
    } else
#endif /* PSA_WANT_ALG_TLS12_PRF || PSA_WANT_ALG_TLS12_PSK_TO_MS */

#if defined(PSA_WANT_ALG_PBKDF2_HMAC) || defined(PSA_WANT_ALG_PBKDF2_AES_CMAC_PRF_128)
#if defined(PSA_WANT_ALG_PBKDF2_HMAC) && defined(PSA_WANT_ALG_PBKDF2_AES_CMAC_PRF_128)
    if (PSA_ALG_IS_PBKDF2_HMAC(alg) || alg == PSA_ALG_PBKDF2_AES_CMAC_PRF_128) {
#elif defined(PSA_WANT_ALG_PBKDF2_HMAC)
    if (PSA_ALG_IS_PBKDF2_HMAC(alg)) {
#elif defined(PSA_WANT_ALG_PBKDF2_AES_CMAC_PRF_128)
    if (alg == PSA_ALG_PBKDF2_AES_CMAC_PRF_128) {
#endif
        switch (step) {
        case PSA_KEY_DERIVATION_INPUT_COST:
            if (operation->cost_set) return PSA_ERROR_BAD_STATE;
            operation->cost_set = 1;
            break;
        case PSA_KEY_DERIVATION_INPUT_SALT:
            if (!operation->cost_set || operation->passw_set) return PSA_ERROR_BAD_STATE;
            operation->salt_set = 1;
            break;
        case PSA_KEY_DERIVATION_INPUT_PASSWORD:
            if (!operation->salt_set || operation->passw_set) return PSA_ERROR_BAD_STATE;
            operation->passw_set = 1;
            break;
        case PSA_KEY_DERIVATION_OUTPUT:
            if (!operation->passw_set) return PSA_ERROR_BAD_STATE;
            operation->no_input = 1;
            break;
        default:
            return PSA_ERROR_INVALID_ARGUMENT;
        }
    } else
#endif /* PSA_WANT_ALG_PBKDF2_HMAC || PSA_WANT_ALG_PBKDF2_AES_CMAC_PRF_128 */

#ifdef PSA_WANT_ALG_TLS12_ECJPAKE_TO_PMS
    if (alg == PSA_ALG_TLS12_ECJPAKE_TO_PMS) {
        switch (step) {
        case PSA_KEY_DERIVATION_INPUT_SECRET:
            if (operation->secret_set) return PSA_ERROR_BAD_STATE;
            operation->secret_set = 1;
            break;
        case PSA_KEY_DERIVATION_OUTPUT:
            if (!operation->secret_set) return PSA_ERROR_BAD_STATE;
            operation->no_input = 1;
            break;
        default:
            return PSA_ERROR_INVALID_ARGUMENT;
        }
    } else
#endif /* PSA_WANT_ALG_TLS12_ECJPAKE_TO_PMS */

#ifdef PSA_WANT_ALG_SRP_PASSWORD_HASH
    if (PSA_ALG_IS_SRP_PASSWORD_HASH(alg)) {
        switch (step) {
        case PSA_KEY_DERIVATION_INPUT_INFO:
            if (operation->info_set) return PSA_ERROR_BAD_STATE;
            operation->info_set = 1;
            break;
        case PSA_KEY_DERIVATION_INPUT_PASSWORD:
            if (!operation->info_set || operation->passw_set) return PSA_ERROR_BAD_STATE;
            operation->passw_set = 1;
            break;
        case PSA_KEY_DERIVATION_INPUT_SALT:
            if (!operation->passw_set || operation->salt_set) return PSA_ERROR_BAD_STATE;
            operation->salt_set = 1;
            break;
        case PSA_KEY_DERIVATION_OUTPUT:
            if (!operation->salt_set) return PSA_ERROR_BAD_STATE;
            operation->no_input = 1;
            break;
        default:
            return PSA_ERROR_INVALID_ARGUMENT;
        }
    } else
#endif /* PSA_WANT_ALG_SRP_PASSWORD_HASH */

#ifdef PSA_WANT_ALG_WPA3_SAE_H2E
    if (PSA_ALG_IS_WPA3_SAE_H2E(alg)) {
        switch (step) {
        case PSA_KEY_DERIVATION_INPUT_SALT:
            if (operation->salt_set) return PSA_ERROR_BAD_STATE;
            operation->salt_set = 1;
            break;
        case PSA_KEY_DERIVATION_INPUT_PASSWORD:
            if (!operation->salt_set || operation->passw_set) return PSA_ERROR_BAD_STATE;
            operation->passw_set = 1;
            break;
        case PSA_KEY_DERIVATION_INPUT_INFO:
            if (!operation->passw_set || operation->info_set) return PSA_ERROR_BAD_STATE;
            operation->info_set = 1;
            break;
        case PSA_KEY_DERIVATION_OUTPUT:
            if (!operation->passw_set) return PSA_ERROR_BAD_STATE;
            operation->no_input = 1;
            break;
        default:
            return PSA_ERROR_INVALID_ARGUMENT;
        }
    } else
#endif /* PSA_WANT_ALG_WPA3_SAE_PT */

#if defined(PSA_WANT_ALG_SP800_108_COUNTER_HMAC) || defined(PSA_WANT_ALG_SP800_108_COUNTER_CMAC)
#if defined(PSA_WANT_ALG_SP800_108_COUNTER_HMAC) && defined(PSA_WANT_ALG_SP800_108_COUNTER_CMAC)
        if (PSA_ALG_IS_SP800_108_COUNTER_HMAC(alg) || alg == PSA_ALG_SP800_108_COUNTER_CMAC) {
#elif defined(PSA_WANT_ALG_SP800_108_COUNTER_HMAC)
        if (PSA_ALG_IS_SP800_108_COUNTER_HMAC(alg)) {
#elif defined(PSA_WANT_ALG_SP800_108_COUNTER_CMAC)
        if (alg == PSA_ALG_SP800_108_COUNTER_CMAC) {
#endif
        switch (step) {
        case PSA_KEY_DERIVATION_INPUT_SECRET:
            if (operation->secret_set) return PSA_ERROR_BAD_STATE;
            operation->secret_set = 1;
            break;
        case PSA_KEY_DERIVATION_INPUT_LABEL:
            if (!operation->secret_set || operation->label_set || operation->context_set) return PSA_ERROR_BAD_STATE;
            operation->label_set = 1;
            break;
        case PSA_KEY_DERIVATION_INPUT_CONTEXT:
            if (!operation->secret_set || operation->context_set) return PSA_ERROR_BAD_STATE;
            operation->context_set = 1;
            break;
        case PSA_KEY_DERIVATION_OUTPUT:
            if (!operation->secret_set) return PSA_ERROR_BAD_STATE;
            operation->no_input = 1;
            break;
        default:
            return PSA_ERROR_INVALID_ARGUMENT;
        }
    } else
#endif /* PSA_WANT_ALG_SP800_108_COUNTER_HMAC || PSA_WANT_ALG_SP800_108_COUNTER_CMAC */

    {
        return PSA_ERROR_NOT_SUPPORTED;
    }

    return PSA_SUCCESS;
}

psa_status_t psa_key_derivation_output_bytes_internal(
    psa_key_derivation_operation_t *operation,
    uint8_t *output,
    size_t output_length)
{
    psa_status_t status;

    if (output_length <= operation->capacity) {
        status = psa_driver_wrapper_key_derivation_output_bytes(operation, output, output_length);
        operation->capacity -= output_length;
        if (status == PSA_SUCCESS) return PSA_SUCCESS;
        psa_key_derivation_abort(operation);
    } else {
        // Not enough capacity:
        // We have to return PSA_ERROR_INSUFFICIENT_DATA and enter a special
        // error state where the operation is cleaned up but the object is
        // still active and further calls to output_bytes() continue to
        // return PSA_ERROR_INSUFFICIENT_DATA.
        psa_driver_wrapper_key_derivation_abort(operation); // clear inner context
        operation->capacity = 0;
        status = PSA_ERROR_INSUFFICIENT_DATA;
    }

    if (output != NULL) {
        memset(output, '!', output_length);
    }
    return status;
}

psa_status_t psa_key_derivation_output_bytes(
    psa_key_derivation_operation_t *operation,
    uint8_t *output,
    size_t output_length)
{
    psa_status_t status;

    status = psa_key_derivation_check_state(operation, PSA_KEY_DERIVATION_OUTPUT);
    if (status != PSA_SUCCESS) return status;

    if (operation->no_output) {
        return PSA_ERROR_NOT_PERMITTED;
    }

    return psa_key_derivation_output_bytes_internal(operation, output, output_length);
}

#ifdef PSA_WANT_KEY_TYPE_WPA3_SAE_PT
static psa_status_t psa_wpa3_sae_pt_check_hash(psa_algorithm_t alg, psa_key_type_t key_type, size_t bits)
{
    psa_algorithm_t hash;
    if (!PSA_ALG_IS_WPA3_SAE_H2E(alg)) return PSA_ERROR_INVALID_ARGUMENT;
    if (PSA_KEY_TYPE_IS_WPA3_SAE_ECC_PT(key_type)) {
        if (bits <= 256) hash = PSA_ALG_SHA_256;
        else if (bits <= 384) hash = PSA_ALG_SHA_384;
        else hash = PSA_ALG_SHA_512;
    } else if (PSA_KEY_TYPE_IS_WPA3_SAE_DH_PT(key_type)) {
        if (bits <= 2048) hash = PSA_ALG_SHA_256;
        else if (bits <= 3072) hash = PSA_ALG_SHA_384;
        else hash = PSA_ALG_SHA_512;
    } else {
        return PSA_ERROR_INVALID_ARGUMENT;
    }
    if (PSA_ALG_GET_HASH(alg) != hash) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }
    return PSA_SUCCESS;
}
#endif

static psa_status_t psa_generate_derived_key_internal(
    psa_key_slot_t *slot,
    size_t bits,
    psa_key_derivation_operation_t *operation)
{
#ifdef MBEDTLS_PSA_STATIC_KEY_SLOTS
    uint8_t data[256]; // large enough for all derivable keys
#else
    uint8_t *data = NULL;
#endif
    size_t bytes = PSA_BITS_TO_BYTES(bits);
    size_t storage_size = bytes;
    psa_status_t status = PSA_ERROR_CORRUPTION_DETECTED;
    psa_key_type_t type = slot->attr.type;
    int calculate_key = 0;

    if (PSA_KEY_TYPE_IS_PUBLIC_KEY(type)) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    if (key_type_is_raw_bytes(type)) {
        if (bits % 8 != 0) return PSA_ERROR_INVALID_ARGUMENT;
#ifdef PSA_WANT_KEY_TYPE_ECC_KEY_PAIR_DERIVE
    } else if (PSA_KEY_TYPE_IS_ECC_KEY_PAIR(type)) {
        if (type == PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_TWISTED_EDWARDS)) {
            bytes = PSA_BITS_TO_BYTES(bits + 1); // ED needs an extra bit
        }
        calculate_key = 1;
#endif /* PSA_WANT_KEY_TYPE_ECC_KEY_PAIR_DERIVE */
#ifdef PSA_WANT_KEY_TYPE_ML_DSA_KEY_PAIR_DERIVE
    } else if (type == PSA_KEY_TYPE_ML_DSA_KEY_PAIR) {
        storage_size = bytes = 32;
#endif /* PSA_WANT_KEY_TYPE_ML_DSA_KEY_PAIR_DERIVE */
#ifdef PSA_WANT_KEY_TYPE_ML_KEM_KEY_PAIR_DERIVE
    } else if (type == PSA_KEY_TYPE_ML_KEM_KEY_PAIR) {
        storage_size = bytes = 64;
#endif /* PSA_WANT_KEY_TYPE_ML_KEM_KEY_PAIR_DERIVE */
#ifdef PSA_WANT_KEY_TYPE_SPAKE2P_KEY_PAIR_DERIVE
    } else if (PSA_KEY_TYPE_IS_SPAKE2P_KEY_PAIR(type)) {
        storage_size = bytes * 2u;  // w0 : w1
        bytes = storage_size + 16u; // w0s : w1s
        calculate_key = 1;
#endif /* PSA_WANT_KEY_TYPE_SPAKE2P_KEY_PAIR_DERIVE */
#ifdef PSA_WANT_KEY_TYPE_SRP_KEY_PAIR_DERIVE
    } else if (PSA_KEY_TYPE_IS_SRP_KEY_PAIR(type)) {
        if (!PSA_ALG_IS_SRP_PASSWORD_HASH(operation->alg)) return PSA_ERROR_INVALID_ARGUMENT;
        storage_size = bytes = PSA_HASH_LENGTH(operation->alg);
#endif /* PSA_WANT_KEY_TYPE_SRP_KEY_PAIR_DERIVE */
#ifdef PSA_WANT_KEY_TYPE_WPA3_SAE_PT
    } else if (PSA_KEY_TYPE_IS_WPA3_SAE_PT(type)) {
        status = psa_wpa3_sae_pt_check_hash(operation->alg, type, bits);
        if (status != PSA_SUCCESS) return status;
        storage_size = bytes * 2u;  // x : y
        bytes = PSA_HASH_LENGTH(operation->alg);
        calculate_key = 1;
#endif /* PSA_WANT_KEY_TYPE_SPAKE2P_KEY_PAIR_DERIVE */
    } else {
        (void)calculate_key;
        return PSA_ERROR_NOT_SUPPORTED;
    }

#ifdef MBEDTLS_PSA_STATIC_KEY_SLOTS
    if (bytes > sizeof data) {
        return PSA_ERROR_INSUFFICIENT_MEMORY;
    }
#else
    data = mbedtls_calloc(1, bytes);
    if (data == NULL) {
        return PSA_ERROR_INSUFFICIENT_MEMORY;
    }
#endif
    slot->attr.bits = (psa_key_bits_t) bits;

    if (psa_key_lifetime_is_external(slot->attr.lifetime)) {
        status = psa_driver_wrapper_get_key_buffer_size(&slot->attr,
                                                        &storage_size);
        if (status != PSA_SUCCESS) {
            goto exit;
        }
    }
    status = psa_allocate_buffer_to_slot(slot, storage_size);
    if (status != PSA_SUCCESS) {
        goto exit;
    }

    do {
        status = psa_key_derivation_output_bytes_internal(operation, data, bytes);
        if (status != PSA_SUCCESS) goto exit;

#if defined(PSA_WANT_KEY_TYPE_ECC_KEY_PAIR_DERIVE) || defined(PSA_WANT_KEY_TYPE_SPAKE2P_KEY_PAIR_DERIVE) || \
    defined(PSA_WANT_KEY_TYPE_WPA3_SAE_PT)
        if (calculate_key) {
            status = psa_driver_wrapper_derive_key(
                &slot->attr,
                data, bytes,
                slot->key.data, slot->key.bytes, &slot->key.bytes);

        } else
#endif /* PSA_WANT_KEY_TYPE_ECC_KEY_PAIR_DERIVE || PSA_WANT_KEY_TYPE_SPAKE2P_KEY_PAIR_DERIVE ||
          PSA_WANT_KEY_TYPE_WPA3_SAE_PT */
        {
            status = psa_driver_wrapper_import_key(
                &slot->attr,
                data, bytes,
                slot->key.data, slot->key.bytes, &slot->key.bytes,
                &bits);
            if (bits != slot->attr.bits) {
                status = PSA_ERROR_INVALID_ARGUMENT;
            }
        }
    } while (status == PSA_ERROR_INSUFFICIENT_DATA);

exit:
#ifdef MBEDTLS_PSA_STATIC_KEY_SLOTS
    mbedtls_platform_zeroize(data, sizeof data);
#else
    mbedtls_zeroize_and_free(data, bytes);
#endif
    return status;
}

psa_status_t psa_key_derivation_output_key(const psa_key_attributes_t *attributes,
                                           psa_key_derivation_operation_t *operation,
                                           mbedtls_svc_key_id_t *key)
{
    psa_status_t status;
    psa_key_slot_t *slot = NULL;
    psa_se_drv_table_entry_t *driver = NULL;

    *key = MBEDTLS_SVC_KEY_ID_INIT;

    /* Reject any attempt to create a zero-length key so that we don't
     * risk tripping up later, e.g. on a malloc(0) that returns NULL. */
    if (psa_get_key_bits(attributes) == 0) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    status = psa_key_derivation_check_state(operation, PSA_KEY_DERIVATION_OUTPUT);
    if (status != PSA_SUCCESS) return status;

    if (operation->no_output || !operation->can_output_key) {
        return PSA_ERROR_NOT_PERMITTED;
    }

    status = psa_start_key_creation(PSA_KEY_CREATION_DERIVE, attributes,
                                    &slot, &driver);
    if (status == PSA_SUCCESS) {
        status = psa_generate_derived_key_internal(slot,
                                                   attributes->bits,
                                                   operation);
    }
    if (status == PSA_SUCCESS) {
        status = psa_finish_key_creation(slot, driver, key);
    }
    if (status != PSA_SUCCESS) {
        psa_fail_key_creation(slot, driver);
    }

    return status;
}

psa_status_t psa_key_derivation_verify_bytes(
    psa_key_derivation_operation_t *operation,
    const uint8_t *expected_output,
    size_t output_length)
{
    psa_status_t status = PSA_SUCCESS;
    uint8_t buffer[256];
    size_t length;
    int diff = 0;

    status = psa_key_derivation_check_state(operation, PSA_KEY_DERIVATION_OUTPUT);
    if (status != PSA_SUCCESS) goto exit;

    length = sizeof buffer;
    while (output_length) {
        if (output_length < length) length = output_length;
        status = psa_key_derivation_output_bytes_internal(operation, buffer, length);
        if (status != PSA_SUCCESS) return status;
        diff |= mbedtls_ct_memcmp(buffer, expected_output, length);
        expected_output += length;
        output_length -= length;
    }
    if (diff) return PSA_ERROR_INVALID_SIGNATURE;
    return PSA_SUCCESS;

exit:
    psa_key_derivation_abort(operation);
    return status;
}

psa_status_t psa_key_derivation_verify_key(
    psa_key_derivation_operation_t *operation,
    mbedtls_svc_key_id_t expected)
{
    psa_status_t status = PSA_ERROR_CORRUPTION_DETECTED;
    psa_status_t unlock_status = PSA_ERROR_CORRUPTION_DETECTED;
    psa_key_slot_t *slot = NULL;

    status = psa_get_and_lock_key_slot_with_policy(
        expected, &slot, PSA_KEY_USAGE_VERIFY_DERIVATION, operation->alg);
    if (status != PSA_SUCCESS) goto exit;

    if (slot->attr.type != PSA_KEY_TYPE_PASSWORD_HASH) {
        status = PSA_ERROR_INVALID_ARGUMENT;
        goto exit;
    }

    status = psa_key_derivation_verify_bytes(
        operation, slot->key.data, slot->key.bytes);

    unlock_status = psa_unregister_read_under_mutex(slot);
    return (status == PSA_SUCCESS) ? unlock_status : status;

exit:
    psa_unregister_read_under_mutex(slot);
    psa_key_derivation_abort(operation);
    return status;
}


/****************************************************************/
/* Key derivation */
/****************************************************************/

psa_status_t psa_key_derivation_setup(psa_key_derivation_operation_t *operation, psa_algorithm_t alg)
{
    psa_status_t status;
    psa_algorithm_t kdf_alg = alg;

    if (operation->alg != 0) {
        return PSA_ERROR_BAD_STATE;
    }

    if (PSA_ALG_IS_RAW_KEY_AGREEMENT(alg)) {
        return PSA_ERROR_INVALID_ARGUMENT;
    } else if (PSA_ALG_IS_KEY_AGREEMENT(alg)) {
        kdf_alg = PSA_ALG_KEY_AGREEMENT_GET_KDF(alg);
    } else if (!PSA_ALG_IS_KEY_DERIVATION(alg)) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    /* Make sure the driver-dependent part of the operation is zeroed.
     * This is a guarantee we make to drivers. Initializing the operation
     * does not necessarily take care of it, since the context is a
     * union and initializing a union does not necessarily initialize
     * all of its members. */
    memset(&operation->ctx, 0, sizeof(operation->ctx));

#if defined(PSA_WANT_ALG_TLS12_PRF) || defined(PSA_WANT_ALG_TLS12_PSK_TO_MS)
    if (PSA_ALG_IS_TLS12_PRF(kdf_alg) || PSA_ALG_IS_TLS12_PSK_TO_MS(kdf_alg)) {
        psa_algorithm_t hash_alg = PSA_ALG_HKDF_GET_HASH(kdf_alg);
        if (hash_alg != PSA_ALG_SHA_256 && hash_alg != PSA_ALG_SHA_384) return PSA_ERROR_NOT_SUPPORTED;
    }
#endif

    status = psa_driver_wrapper_key_derivation_setup(operation, kdf_alg);
    if (status) return status;

    operation->alg = alg;
#if defined(PSA_WANT_ALG_HKDF) || defined(PSA_WANT_ALG_HKDF_EXPAND)
    if (PSA_ALG_IS_HKDF(kdf_alg) || PSA_ALG_IS_HKDF_EXPAND(kdf_alg)) {
        operation->capacity = 255 * PSA_HASH_LENGTH(kdf_alg);
    } else
#endif
#if defined(PSA_WANT_ALG_HKDF_EXTRACT) || defined(PSA_WANT_ALG_SRP_PASSWORD_HASH)
    if (PSA_ALG_IS_HKDF_EXTRACT(kdf_alg) || PSA_ALG_IS_SRP_PASSWORD_HASH(kdf_alg)) {
        operation->capacity = PSA_HASH_LENGTH(kdf_alg);
    } else
#endif
#if defined(PSA_WANT_ALG_TLS12_ECJPAKE_TO_PMS)
    if (kdf_alg == PSA_ALG_TLS12_ECJPAKE_TO_PMS) {
        operation->capacity = PSA_TLS12_ECJPAKE_TO_PMS_DATA_SIZE;
    } else
#endif
#if defined(PSA_WANT_ALG_SP800_108_COUNTER_HMAC) || defined(PSA_WANT_ALG_SP800_108_COUNTER_CMAC)
    if (PSA_ALG_IS_SP800_108_COUNTER_HMAC(kdf_alg) || kdf_alg == PSA_ALG_SP800_108_COUNTER_CMAC) {
        operation->capacity = 0x1fffffff;
    } else
#endif
#if defined(PSA_WANT_ALG_TLS12_PSK_TO_MS)
    if (PSA_ALG_IS_TLS12_PSK_TO_MS(kdf_alg)) {
        operation->capacity = 48U;
    } else
#endif
#if (SIZE_MAX > UINT32_MAX) && defined(PSA_WANT_ALG_PBKDF2_AES_CMAC_PRF_128)
    if (kdf_alg == PSA_ALG_PBKDF2_AES_CMAC_PRF_128) {
        operation->capacity = UINT32_MAX * (size_t)PSA_BLOCK_CIPHER_BLOCK_LENGTH(PSA_KEY_TYPE_AES);
    } else
#endif
#if (SIZE_MAX > UINT32_MAX) && defined(PSA_WANT_ALG_PBKDF2_HMAC)
    if (PSA_ALG_IS_PBKDF2_HMAC(kdf_alg)) {
        operation->capacity = UINT32_MAX * (size_t)PSA_HASH_LENGTH(kdf_alg);
    } else
#endif
    {
        operation->capacity = PSA_KEY_DERIVATION_UNLIMITED_CAPACITY;
    }

    return PSA_SUCCESS;
}

/** Check whether the given key type is acceptable for the given
 * input step of a key derivation.
 *
 * Secret inputs must have the type #PSA_KEY_TYPE_DERIVE.
 * Non-secret inputs must have the type #PSA_KEY_TYPE_RAW_DATA.
 * Both secret and non-secret inputs can alternatively have the type
 * #PSA_KEY_TYPE_NONE, which is never the type of a key object, meaning
 * that the input was passed as a buffer rather than via a key object.
 */
static int psa_key_derivation_check_input_type(
    psa_algorithm_t alg,
    psa_key_derivation_step_t step,
    psa_key_type_t key_type)
{
    switch (step) {
        case PSA_KEY_DERIVATION_INPUT_PASSWORD:
            if (key_type == PSA_KEY_TYPE_PASSWORD) {
                return PSA_SUCCESS;
            }
            // fall through
        case PSA_KEY_DERIVATION_INPUT_SECRET:
        case PSA_KEY_DERIVATION_INPUT_OTHER_SECRET:
            if (key_type == PSA_KEY_TYPE_DERIVE) {
                return PSA_SUCCESS;
            }
            if (key_type == PSA_KEY_TYPE_NONE) {
                return PSA_SUCCESS;
            }
            if (key_type == PSA_KEY_TYPE_AES && alg == PSA_ALG_SP800_108_COUNTER_CMAC) {
                return PSA_SUCCESS;
            }
            break;
        case PSA_KEY_DERIVATION_INPUT_SALT:
            if (key_type == PSA_KEY_TYPE_PEPPER) {
                return PSA_SUCCESS;
            }
            // fall through
        case PSA_KEY_DERIVATION_INPUT_LABEL:
        case PSA_KEY_DERIVATION_INPUT_INFO:
        case PSA_KEY_DERIVATION_INPUT_SEED:
        case PSA_KEY_DERIVATION_INPUT_COST:
        case PSA_KEY_DERIVATION_INPUT_CONTEXT:
            if (key_type == PSA_KEY_TYPE_RAW_DATA) {
                return PSA_SUCCESS;
            }
            if (key_type == PSA_KEY_TYPE_NONE) {
                return PSA_SUCCESS;
            }
            break;
    }
    return PSA_ERROR_INVALID_ARGUMENT;
}

static psa_status_t psa_key_derivation_input_internal(
    psa_key_derivation_operation_t *operation,
    psa_key_derivation_step_t step,
    psa_key_attributes_t *attributes,
    const uint8_t *data,
    size_t data_length)
{
    psa_status_t status;
    status = psa_key_derivation_check_state(operation, step);
    if (status != PSA_SUCCESS) goto exit;

    if (operation->alg == PSA_ALG_SP800_108_COUNTER_CMAC &&
        step == PSA_KEY_DERIVATION_INPUT_SECRET) {
        // key must be a block-cipher key
        // psa_key_derivation_input_bytes (key_type == PSA_KEY_TYPE_NONE) is not allowed
        if ((attributes->type & ~0xFF) != PSA_KEY_TYPE_AES) {
            status = PSA_ERROR_INVALID_ARGUMENT;
            goto exit;
        }
    } else if (PSA_ALG_IS_SP800_108_COUNTER_HMAC(operation->alg) &&
        step == PSA_KEY_DERIVATION_INPUT_SECRET &&
        attributes->type == PSA_KEY_TYPE_HMAC) {
        // ok
    } else {
        status = psa_key_derivation_check_input_type(operation->alg, step,
            attributes ? attributes->type : PSA_KEY_TYPE_NONE);
        if (status != PSA_SUCCESS) {
            goto exit;
        }
    }

    if (attributes)
    {
        status = psa_driver_wrapper_key_derivation_input_key(operation, step, attributes, data, data_length);
    }
    else {
        status = psa_driver_wrapper_key_derivation_input_bytes(operation, step, data, data_length);
    }

    if (status != PSA_SUCCESS) goto exit;

    return PSA_SUCCESS;

exit:
    psa_key_derivation_abort(operation);
    return status;
}

psa_status_t psa_key_derivation_input_bytes(
    psa_key_derivation_operation_t *operation,
    psa_key_derivation_step_t step,
    const uint8_t *data,
    size_t data_length)
{
    return psa_key_derivation_input_internal(operation, step,
                                             NULL,
                                             data, data_length);
}

psa_status_t psa_key_derivation_input_integer(
    psa_key_derivation_operation_t *operation,
    psa_key_derivation_step_t step,
    uint64_t value)
{
    psa_status_t status;

    if (step != PSA_KEY_DERIVATION_INPUT_COST) {
        status = PSA_ERROR_INVALID_ARGUMENT;
        goto exit;
    }

    status = psa_key_derivation_check_state(operation, step);
    if (status != PSA_SUCCESS) goto exit;

    status = psa_key_derivation_check_input_type(operation->alg, step, PSA_KEY_TYPE_NONE);
    if (status != PSA_SUCCESS) goto exit;

    if (PSA_ALG_IS_PBKDF2(operation->alg)) {
        if (value == 0) {
            status = PSA_ERROR_INVALID_ARGUMENT;
            goto exit;
        }
        if (value > PSA_VENDOR_PBKDF2_MAX_ITERATIONS) {
            status = PSA_ERROR_NOT_SUPPORTED;
            goto exit;
        }
    }

    status = psa_driver_wrapper_key_derivation_input_integer(operation, step, value);
    if (status != PSA_SUCCESS) goto exit;

    return PSA_SUCCESS;

exit:
    psa_key_derivation_abort(operation);
    return status;
}

psa_status_t psa_key_derivation_input_key(
    psa_key_derivation_operation_t *operation,
    psa_key_derivation_step_t step,
    mbedtls_svc_key_id_t key)
{
    psa_status_t status = PSA_ERROR_CORRUPTION_DETECTED;
    psa_status_t unlock_status = PSA_ERROR_CORRUPTION_DETECTED;
    psa_key_slot_t *slot = NULL;

    status = psa_get_and_lock_key_slot_with_policy(
        key, &slot, 0, operation->alg);
    if (status != PSA_SUCCESS) goto exit;

    /* check usage, PSA_KEY_USAGE_DERIVE or PSA_KEY_USAGE_VERIFY_DERIVATION */
    if ((slot->attr.policy.usage & PSA_KEY_USAGE_DERIVE) == 0) {
        operation->no_output = 1;
        if ((slot->attr.policy.usage & PSA_KEY_USAGE_VERIFY_DERIVATION) == 0) {
            status = PSA_ERROR_NOT_PERMITTED;
            goto exit;
        }
    }

    /* Passing a key object as a SECRET or PASSWORD input unlocks the
     * permission to output to a key object. */
    if (step == PSA_KEY_DERIVATION_INPUT_SECRET ||
        step == PSA_KEY_DERIVATION_INPUT_PASSWORD) {
        operation->can_output_key = 1;
    }

    status = psa_key_derivation_input_internal(operation,
                                               step, &slot->attr,
                                               slot->key.data,
                                               slot->key.bytes);

exit:
    unlock_status = psa_unregister_read_under_mutex(slot);

    if (status == PSA_SUCCESS) {
        status = unlock_status;
    } else {
        psa_key_derivation_abort(operation);
    }

    return status;
}


/****************************************************************/
/* Key agreement */
/****************************************************************/

#define PSA_KEY_AGREEMENT_MAX_SHARED_SECRET_SIZE (PSA_BITS_TO_BYTES(PSA_VENDOR_ECC_MAX_CURVE_BITS))

/* Note that if this function fails, you must call psa_key_derivation_abort()
 * to potentially free embedded data structures and wipe confidential data.
 */
static psa_status_t psa_key_agreement_internal(psa_key_derivation_operation_t *operation,
                                               psa_key_derivation_step_t step,
                                               psa_key_slot_t *private_key,
                                               const uint8_t *peer_key,
                                               size_t peer_key_length)
{
    psa_status_t status;
    uint8_t shared_secret[PSA_RAW_KEY_AGREEMENT_OUTPUT_MAX_SIZE] = { 0 };
    size_t shared_secret_length = 0;
    psa_algorithm_t ka_alg = PSA_ALG_KEY_AGREEMENT_GET_BASE(operation->alg);

    /* Step 1: run the secret agreement algorithm to generate the shared
     * secret. */
    status = psa_driver_wrapper_key_agreement(
        &private_key->attr, private_key->key.data, private_key->key.bytes,
        ka_alg,
        peer_key, peer_key_length,
        shared_secret, sizeof(shared_secret), &shared_secret_length);
    if (status != PSA_SUCCESS) {
        goto exit;
    }

    /* Step 2: set up the key derivation to generate key material from
     * the shared secret. A shared secret is permitted wherever a key
     * of type DERIVE is permitted. */
    status = psa_key_derivation_input_internal(operation, step,
                                               NULL,
                                               shared_secret,
                                               shared_secret_length);
exit:
    mbedtls_platform_zeroize(shared_secret, shared_secret_length);
    return status;
}

psa_status_t psa_key_derivation_key_agreement(psa_key_derivation_operation_t *operation,
                                              psa_key_derivation_step_t step,
                                              mbedtls_svc_key_id_t private_key,
                                              const uint8_t *peer_key,
                                              size_t peer_key_length)
{
    psa_status_t status = PSA_ERROR_CORRUPTION_DETECTED;
    psa_status_t unlock_status = PSA_ERROR_CORRUPTION_DETECTED;
    psa_key_slot_t *slot;

    if (!PSA_ALG_IS_KEY_AGREEMENT(operation->alg)) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }
    status = psa_get_and_lock_key_slot_with_policy(
        private_key, &slot, PSA_KEY_USAGE_DERIVE, operation->alg);
    if (status != PSA_SUCCESS) {
        return status;
    }
    status = psa_key_agreement_internal(operation, step,
                                        slot,
                                        peer_key, peer_key_length);
    if (status != PSA_SUCCESS) {
        psa_key_derivation_abort(operation);
    } else {
        /* If a private key has been added as SECRET, we allow the derived
         * key material to be used as a key in PSA Crypto. */
        if (step == PSA_KEY_DERIVATION_INPUT_SECRET) {
            operation->can_output_key = 1;
        }
    }

    unlock_status = psa_unregister_read_under_mutex(slot);

    return (status == PSA_SUCCESS) ? unlock_status : status;
}

psa_status_t psa_raw_key_agreement(psa_algorithm_t alg,
                                   mbedtls_svc_key_id_t private_key,
                                   const uint8_t *peer_key,
                                   size_t peer_key_length,
                                   uint8_t *output,
                                   size_t output_size,
                                   size_t *output_length)
{
    psa_status_t status = PSA_ERROR_CORRUPTION_DETECTED;
    psa_status_t unlock_status = PSA_ERROR_CORRUPTION_DETECTED;
    psa_key_slot_t *slot = NULL;

    if (!PSA_ALG_IS_STANDALONE_KEY_AGREEMENT(alg)) {
        status = PSA_ERROR_INVALID_ARGUMENT;
        goto exit;
    }
    status = psa_get_and_lock_key_slot_with_policy(
        private_key, &slot, PSA_KEY_USAGE_DERIVE, alg);
    if (status != PSA_SUCCESS) {
        goto exit;
    }

    status = psa_driver_wrapper_key_agreement(
        &slot->attr, slot->key.data, slot->key.bytes,
        alg,
        peer_key, peer_key_length,
        output, output_size, output_length);

exit:
    if (status != PSA_SUCCESS) {
        /* If an error happens and is not handled properly, the output
         * may be used as a key to protect sensitive data. Arrange for such
         * a key to be random, which is likely to result in decryption or
         * verification errors. This is better than filling the buffer with
         * some constant data such as zeros, which would result in the data
         * being protected with a reproducible, easily knowable key.
         */
        psa_generate_random(output, output_size);
        *output_length = output_size;
    }

    unlock_status = psa_unregister_read_under_mutex(slot);

    return (status == PSA_SUCCESS) ? unlock_status : status;
}

psa_status_t psa_key_agreement(mbedtls_svc_key_id_t private_key,
    const uint8_t *peer_key,
    size_t peer_key_length,
    psa_algorithm_t alg,
    const psa_key_attributes_t *attributes,
    mbedtls_svc_key_id_t *key)
{
    psa_status_t status;
    uint8_t shared_secret[PSA_RAW_KEY_AGREEMENT_OUTPUT_MAX_SIZE];
    size_t shared_secret_len;
    psa_key_type_t key_type;

    *key = MBEDTLS_SVC_KEY_ID_INIT;

    key_type = psa_get_key_type(attributes);
    if (key_type != PSA_KEY_TYPE_DERIVE && key_type != PSA_KEY_TYPE_RAW_DATA
        && key_type != PSA_KEY_TYPE_HMAC && key_type != PSA_KEY_TYPE_PASSWORD) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    status = psa_raw_key_agreement(alg, private_key, peer_key, peer_key_length,
        shared_secret, sizeof(shared_secret), &shared_secret_len);
    if (status != PSA_SUCCESS) {
        return status;
    }

    return psa_import_key(attributes, shared_secret, shared_secret_len, key);
}


/****************************************************************/
/* PAKE */
/****************************************************************/

psa_status_t psa_pake_setup(psa_pake_operation_t *operation,
    mbedtls_svc_key_id_t password_key,
    const psa_pake_cipher_suite_t *cipher_suite)
{
    psa_status_t status = PSA_ERROR_CORRUPTION_DETECTED;
    psa_status_t unlock_status = PSA_ERROR_CORRUPTION_DETECTED;
    psa_algorithm_t alg = psa_pake_cs_get_algorithm(cipher_suite);
    psa_pake_primitive_t primitive = psa_pake_cs_get_primitive(cipher_suite);
    psa_pake_primitive_t ptype = PSA_PAKE_PRIMITIVE_GET_TYPE(primitive);
    psa_ecc_family_t family = PSA_PAKE_PRIMITIVE_GET_FAMILY(primitive);
    size_t bits = PSA_PAKE_PRIMITIVE_GET_BITS(primitive);
    psa_key_slot_t *slot = NULL;
    psa_key_type_t ktype;

    if (operation->alg) {
        return PSA_ERROR_BAD_STATE;
    }

    if (!PSA_ALG_IS_PAKE(alg) ||
        (ptype != PSA_PAKE_PRIMITIVE_TYPE_ECC && ptype != PSA_PAKE_PRIMITIVE_TYPE_DH)) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    /* Make sure the driver-dependent part of the operation is zeroed.
     * This is a guarantee we make to drivers. Initializing the operation
     * does not necessarily take care of it, since the context is a
     * union and initializing a union does not necessarily initialize
     * all of its members. */
    memset(&operation->ctx, 0, sizeof(operation->ctx));

    status = psa_get_and_lock_key_slot_with_policy(
        password_key, &slot, PSA_KEY_USAGE_DERIVE, alg);
    if (status != PSA_SUCCESS) goto exit;
    ktype = slot->attr.type;

    if (PSA_ALG_IS_JPAKE(alg)) {
        if ((ktype != PSA_KEY_TYPE_PASSWORD && ktype != PSA_KEY_TYPE_PASSWORD_HASH) ||
            psa_pake_cs_get_key_confirmation(cipher_suite) != PSA_PAKE_UNCONFIRMED_KEY) {
            status = PSA_ERROR_INVALID_ARGUMENT;
            goto exit;
        }
        if (ptype == PSA_PAKE_PRIMITIVE_TYPE_ECC) {
            operation->secret_size = (uint32_t)PSA_KEY_EXPORT_ECC_PUBLIC_KEY_MAX_SIZE(bits);
        } else if (ptype == PSA_PAKE_PRIMITIVE_TYPE_DH) {
            operation->secret_size = (uint32_t)PSA_BITS_TO_BYTES(bits);
        } else {
            status = PSA_ERROR_INVALID_ARGUMENT;
            goto exit;
        }
    } else {
        operation->secret_size = PSA_HASH_LENGTH(alg);
        if (PSA_ALG_IS_SPAKE2P(alg)) {
            if (!PSA_KEY_TYPE_IS_SPAKE2P(ktype) || ptype != PSA_PAKE_PRIMITIVE_TYPE_ECC ||
                family != PSA_KEY_TYPE_SPAKE2P_GET_FAMILY(ktype) ||
                bits != slot->attr.bits) {
                status = PSA_ERROR_INVALID_ARGUMENT;
                goto exit;
            }
            if (alg == PSA_ALG_SPAKE2P_MATTER) operation->secret_size >>= 1;
        } else if (PSA_ALG_IS_SRP_6(alg)) {
            if (!PSA_KEY_TYPE_IS_SRP(ktype) || ptype != PSA_PAKE_PRIMITIVE_TYPE_DH ||
                family != PSA_KEY_TYPE_SRP_GET_FAMILY(ktype) ||
                bits != slot->attr.bits) {
                status = PSA_ERROR_INVALID_ARGUMENT;
                goto exit;
            }
        } else if (PSA_ALG_IS_WPA3_SAE(alg)) {
            if (PSA_KEY_TYPE_IS_WPA3_SAE_ECC_PT(ktype)) {
                if (ptype != PSA_PAKE_PRIMITIVE_TYPE_ECC ||
                    family != PSA_KEY_TYPE_WPA3_SAE_PT_GET_FAMILY(ktype) ||
                    bits != slot->attr.bits) {
                    status = PSA_ERROR_INVALID_ARGUMENT;
                    goto exit;
                }
            } else if (PSA_KEY_TYPE_IS_WPA3_SAE_DH_PT(ktype)) {
                if (ptype != PSA_PAKE_PRIMITIVE_TYPE_DH || 
                    family != PSA_KEY_TYPE_WPA3_SAE_PT_GET_FAMILY(ktype) ||
                    bits != slot->attr.bits) {
                    status = PSA_ERROR_INVALID_ARGUMENT;
                    goto exit;
                }
            } else if (ktype != PSA_KEY_TYPE_PASSWORD || PSA_ALG_IS_WPA3_SAE_GDH(alg)) {
                status = PSA_ERROR_INVALID_ARGUMENT;
                goto exit;
            }
            // fixed (non GDH) output key size is 256 bits
            if (PSA_ALG_IS_WPA3_SAE_FIXED(alg)) operation->secret_size = 32;
        } else {
            status = PSA_ERROR_NOT_SUPPORTED;
            goto exit;
        }
        if (psa_pake_cs_get_key_confirmation(cipher_suite) != PSA_PAKE_CONFIRMED_KEY) {
            status = PSA_ERROR_INVALID_ARGUMENT;
            goto exit;
        }
    }

    status = psa_driver_wrapper_pake_setup(
        operation, &slot->attr,
        slot->key.data, slot->key.bytes,
        cipher_suite);

    operation->alg = alg;
    operation->started = 0;
    operation->sequence = 0;

exit:
    unlock_status = psa_unregister_read_under_mutex(slot);

    if (status == PSA_SUCCESS) {
        status = unlock_status;
    } else {
        psa_pake_abort(operation);
    }

    return status;
}

psa_status_t psa_pake_set_role(psa_pake_operation_t *operation,
    psa_pake_role_t role)
{
    psa_status_t status = PSA_ERROR_CORRUPTION_DETECTED;

    if (operation->alg == 0 || operation->role_set || operation->started) {
        status = PSA_ERROR_BAD_STATE;
        goto exit;
    }

#if defined(PSA_WANT_ALG_JPAKE) || defined(PSA_WANT_ALG_WPA3_SAE)
    if (PSA_ALG_IS_JPAKE(operation->alg) || PSA_ALG_IS_WPA3_SAE(operation->alg)) {
        if (role != PSA_PAKE_ROLE_NONE) return PSA_ERROR_INVALID_ARGUMENT;
    } else
#endif
#if defined(PSA_WANT_ALG_SPAKE2P_HMAC) || defined(PSA_WANT_ALG_SPAKE2P_CMAC) || \
    defined(PSA_WANT_ALG_SPAKE2P_MATTER) || defined(PSA_WANT_ALG_SRP_6)
    if (PSA_ALG_IS_SPAKE2P(operation->alg) || PSA_ALG_IS_SRP_6(operation->alg)) {
        if (role == PSA_PAKE_ROLE_SERVER) operation->is_second = 1;
        else if (role != PSA_PAKE_ROLE_CLIENT) return PSA_ERROR_INVALID_ARGUMENT;
    } else
#endif
    {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    status = psa_driver_wrapper_pake_set_role(operation, role);
    if (status != PSA_SUCCESS) goto exit;

    operation->role_set = 1;
    return PSA_SUCCESS;

exit:
    psa_pake_abort(operation);
    return status;
}

psa_status_t psa_pake_set_user(psa_pake_operation_t *operation,
    const uint8_t *user_id,
    size_t user_id_len)
{
    psa_status_t status = PSA_ERROR_CORRUPTION_DETECTED;

    if (operation->alg == 0 || operation->user_set || operation->started) {
        status = PSA_ERROR_BAD_STATE;
        goto exit;
    }

#ifdef PSA_WANT_ALG_JPAKE
    if (PSA_ALG_IS_JPAKE(operation->alg)) {
        if (user_id == NULL || user_id_len == 0) {
            status = PSA_ERROR_INVALID_ARGUMENT;
            goto exit;
        }
    } else
#endif
#if defined(PSA_WANT_ALG_SPAKE2P_HMAC) || defined(PSA_WANT_ALG_SPAKE2P_CMAC) || defined(PSA_WANT_ALG_SPAKE2P_MATTER)
    if (PSA_ALG_IS_SPAKE2P(operation->alg)) {
        if (!operation->role_set) {
            status = PSA_ERROR_BAD_STATE;
            goto exit;
        }
        if (user_id == NULL && user_id_len != 0) {
            status = PSA_ERROR_INVALID_ARGUMENT;
            goto exit;
        }
    } else
#endif
#ifdef PSA_WANT_ALG_SRP_6
    if (PSA_ALG_IS_SRP_6(operation->alg)) {
        if (!operation->role_set) {
            status = PSA_ERROR_BAD_STATE;
            goto exit;
        }
        if (user_id == NULL || user_id_len == 0) {
            status = PSA_ERROR_INVALID_ARGUMENT;
            goto exit;
        }
    } else
#endif
#ifdef PSA_WANT_ALG_WPA3_SAE
    if (PSA_ALG_IS_WPA3_SAE(operation->alg)) {
        if (user_id_len != 6) {
            status = PSA_ERROR_INVALID_ARGUMENT;
            goto exit;
        }
    } else
#endif
    {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    status = psa_driver_wrapper_pake_set_user(operation, user_id, user_id_len);
    if (status != PSA_SUCCESS) goto exit;

    operation->user_set = 1;
    return PSA_SUCCESS;

exit:
    psa_pake_abort(operation);
    return status;
}

psa_status_t psa_pake_set_peer(psa_pake_operation_t *operation,
    const uint8_t *peer_id,
    size_t peer_id_len)
{
    psa_status_t status = PSA_ERROR_CORRUPTION_DETECTED;

    if (operation->alg == 0 || operation->peer_set || operation->started) {
        status = PSA_ERROR_BAD_STATE;
        goto exit;
    }

#ifdef PSA_WANT_ALG_JPAKE
    if (PSA_ALG_IS_JPAKE(operation->alg)) {
        if (!operation->user_set) {
            status = PSA_ERROR_BAD_STATE;
            goto exit;
        }
        if (peer_id == NULL || peer_id_len == 0) {
            status = PSA_ERROR_INVALID_ARGUMENT;
            goto exit;
        }
    } else
#endif
#if defined(PSA_WANT_ALG_SPAKE2P_HMAC) || defined(PSA_WANT_ALG_SPAKE2P_CMAC) || defined(PSA_WANT_ALG_SPAKE2P_MATTER)
    if (PSA_ALG_IS_SPAKE2P(operation->alg)) {
        if (!operation->role_set) {
            status = PSA_ERROR_BAD_STATE;
            goto exit;
        }
        if (peer_id == NULL && peer_id_len != 0) {
            status = PSA_ERROR_INVALID_ARGUMENT;
            goto exit;
        }
    } else
#endif
#ifdef PSA_WANT_ALG_WPA3_SAE
    if (PSA_ALG_IS_WPA3_SAE(operation->alg)) {
        if (!operation->user_set) {
            status = PSA_ERROR_BAD_STATE;
            goto exit;
        }
        if (peer_id_len != 6) {
            status = PSA_ERROR_INVALID_ARGUMENT;
            goto exit;
        }
    } else
#endif
    {
        status = PSA_ERROR_BAD_STATE;
        goto exit;
    }

    status = psa_driver_wrapper_pake_set_peer(operation, peer_id, peer_id_len);
    if (status != PSA_SUCCESS) goto exit;

    operation->peer_set = 1;
    return PSA_SUCCESS;

exit:
    psa_pake_abort(operation);
    return status;
}

psa_status_t psa_pake_set_context(psa_pake_operation_t *operation,
    const uint8_t *context,
    size_t context_len)
{
    psa_status_t status = PSA_ERROR_CORRUPTION_DETECTED;

    if (operation->alg == 0 || operation->context_set || !operation->role_set || operation->started) {
        status = PSA_ERROR_BAD_STATE;
        goto exit;
    }

#if defined(PSA_WANT_ALG_SPAKE2P_HMAC) || defined(PSA_WANT_ALG_SPAKE2P_CMAC) || defined(PSA_WANT_ALG_SPAKE2P_MATTER)
    if (PSA_ALG_IS_SPAKE2P(operation->alg)) {
        if (context == NULL && context_len != 0) {
            status = PSA_ERROR_INVALID_ARGUMENT;
            goto exit;
        }
    } else
#endif
    {
        status = PSA_ERROR_BAD_STATE;
        goto exit;
    }

    status = psa_driver_wrapper_pake_set_context(operation, context, context_len);
    if (status != PSA_SUCCESS) goto exit;

    operation->context_set = 1;
    return PSA_SUCCESS;

exit:
    psa_pake_abort(operation);
    return status;
}


#ifdef PSA_WANT_ALG_JPAKE
/* JPAKE sequence numbers:
 *        first                        second
 *  0- 2: output SHARE,PUBLIC,PROOF    input  SHARE,PUBLIC,PROOF
 *  3- 5: output SHARE,PUBLIC,PROOF    input  SHARE,PUBLIC,PROOF
 *  6- 8: input  SHARE,PUBLIC,PROOF    output SHARE,PUBLIC,PROOF
 *  9-11: input  SHARE,PUBLIC,PROOF    output SHARE,PUBLIC,PROOF
 * 12-14: output SHARE,PUBLIC,PROOF    input  SHARE,PUBLIC,PROOF
 * 15-17: input  SHARE,PUBLIC,PROOF    output SHARE,PUBLIC,PROOF
 */

static psa_status_t psa_check_jpake_sequence(psa_pake_operation_t *operation,
    psa_pake_step_t step,
    unsigned int first)
{
    unsigned int sequence = operation->sequence;

    if (step != PSA_PAKE_STEP_KEY_SHARE && step != PSA_PAKE_STEP_ZK_PUBLIC && step != PSA_PAKE_STEP_ZK_PROOF) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    switch (sequence / 3) {
    case 0:
    case 1:
    case 4:
        if (!first) return PSA_ERROR_BAD_STATE;
        break;
    case 2:
    case 3:
    case 5:
        if (first) return PSA_ERROR_BAD_STATE;
        break;
    default:
        return PSA_ERROR_BAD_STATE;
    }

    switch (sequence % 3) {
    case 0:
        if (step != PSA_PAKE_STEP_KEY_SHARE) return PSA_ERROR_BAD_STATE;
        break;
    case 1:
        if (step != PSA_PAKE_STEP_ZK_PUBLIC) return PSA_ERROR_BAD_STATE;
        break;
    case 2:
        if (step != PSA_PAKE_STEP_ZK_PROOF) return PSA_ERROR_BAD_STATE;
        break;
    }

    sequence++;
    if (sequence == 18) operation->done = 1;

    operation->sequence = sequence;
    return PSA_SUCCESS;
}
#endif

#if defined(PSA_WANT_ALG_SPAKE2P_HMAC) || defined(PSA_WANT_ALG_SPAKE2P_CMAC) || defined(PSA_WANT_ALG_SPAKE2P_MATTER)
/* SPAKE2+ sequence numbers:
 *      prover (client)       verifier (server)
 *  0:  output shareP         input  shareP
 *  1:  input  shareV         output shareV
 *  2:  input  confirmV       output confirmV
 *  3:  output confirmP       input  confirmP
 */

static psa_status_t psa_check_spake2p_sequence(psa_pake_operation_t *operation,
    psa_pake_step_t step,
    unsigned int first)
{
    unsigned int sequence = operation->sequence;

    if (step != PSA_PAKE_STEP_KEY_SHARE && step != PSA_PAKE_STEP_CONFIRM) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    switch (sequence) {
    case 0: // shareP
        if (!first || step != PSA_PAKE_STEP_KEY_SHARE) return PSA_ERROR_BAD_STATE;
        break;
    case 1: // shareV
        if (first || step != PSA_PAKE_STEP_KEY_SHARE) return PSA_ERROR_BAD_STATE;
        break;
    case 2: // confirmV
        if (first || step != PSA_PAKE_STEP_CONFIRM) return PSA_ERROR_BAD_STATE;
        break;
    case 3: // confirmP
        if (!first || step != PSA_PAKE_STEP_CONFIRM) return PSA_ERROR_BAD_STATE;
        operation->done = 1;
        break;
    default:
        return PSA_ERROR_BAD_STATE;
    }

    operation->sequence = sequence + 1;
    return PSA_SUCCESS;
}
#endif

#ifdef PSA_WANT_ALG_SRP_6
/* SRP sequence numbers:
 * (salt and share can be used in any order)
 *      client                server
 *  ~1: input  salt           input salt
 *  ~2: output client share   input  client share
 *  ~4: input  server share   output server share
 *   7: output proof1         input  proof1
 *  15: input  proof2         output proof2
 */

static psa_status_t psa_check_srp_sequence(psa_pake_operation_t *operation,
    psa_pake_step_t step,
    unsigned int first)
{
    unsigned int sequence = operation->sequence;

    switch (step) {
    case PSA_PAKE_STEP_SALT:
        if (sequence & 1) return PSA_ERROR_BAD_STATE;
            sequence += 1;
        break;
    case PSA_PAKE_STEP_KEY_SHARE:
        if (first) {
            if (sequence & 2) return PSA_ERROR_BAD_STATE;
            sequence += 2;
        } else {
            if (sequence & 4) return PSA_ERROR_BAD_STATE;
            sequence += 4;
        }
        break;
    case PSA_PAKE_STEP_CONFIRM:
        if (first) {
            if (sequence != 7) return PSA_ERROR_BAD_STATE;
            sequence += 8;
        } else {
            if (sequence != 15) return PSA_ERROR_BAD_STATE;
            operation->done = 1;
        }
        break;
    default:
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    operation->sequence = sequence;
    return PSA_SUCCESS;
}
#endif

#ifdef PSA_WANT_ALG_WPA3_SAE
/* WPA3-SAE sequence numbers:
 * (salt and share can be used in any order)
 *  ~1: output commit
 *  ~2: input  commit
 *  ~4: output confirm
 *  ~8: input  confirm
 *  ~16: input salt (rejected group list)
 *  ~32: input send confirm
 */

static psa_status_t psa_check_wpa3_sae_sequence(psa_pake_operation_t *operation,
    psa_pake_step_t step,
    unsigned int output)
{
    unsigned int sequence = operation->sequence;

    switch (step) {
    case PSA_PAKE_STEP_COMMIT:
        if (output) {
            if (sequence & 1) return PSA_ERROR_BAD_STATE;
            sequence |= 1;
        } else {
            if (sequence & 2) return PSA_ERROR_BAD_STATE;
            sequence |= 2;
        }
        break;
    case PSA_PAKE_STEP_SALT:
        if (output) return PSA_ERROR_INVALID_ARGUMENT;
        if (sequence < 3 || sequence & 16) return PSA_ERROR_BAD_STATE;
        sequence |= 16;
        break;
    case PSA_PAKE_STEP_CONFIRM:
        if (sequence < 3) return PSA_ERROR_BAD_STATE;
        if (output) {
            if ((sequence & 32) == 0) return PSA_ERROR_BAD_STATE;
            sequence |= 4;
        } else {
            sequence |= 8;
        }
        if ((sequence & 15) == 15) operation->done = 1;
        break;
    case PSA_PAKE_STEP_SEND_CONFIRM:
        if (output) return PSA_ERROR_INVALID_ARGUMENT;
        if (sequence < 3) return PSA_ERROR_BAD_STATE;
        sequence |= 32;
        break;
    case PSA_PAKE_STEP_KEYID:
        if (!output) return PSA_ERROR_INVALID_ARGUMENT;
        if (sequence < 3) return PSA_ERROR_BAD_STATE;
        break;
    default:
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    operation->sequence = sequence;
    return PSA_SUCCESS;
}
#endif

psa_status_t psa_pake_output(psa_pake_operation_t *operation,
    psa_pake_step_t step,
    uint8_t *output,
    size_t output_size,
    size_t *output_length)
{
    psa_status_t status = PSA_ERROR_CORRUPTION_DETECTED;

    if (operation->alg == 0) {
        return PSA_ERROR_BAD_STATE;
    }

#ifdef PSA_WANT_ALG_JPAKE
    if (PSA_ALG_IS_JPAKE(operation->alg)) {
        if (!operation->peer_set) return PSA_ERROR_BAD_STATE;
        if (operation->sequence == 0 || operation->sequence == 12) operation->is_second = 0;
        status = psa_check_jpake_sequence(operation, step, 1 - operation->is_second);
        if (status != PSA_SUCCESS) return status;
    } else
#endif
#if defined(PSA_WANT_ALG_SPAKE2P_HMAC) || defined(PSA_WANT_ALG_SPAKE2P_CMAC) || defined(PSA_WANT_ALG_SPAKE2P_MATTER)
    if (PSA_ALG_IS_SPAKE2P(operation->alg)) {
        if (!operation->role_set) return PSA_ERROR_BAD_STATE;
        status = psa_check_spake2p_sequence(operation, step, 1 - operation->is_second);
        if (status != PSA_SUCCESS) return status;
    } else
#endif
#ifdef PSA_WANT_ALG_SRP_6
    if (PSA_ALG_IS_SRP_6(operation->alg)) {
        if (!operation->role_set || !operation->user_set) return PSA_ERROR_BAD_STATE;
        if (step == PSA_PAKE_STEP_SALT) return PSA_ERROR_INVALID_ARGUMENT;
        status = psa_check_srp_sequence(operation, step, 1 - operation->is_second);
        if (status != PSA_SUCCESS) return status;
    } else
#endif
#ifdef PSA_WANT_ALG_WPA3_SAE
    if (PSA_ALG_IS_WPA3_SAE(operation->alg)) {
        if (!operation->user_set || !operation->peer_set) return PSA_ERROR_BAD_STATE;
        status = psa_check_wpa3_sae_sequence(operation, step, 1);
        if (status != PSA_SUCCESS) return status;
    } else
#endif
    {
        return PSA_ERROR_NOT_SUPPORTED;
    }

    operation->started = 1;

    status = psa_driver_wrapper_pake_output(
        operation, step,
        output, output_size, output_length);

    if (status != PSA_SUCCESS) {
        psa_pake_abort(operation);
    }

    return status;
}

psa_status_t psa_pake_input(psa_pake_operation_t *operation,
    psa_pake_step_t step,
    const uint8_t *input,
    size_t input_length)
{
    psa_status_t status = PSA_ERROR_CORRUPTION_DETECTED;

    if (operation->alg == 0) {
        return PSA_ERROR_BAD_STATE;
    }

    if (input == NULL || input_length == 0) return PSA_ERROR_INVALID_ARGUMENT;

#ifdef PSA_WANT_ALG_JPAKE
    if (PSA_ALG_IS_JPAKE(operation->alg)) {
        if (!operation->peer_set) return PSA_ERROR_BAD_STATE;
        if (operation->sequence == 0 || operation->sequence == 12) operation->is_second = 1;
        status = psa_check_jpake_sequence(operation, step, operation->is_second);
        if (status != PSA_SUCCESS) return status;
    } else
#endif
#if defined(PSA_WANT_ALG_SPAKE2P_HMAC) || defined(PSA_WANT_ALG_SPAKE2P_CMAC) || defined(PSA_WANT_ALG_SPAKE2P_MATTER)
    if (PSA_ALG_IS_SPAKE2P(operation->alg)) {
        if (!operation->role_set) return PSA_ERROR_BAD_STATE;
        status = psa_check_spake2p_sequence(operation, step, operation->is_second);
        if (status != PSA_SUCCESS) return status;
    } else
#endif
#ifdef PSA_WANT_ALG_SRP_6
    if (PSA_ALG_IS_SRP_6(operation->alg)) {
        if (!operation->role_set || !operation->user_set) return PSA_ERROR_BAD_STATE;
        status = psa_check_srp_sequence(operation, step, operation->is_second);
        if (status != PSA_SUCCESS) return status;
    } else
#endif
#ifdef PSA_WANT_ALG_WPA3_SAE
    if (PSA_ALG_IS_WPA3_SAE(operation->alg)) {
        if (!operation->user_set || !operation->peer_set) return PSA_ERROR_BAD_STATE;
        status = psa_check_wpa3_sae_sequence(operation, step, 0);
        if (status != PSA_SUCCESS) return status;
    } else
#endif
    {
        return PSA_ERROR_NOT_SUPPORTED;
    }

    operation->started = 1;

    status = psa_driver_wrapper_pake_input(
        operation, step,
        input, input_length);

    if (status != PSA_SUCCESS) {
        psa_pake_abort(operation);
    }

    return status;
}

psa_status_t psa_pake_get_shared_key(psa_pake_operation_t *operation,
    const psa_key_attributes_t *attributes,
    mbedtls_svc_key_id_t *key)
{
    psa_status_t status = PSA_ERROR_CORRUPTION_DETECTED;
    psa_key_slot_t *slot = NULL;
    psa_se_drv_table_entry_t *driver = NULL;
    psa_key_type_t type;
    size_t storage_size;

    if (operation->alg == 0 || operation->done == 0) {
        return PSA_ERROR_BAD_STATE;
    }

    if (psa_get_key_bits(attributes) != 0) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    type = psa_get_key_type(attributes);
    if (type != PSA_KEY_TYPE_DERIVE && type != PSA_KEY_TYPE_HMAC) {
#ifdef PSA_WANT_ALG_JPAKE
        if (PSA_ALG_IS_JPAKE(operation->alg)) {
            // the JPAKE secret can only be used for key derivation
            return PSA_ERROR_INVALID_ARGUMENT;
        } else
#endif
        {
            // other secrets can be used directly for symmetric crypto
            if ((type & PSA_KEY_TYPE_CATEGORY_MASK) != PSA_KEY_TYPE_CATEGORY_SYMMETRIC) {
                return PSA_ERROR_INVALID_ARGUMENT;
            }
        }
    }

    status = psa_start_key_creation(
        PSA_KEY_CREATION_DERIVE, attributes, &slot, &driver);
    if (status != PSA_SUCCESS) goto exit;

    storage_size = operation->secret_size;
    if (psa_key_lifetime_is_external(attributes->lifetime)) {
        status = psa_driver_wrapper_get_key_buffer_size(attributes, &storage_size);
        if (status != PSA_SUCCESS) goto exit;
    }
    status = psa_allocate_buffer_to_slot(slot, storage_size);
    if (status != PSA_SUCCESS) goto exit;

    status = psa_driver_wrapper_pake_get_shared_key(
        operation, attributes,
        slot->key.data, slot->key.bytes, &slot->key.bytes);
    if (status == PSA_SUCCESS) {
        status = psa_finish_key_creation(slot, driver, key);
    }

exit:
    if (status != PSA_SUCCESS) {
        psa_fail_key_creation(slot, driver);
        *key = MBEDTLS_SVC_KEY_ID_INIT;
    }

    psa_pake_abort(operation);
    return status;
}

psa_status_t psa_pake_abort(psa_pake_operation_t *operation)
{
    psa_status_t status = PSA_ERROR_CORRUPTION_DETECTED;

    if (operation->alg == 0) {
        return PSA_SUCCESS;
    }

    status = psa_driver_wrapper_pake_abort(operation);

    memset(operation, 0, sizeof(*operation));

    return status;
}


/****************************************************************/
/* Key Wrapping */
/****************************************************************/

psa_status_t oberon_psa_wrap_key(
    mbedtls_svc_key_id_t wrapping_key,
    psa_algorithm_t alg,
    mbedtls_svc_key_id_t key,
    uint8_t *data,
    size_t data_size,
    size_t *data_length)
{
    psa_status_t status = PSA_ERROR_CORRUPTION_DETECTED;
    psa_status_t unlock_status = PSA_ERROR_CORRUPTION_DETECTED;
    psa_key_slot_t *w_slot = NULL;
    psa_key_slot_t *k_slot = NULL;

    if (!PSA_ALG_IS_KEY_WRAP(alg)) {
        status = PSA_ERROR_INVALID_ARGUMENT;
        goto exit;
    }

    status = psa_get_and_lock_key_slot_with_policy(
        wrapping_key, &w_slot, PSA_KEY_USAGE_WRAP, alg);
    if (status != PSA_SUCCESS) {
        goto exit;
    }

    status = psa_get_and_lock_key_slot_with_policy(
        key, &k_slot, PSA_KEY_USAGE_EXPORT, alg);
    if (status != PSA_SUCCESS) {
        goto exit;
    }

    status = psa_driver_wrapper_wrap_key(
        &w_slot->attr, w_slot->key.data, w_slot->key.bytes,
        alg,
        &k_slot->attr, k_slot->key.data, k_slot->key.bytes,
        data, data_size, data_length);

exit:
    unlock_status = psa_unregister_read_under_mutex(w_slot);
    if (status == PSA_SUCCESS) {
        status = unlock_status;
    }

    unlock_status = psa_unregister_read_under_mutex(k_slot);
    if (status == PSA_SUCCESS) {
        status = unlock_status;
    }

    return status;
}

psa_status_t oberon_psa_unwrap_key(
    const psa_key_attributes_t *attributes,
    mbedtls_svc_key_id_t wrapping_key,
    psa_algorithm_t alg,
    const uint8_t *data,
    size_t data_length,
    mbedtls_svc_key_id_t *key)
{
    psa_status_t status = PSA_ERROR_CORRUPTION_DETECTED;
    psa_status_t unlock_status = PSA_ERROR_CORRUPTION_DETECTED;
    size_t storage_size;
    psa_key_slot_t *w_slot = NULL;
    psa_key_slot_t *k_slot = NULL;
    psa_se_drv_table_entry_t *driver = NULL;

    if (!PSA_ALG_IS_KEY_WRAP(alg)) {
        status = PSA_ERROR_INVALID_ARGUMENT;
        goto exit;
    }

    status = psa_get_and_lock_key_slot_with_policy(
        wrapping_key, &w_slot, PSA_KEY_USAGE_UNWRAP, alg);
    if (status != PSA_SUCCESS) {
        goto exit;
    }

    status = psa_start_key_creation(
        PSA_KEY_CREATION_IMPORT, attributes, &k_slot, &driver);
    if (status != PSA_SUCCESS) goto exit;

    switch (alg) {
    case PSA_ALG_AES_KW:
    case PSA_ALG_AES_KWP:
        if (data_length < 8) {
            status = PSA_ERROR_INVALID_ARGUMENT;
            goto exit;
        }
        storage_size = data_length - 8;
        break;
    default:
        storage_size = data_length;
        break;
    }

    status = psa_allocate_buffer_to_slot(k_slot, storage_size);
    if (status != PSA_SUCCESS) goto exit;

    status = psa_driver_wrapper_unwrap_key(
        attributes,
        &w_slot->attr, w_slot->key.data, w_slot->key.bytes,
        alg,
        data, data_length,
        k_slot->key.data, k_slot->key.bytes, &k_slot->key.bytes);
    if (status != PSA_SUCCESS) goto exit;

    status = psa_finish_key_creation(k_slot, driver, key);

exit:
    unlock_status = psa_unregister_read_under_mutex(w_slot);
    if (status == PSA_SUCCESS) {
        status = unlock_status;
    }

    if (status != PSA_SUCCESS) {
        psa_fail_key_creation(k_slot, driver);
        *key = MBEDTLS_SVC_KEY_ID_INIT;
    }

    return status;
}


/****************************************************************/
/* Random generation */
/****************************************************************/

psa_status_t psa_generate_random(uint8_t *output,
                                 size_t output_size)
{
    GUARD_MODULE_INITIALIZED;
    return psa_driver_wrapper_get_random(
        &global_data.rng,
        output, output_size);
}

#if defined(MBEDTLS_PSA_INJECT_ENTROPY)
#include "entropy_poll.h"

psa_status_t mbedtls_psa_inject_entropy(const uint8_t *seed,
                                        size_t seed_size)
{
    if (psa_get_initialized()) {
        return PSA_ERROR_NOT_PERMITTED;
    }

    if (((seed_size < MBEDTLS_ENTROPY_MIN_PLATFORM) ||
         (seed_size < MBEDTLS_ENTROPY_BLOCK_SIZE)) ||
        (seed_size > MBEDTLS_ENTROPY_MAX_SEED_SIZE)) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    return mbedtls_psa_storage_inject_entropy(seed, seed_size);
}
#endif /* MBEDTLS_PSA_INJECT_ENTROPY */

/** Validate the key type and size for key generation
 *
 * \param  type  The key type
 * \param  bits  The number of bits of the key
 *
 * \retval #PSA_SUCCESS
 *         The key type and size are valid.
 * \retval #PSA_ERROR_INVALID_ARGUMENT
 *         The size in bits of the key is not valid.
 * \retval #PSA_ERROR_NOT_SUPPORTED
 *         The type and/or the size in bits of the key or the combination of
 *         the two is not supported.
 */
static psa_status_t psa_validate_key_type_and_size_for_key_generation(
    psa_key_type_t type, size_t bits)
{
    psa_status_t status = PSA_ERROR_CORRUPTION_DETECTED;

    if (key_type_is_raw_bytes(type)) {
        status = psa_validate_unstructured_key_bit_size(type, bits);
        if (status != PSA_SUCCESS) {
            return status;
        }
    } else
#if defined(PSA_WANT_KEY_TYPE_RSA_KEY_PAIR_GENERATE)
    if (PSA_KEY_TYPE_IS_RSA(type) && PSA_KEY_TYPE_IS_KEY_PAIR(type)) {
        if (bits > PSA_VENDOR_RSA_MAX_KEY_BITS) {
            return PSA_ERROR_NOT_SUPPORTED;
        }
        if (bits < PSA_VENDOR_RSA_GENERATE_MIN_KEY_BITS) {
            return PSA_ERROR_NOT_SUPPORTED;
        }

        /* Accept only byte-aligned keys, for the same reasons as
         * in psa_import_rsa_key(). */
        if (bits % 8 != 0) {
            return PSA_ERROR_NOT_SUPPORTED;
        }
    } else
#endif /* defined(PSA_WANT_KEY_TYPE_RSA_KEY_PAIR_GENERATE) */

#if defined(PSA_WANT_KEY_TYPE_ECC_KEY_PAIR_GENERATE)
    if (PSA_KEY_TYPE_IS_ECC(type) && PSA_KEY_TYPE_IS_KEY_PAIR(type)) {
        /* To avoid empty block, return successfully here. */
        return PSA_SUCCESS;
    } else
#endif /* defined(PSA_WANT_KEY_TYPE_ECC_KEY_PAIR_GENERATE) */

#if defined(PSA_WANT_KEY_TYPE_ML_DSA_KEY_PAIR_GENERATE)
    if (type == PSA_KEY_TYPE_ML_DSA_KEY_PAIR) {
        return PSA_SUCCESS;
    } else
#endif /* defined(PSA_WANT_KEY_TYPE_ML_DSA_KEY_PAIR_GENERATE) */

#if defined(PSA_WANT_KEY_TYPE_ML_KEM_KEY_PAIR_GENERATE)
    if (type == PSA_KEY_TYPE_ML_KEM_KEY_PAIR) {
        return PSA_SUCCESS;
    } else
#endif /* defined(PSA_WANT_KEY_TYPE_ML_KEM_KEY_PAIR_GENERATE) */
    {
        return PSA_ERROR_NOT_SUPPORTED;
    }

    return PSA_SUCCESS;
}

psa_status_t psa_generate_key_internal(
    const psa_key_attributes_t *attributes,
    uint8_t *key_buffer, size_t key_buffer_size, size_t *key_buffer_length)
{
    psa_status_t status = PSA_ERROR_CORRUPTION_DETECTED;
    psa_key_type_t type = attributes->type;

    if (key_type_is_raw_bytes(type)
#if defined(PSA_WANT_KEY_TYPE_ML_DSA_KEY_PAIR_GENERATE)
        || type == PSA_KEY_TYPE_ML_DSA_KEY_PAIR
#endif
#if defined(PSA_WANT_KEY_TYPE_ML_KEM_KEY_PAIR_GENERATE)
        || type == PSA_KEY_TYPE_ML_KEM_KEY_PAIR
#endif
    ) {
        status = psa_generate_random(key_buffer, key_buffer_size);
        if (status != PSA_SUCCESS) {
            return status;
        }
    } else {
        (void) key_buffer_length;
        return PSA_ERROR_NOT_SUPPORTED;
    }

    return PSA_SUCCESS;
}

psa_status_t psa_generate_key(const psa_key_attributes_t *attributes,
                              mbedtls_svc_key_id_t *key)
{
    psa_status_t status;
    psa_key_slot_t *slot = NULL;
    psa_se_drv_table_entry_t *driver = NULL;
    size_t key_buffer_size;
    psa_key_type_t key_type = psa_get_key_type(attributes);

    *key = MBEDTLS_SVC_KEY_ID_INIT;

    /* Reject any attempt to create a zero-length key so that we don't
     * risk tripping up later, e.g. on a malloc(0) that returns NULL. */
    if (psa_get_key_bits(attributes) == 0) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    /* Reject any attempt to create a public key. */
    if (PSA_KEY_TYPE_IS_PUBLIC_KEY(attributes->type)) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    /* Check the ecc keys for plausibility */
    if(PSA_KEY_TYPE_IS_ECC_KEY_PAIR(key_type) || PSA_KEY_TYPE_IS_ECC_PUBLIC_KEY(key_type)) {
        status = psa_validate_ecc_key_attr(attributes);
        if (status != PSA_SUCCESS) {
            return status;
        }
    }


    status = psa_start_key_creation(PSA_KEY_CREATION_GENERATE, attributes,
                                    &slot, &driver);
    if (status != PSA_SUCCESS) {
        goto exit;
    }

    /* In the case of a transparent key or an opaque key stored in local
     * storage ( thus not in the case of generating a key in a secure element
     * with storage ( MBEDTLS_PSA_CRYPTO_SE_C ) ),we have to allocate a
     * buffer to hold the generated key material. */
    if (slot->key.bytes == 0) {
        if (PSA_KEY_LIFETIME_GET_LOCATION(attributes->lifetime) ==
            PSA_KEY_LOCATION_LOCAL_STORAGE) {
            status = psa_validate_key_type_and_size_for_key_generation(
                attributes->type, attributes->bits);
            if (status != PSA_SUCCESS) {
                goto exit;
            }

            key_buffer_size = PSA_EXPORT_KEY_OUTPUT_SIZE(
                attributes->type,
                attributes->bits);
        } else {
            status = psa_driver_wrapper_get_key_buffer_size(
                attributes, &key_buffer_size);
            if (status != PSA_SUCCESS) {
                goto exit;
            }
        }

        status = psa_allocate_buffer_to_slot(slot, key_buffer_size);
        if (status != PSA_SUCCESS) {
            goto exit;
        }
    }

    status = psa_driver_wrapper_generate_key(attributes,
                                             slot->key.data, slot->key.bytes, &slot->key.bytes);

    if (status != PSA_SUCCESS) {
        psa_remove_key_data_from_memory(slot);
    }

exit:
    if (status == PSA_SUCCESS) {
        status = psa_finish_key_creation(slot, driver, key);
    }
    if (status != PSA_SUCCESS) {
        psa_fail_key_creation(slot, driver);
    }

    return status;
}

/****************************************************************/
/* Module setup */
/****************************************************************/

#if !defined(MBEDTLS_PSA_CRYPTO_EXTERNAL_RNG)
psa_status_t mbedtls_psa_crypto_configure_entropy_sources(
    void (* entropy_init)(mbedtls_entropy_context *ctx),
    void (* entropy_free)(mbedtls_entropy_context *ctx))
{
    (void)entropy_init;
    (void)entropy_free;
    return PSA_SUCCESS;
}
#endif

void mbedtls_psa_crypto_free(void)
{

#if defined(MBEDTLS_THREADING_C)
    mbedtls_mutex_lock(&mbedtls_threading_psa_globaldata_mutex);
#endif /* defined(MBEDTLS_THREADING_C) */

    /* Nothing to do to free transaction. */
    if (global_data.initialized & PSA_CRYPTO_SUBSYSTEM_TRANSACTION_INITIALIZED) {
        global_data.initialized &= ~PSA_CRYPTO_SUBSYSTEM_TRANSACTION_INITIALIZED;
    }

    if (global_data.initialized & PSA_CRYPTO_SUBSYSTEM_KEY_SLOTS_INITIALIZED) {
        psa_wipe_all_key_slots();
        global_data.initialized &= ~PSA_CRYPTO_SUBSYSTEM_KEY_SLOTS_INITIALIZED;
    }

#if defined(MBEDTLS_THREADING_C)
    mbedtls_mutex_unlock(&mbedtls_threading_psa_globaldata_mutex);
#endif /* defined(MBEDTLS_THREADING_C) */

#if defined(MBEDTLS_THREADING_C)
    mbedtls_mutex_lock(&mbedtls_threading_psa_rngdata_mutex);
#endif /* defined(MBEDTLS_THREADING_C) */

    if (global_data.rng_state != RNG_NOT_INITIALIZED) {
        psa_driver_wrapper_free_random(&global_data.rng);
    }
    global_data.rng_state = RNG_NOT_INITIALIZED;
    mbedtls_platform_zeroize(&global_data.rng, sizeof(global_data.rng));

#if defined(MBEDTLS_THREADING_C)
    mbedtls_mutex_unlock(&mbedtls_threading_psa_rngdata_mutex);
#endif /* defined(MBEDTLS_THREADING_C) */

#if defined(MBEDTLS_THREADING_C)
    mbedtls_mutex_lock(&mbedtls_threading_psa_globaldata_mutex);
#endif /* defined(MBEDTLS_THREADING_C) */

    /* Terminate drivers */
    if (global_data.initialized & PSA_CRYPTO_SUBSYSTEM_DRIVER_WRAPPERS_INITIALIZED) {
        psa_driver_wrapper_free();
        global_data.initialized &= ~PSA_CRYPTO_SUBSYSTEM_DRIVER_WRAPPERS_INITIALIZED;
    }

#if defined(MBEDTLS_THREADING_C)
    mbedtls_mutex_unlock(&mbedtls_threading_psa_globaldata_mutex);
#endif /* defined(MBEDTLS_THREADING_C) */

}

#if defined(PSA_CRYPTO_STORAGE_HAS_TRANSACTIONS)
/** Recover a transaction that was interrupted by a power failure.
 *
 * This function is called during initialization, before psa_crypto_init()
 * returns. If this function returns a failure status, the initialization
 * fails.
 */
static psa_status_t psa_crypto_recover_transaction(
    const psa_crypto_transaction_t *transaction)
{
    switch (transaction->unknown.type) {
        case PSA_CRYPTO_TRANSACTION_CREATE_KEY:
        case PSA_CRYPTO_TRANSACTION_DESTROY_KEY:
        /* TODO - fall through to the failure case until this
         * is implemented.
         * https://github.com/ARMmbed/mbed-crypto/issues/218
         */
        default:
            /* We found an unsupported transaction in the storage.
             * We don't know what state the storage is in. Give up. */
            return PSA_ERROR_DATA_INVALID;
    }
}
#endif /* PSA_CRYPTO_STORAGE_HAS_TRANSACTIONS */

psa_status_t psa_crypto_init(void)
{
    psa_status_t status = PSA_SUCCESS;
    uint8_t driver_wrappers_initialized = 0;

    /* Double initialization is explicitly allowed. Early out if everything is
     * done. */
    if (psa_get_initialized()) {
        return PSA_SUCCESS;
    }

    /* Init drivers */

#if defined(MBEDTLS_THREADING_C)
    PSA_THREADING_CHK_GOTO_EXIT(mbedtls_mutex_lock(&mbedtls_threading_psa_globaldata_mutex));
#endif /* defined(MBEDTLS_THREADING_C) */

    if (!(global_data.initialized & PSA_CRYPTO_SUBSYSTEM_DRIVER_WRAPPERS_INITIALIZED)) {
        /* Init drivers */
        status = psa_driver_wrapper_init();

        /* Drivers need shutdown regardless of startup errors. */
        global_data.initialized |= PSA_CRYPTO_SUBSYSTEM_DRIVER_WRAPPERS_INITIALIZED;
    }

#if defined(MBEDTLS_THREADING_C)
    PSA_THREADING_CHK_GOTO_EXIT(mbedtls_mutex_unlock(
        &mbedtls_threading_psa_globaldata_mutex));
#endif /* defined(MBEDTLS_THREADING_C) */

    if (status != PSA_SUCCESS) {
        goto exit;
    }

    /* Init key slots */

#if defined(MBEDTLS_THREADING_C)
    PSA_THREADING_CHK_GOTO_EXIT(mbedtls_mutex_lock(&mbedtls_threading_psa_globaldata_mutex));
#endif /* defined(MBEDTLS_THREADING_C) */

    if (!(global_data.initialized & PSA_CRYPTO_SUBSYSTEM_KEY_SLOTS_INITIALIZED)) {
        status = psa_initialize_key_slots();

        /* Need to wipe keys even if initialization fails. */
        global_data.initialized |= PSA_CRYPTO_SUBSYSTEM_KEY_SLOTS_INITIALIZED;
    }

#if defined(MBEDTLS_THREADING_C)
    PSA_THREADING_CHK_GOTO_EXIT(mbedtls_mutex_unlock(
        &mbedtls_threading_psa_globaldata_mutex));
#endif /* defined(MBEDTLS_THREADING_C) */

    if (status != PSA_SUCCESS) {
        goto exit;
    }

    /* Init RNG */

#if defined(MBEDTLS_THREADING_C)
    PSA_THREADING_CHK_GOTO_EXIT(mbedtls_mutex_lock(&mbedtls_threading_psa_globaldata_mutex));
#endif /* defined(MBEDTLS_THREADING_C) */

    driver_wrappers_initialized =
        (global_data.initialized & PSA_CRYPTO_SUBSYSTEM_DRIVER_WRAPPERS_INITIALIZED);

#if defined(MBEDTLS_THREADING_C)
    PSA_THREADING_CHK_GOTO_EXIT(mbedtls_mutex_unlock(
        &mbedtls_threading_psa_globaldata_mutex));
#endif /* defined(MBEDTLS_THREADING_C) */

    /* Need to use separate mutex here, as initialisation can require
    * testing of init flags, which requires locking the global data
    * mutex. */
#if defined(MBEDTLS_THREADING_C)
    PSA_THREADING_CHK_GOTO_EXIT(mbedtls_mutex_lock(&mbedtls_threading_psa_rngdata_mutex));
#endif /* defined(MBEDTLS_THREADING_C) */

    /* Initialize and seed the random generator. */
    if (global_data.rng_state == RNG_NOT_INITIALIZED && driver_wrappers_initialized) {
        status = psa_driver_wrapper_init_random(&global_data.rng);
        global_data.rng_state = RNG_SEEDED;
    }

#if defined(MBEDTLS_THREADING_C)
    PSA_THREADING_CHK_GOTO_EXIT(mbedtls_mutex_unlock(
        &mbedtls_threading_psa_rngdata_mutex));
#endif /* defined(MBEDTLS_THREADING_C) */

    if (status != PSA_SUCCESS) {
        goto exit;
    }

    /* Init transactions */

#if defined(MBEDTLS_THREADING_C)
    PSA_THREADING_CHK_GOTO_EXIT(mbedtls_mutex_lock(&mbedtls_threading_psa_globaldata_mutex));
#endif /* defined(MBEDTLS_THREADING_C) */

    if (!(global_data.initialized & PSA_CRYPTO_SUBSYSTEM_TRANSACTION_INITIALIZED)) {
#if defined(PSA_CRYPTO_STORAGE_HAS_TRANSACTIONS)
        status = psa_crypto_load_transaction();
        if (status == PSA_SUCCESS) {
            status = psa_crypto_recover_transaction(&psa_crypto_transaction);
            if (status == PSA_SUCCESS) {
                global_data.initialized |= PSA_CRYPTO_SUBSYSTEM_TRANSACTION_INITIALIZED;
            }
            status = psa_crypto_stop_transaction();
        } else if (status == PSA_ERROR_DOES_NOT_EXIST) {
            /* There's no transaction to complete. It's all good. */
            global_data.initialized |= PSA_CRYPTO_SUBSYSTEM_TRANSACTION_INITIALIZED;
            status = PSA_SUCCESS;
        }
#else /* defined(PSA_CRYPTO_STORAGE_HAS_TRANSACTIONS) */
        global_data.initialized |= PSA_CRYPTO_SUBSYSTEM_TRANSACTION_INITIALIZED;
        status = PSA_SUCCESS;
#endif /* defined(PSA_CRYPTO_STORAGE_HAS_TRANSACTIONS) */
    }

#if defined(MBEDTLS_THREADING_C)
    PSA_THREADING_CHK_GOTO_EXIT(mbedtls_mutex_unlock(
        &mbedtls_threading_psa_globaldata_mutex));
#endif /* defined(MBEDTLS_THREADING_C) */

exit:
    if (status != PSA_SUCCESS) {
        mbedtls_psa_crypto_free();
    }
    return status;
}

#endif /* MBEDTLS_PSA_CRYPTO_C */
