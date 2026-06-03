/*
 *  Functions to delegate cryptographic operations to an available
 *  and appropriate accelerator.
 */
/*
 *  Copyright The Mbed TLS Contributors
 *  SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
 */

/*
 * NOTICE: This file has been modified by Oberon microsystems AG.
 */

#include "tf_psa_crypto_common.h"
#include "psa/crypto.h"
#include "psa_crypto_core.h"
#include "psa_crypto_driver_wrappers.h"

#if defined(MBEDTLS_PSA_CRYPTO_C)

/* Include test driver definition when running tests */

#ifdef PSA_NEED_ACME_RNG_DRIVER
#include "acme_rng.h"
#endif
#ifdef PSA_NEED_ACME_SHA_DRIVER
#include "acme_sha.h"
#endif
#ifdef PSA_NEED_ACME_AES_DRIVER
#include "acme_aes.h"
#endif
#ifdef PSA_NEED_ACME_MAC_DRIVER
#include "acme_mac.h"
#endif
#ifdef PSA_NEED_ACME_KDF_DRIVER
#include "acme_kdf.h"
#endif


/* Unique driver ids */
#define ACME_DRIVER_ID         1
#define ACME_SHA_DRIVER_ID     2
#define ACME_AES_DRIVER_ID     3
#define ACME_MAC_DRIVER_ID     4
#define ACME_KDF_DRIVER_ID     5
#define ACME_OPAQUE_DRIVER_ID  6  


psa_status_t psa_driver_wrapper_init()
{
    psa_status_t status;

    // status = acme_opaque_init();
    // if (status != PSA_SUCCESS) return status;

    (void)status;
    return PSA_SUCCESS;
}

void psa_driver_wrapper_free()
{
    // acme_opaque_free();
}

psa_status_t psa_driver_wrapper_sign_message_with_context(
    const psa_key_attributes_t *attributes,
    const uint8_t *key_buffer, size_t key_buffer_size,
    psa_algorithm_t alg,
    const uint8_t *input, size_t input_length,
    const uint8_t *context, size_t context_length,
    uint8_t *signature, size_t signature_size, size_t *signature_length)
{
    psa_status_t status;

    switch (PSA_KEY_LIFETIME_GET_LOCATION(attributes->lifetime)) {
    case PSA_KEY_LOCATION_LOCAL_STORAGE:
        /* Add cases for transparent drivers here */
        // status = acme_sign_message_with_context(
        //     attributes, key_buffer, key_buffer_size,
        //     alg,
        //     input, input_length,
        //     context, context_length,
        //     signature, signature_size, signature_length);
        // if (status != PSA_ERROR_NOT_SUPPORTED) return status;
        break;

    /* Add cases for opaque drivers here */
    // case ACME_OPAQUE_DRIVER_LOCATION:
    //     return acme_opaque_signature_sign_message_with_context(
    //         attributes, key_buffer, key_buffer_size,
    //         alg,
    //         input, input_length,
    //         context, context_length,
    //         signature, signature_size, signature_length);

    default:
        /* Key is declared with a lifetime not known to us */
        (void)status;
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    /* Use generic fallback */
    return psa_sign_message_with_context_builtin(
        attributes, key_buffer, key_buffer_size,
        alg,
        input, input_length,
        context, context_length,
        signature, signature_size, signature_length);
}

psa_status_t psa_driver_wrapper_verify_message_with_context(
    const psa_key_attributes_t *attributes,
    const uint8_t *key_buffer, size_t key_buffer_size,
    psa_algorithm_t alg,
    const uint8_t *input, size_t input_length,
    const uint8_t *context, size_t context_length,
    const uint8_t *signature, size_t signature_length)
{
    psa_status_t status;

    switch (PSA_KEY_LIFETIME_GET_LOCATION(attributes->lifetime)) {
    case PSA_KEY_LOCATION_LOCAL_STORAGE:
        /* Add cases for transparent drivers here */
        // status = acme_verify_message_with_context(
        //     attributes, key_buffer, key_buffer_size,
        //     alg,
        //     input, input_length,
        //     context, context_length,
        //     signature, signature_length);
        // if (status != PSA_ERROR_NOT_SUPPORTED) return status;
        break;

    /* Add cases for opaque drivers here */
    // case ACME_OPAQUE_DRIVER_LOCATION:
    //     return acme_opaque_signature_verify_message_with_context(
    //         attributes, key_buffer, key_buffer_size,
    //         alg,
    //         input, input_length,
    //         context, context_length,
    //         signature, signature_length);

    default:
        /* Key is declared with a lifetime not known to us */
        (void)status;
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    /* Use generic fallback */
    return psa_verify_message_with_context_builtin(
        attributes, key_buffer, key_buffer_size,
        alg,
        input, input_length,
        context, context_length,
        signature, signature_length);
}

psa_status_t psa_driver_wrapper_sign_hash_with_context(
    const psa_key_attributes_t *attributes,
    const uint8_t *key_buffer, size_t key_buffer_size,
    psa_algorithm_t alg, const uint8_t *hash, size_t hash_length,
    const uint8_t *context, size_t context_length,
    uint8_t *signature, size_t signature_size, size_t *signature_length)
{
    switch (PSA_KEY_LIFETIME_GET_LOCATION(attributes->lifetime)) {
    case PSA_KEY_LOCATION_LOCAL_STORAGE:
        /* Add cases for transparent drivers here */
        // return acme_sign_hash_with_context(
        //     attributes, key_buffer, key_buffer_size,
        //     alg,
        //     hash, hash_length,
        //     context, context_length,
        //     signature, signature_size, signature_length);
        return PSA_ERROR_NOT_SUPPORTED;

    /* Add cases for opaque drivers here */
    // case ACME_OPAQUE_DRIVER_LOCATION:
    //     return acme_opaque_signature_sign_hash(
    //         attributes, key_buffer, key_buffer_size,
    //         alg,
    //         hash, hash_length,
    //         context, context_length,
    //         signature, signature_size, signature_length);

    default:
        /* Key is declared with a lifetime not known to us */
        (void)key_buffer;
        (void)key_buffer_size;
        (void)alg;
        (void)hash;
        (void)hash_length;
        (void)context;
        (void)context_length;
        (void)signature;
        (void)signature_size;
        (void)signature_length;
        return PSA_ERROR_INVALID_ARGUMENT;
    }
}

psa_status_t psa_driver_wrapper_verify_hash_with_context(
    const psa_key_attributes_t *attributes,
    const uint8_t *key_buffer, size_t key_buffer_size,
    psa_algorithm_t alg, const uint8_t *hash, size_t hash_length,
    const uint8_t *context, size_t context_length,
    const uint8_t *signature, size_t signature_length)
{
    switch (PSA_KEY_LIFETIME_GET_LOCATION(attributes->lifetime)) {
    case PSA_KEY_LOCATION_LOCAL_STORAGE:
        /* Add cases for transparent drivers here */
        // return acme_verify_hash_with_context(
        //     attributes, key_buffer, key_buffer_size,
        //     alg,
        //     hash, hash_length,
        //     context, context_length,
        //     signature, signature_length);
        return PSA_ERROR_NOT_SUPPORTED;

    /* Add cases for opaque drivers here */
    // case ACME_OPAQUE_DRIVER_LOCATION:
    //     return acme_opaque_signature_verify_hash(
    //         attributes, key_buffer, key_buffer_size,
    //         alg,
    //         hash, hash_length,
    //         context, context_length,
    //         signature, signature_length);

    default:
        /* Key is declared with a lifetime not known to us */
        (void)key_buffer;
        (void)key_buffer_size;
        (void)alg;
        (void)hash;
        (void)hash_length;
        (void)context;
        (void)context_length;
        (void)signature;
        (void)signature_length;
        return PSA_ERROR_INVALID_ARGUMENT;
    }
}

/** Calculate the key buffer size required to store the key material of a key
 *  associated with an opaque driver from input key data.
 *
 * \param[in] attributes        The key attributes
 * \param[in] data              The input key data.
 * \param[in] data_length       The input data length.
 * \param[out] key_buffer_size  Minimum buffer size to contain the key material.
 *
 * \retval #PSA_SUCCESS
 * \retval #PSA_ERROR_INVALID_ARGUMENT
 * \retval #PSA_ERROR_NOT_SUPPORTED
 */
psa_status_t psa_driver_wrapper_get_key_buffer_size_from_key_data(
    const psa_key_attributes_t *attributes,
    const uint8_t *data, size_t data_length, size_t *key_buffer_size)
{
    psa_key_type_t key_type = attributes->type;

    *key_buffer_size = 0;
    switch (PSA_KEY_LIFETIME_GET_LOCATION(attributes->lifetime)) {
    /* Add cases for opaque drivers here */
    // case ACME_OPAQUE_DRIVER_LOCATION:
    //     *key_buffer_size = acme_opaque_size_function(
    //         key_type, PSA_BYTES_TO_BITS(data_length));
    //     return *key_buffer_size != 0 ? PSA_SUCCESS : PSA_ERROR_NOT_SUPPORTED;

    default:
        (void)key_type;
        (void)data;
        (void)data_length;
        return PSA_ERROR_INVALID_ARGUMENT;
    }
}

/** Get the key buffer size required to store the key material of a key
 *  associated with an opaque driver.
 *
 * \param[in] attributes  The key attributes.
 * \param[out] key_buffer_size  Minimum buffer size to contain the key material
 *
 * \retval #PSA_SUCCESS
 *         The minimum size for a buffer to contain the key material has been
 *         returned successfully.
 * \retval #PSA_ERROR_NOT_SUPPORTED
 *         The type and/or the size in bits of the key or the combination of
 *         the two is not supported.
 * \retval #PSA_ERROR_INVALID_ARGUMENT
 *         The key is declared with a lifetime not known to us.
 */
psa_status_t psa_driver_wrapper_get_key_buffer_size(
    const psa_key_attributes_t *attributes,
    size_t *key_buffer_size)
{
    psa_key_type_t key_type = attributes->type;
    size_t key_bits = attributes->bits;

    *key_buffer_size = 0;
    switch (PSA_KEY_LIFETIME_GET_LOCATION(attributes->lifetime)) {
    /* Add cases for opaque drivers here */
    // case ACME_OPAQUE_DRIVER_LOCATION:
    //     *key_buffer_size = acme_opaque_size_function(
    //         key_type, key_bits);
    //     return *key_buffer_size != 0 ? PSA_SUCCESS : PSA_ERROR_NOT_SUPPORTED;

    default:
        (void)key_type;
        (void)key_bits;
        return PSA_ERROR_INVALID_ARGUMENT;
    }
}

psa_status_t psa_driver_wrapper_generate_key(
    const psa_key_attributes_t *attributes,
    uint8_t *key_buffer, size_t key_buffer_size, size_t *key_buffer_length)
{
    psa_status_t status;

    switch (PSA_KEY_LIFETIME_GET_LOCATION(attributes->lifetime)) {
    case PSA_KEY_LOCATION_LOCAL_STORAGE:
        /* Add cases for transparent drivers here */
        // status = acme_generate_key(
        //     attributes, key_buffer, key_buffer_size, key_buffer_length);
        // if (status != PSA_ERROR_NOT_SUPPORTED) return status;
        break;

    /* Add cases for opaque drivers here */
    // case ACME_OPAQUE_DRIVER_LOCATION:
    //     return acme_opaque_generate_key(
    //         attributes, key_buffer, key_buffer_size, key_buffer_length);

    default:
        /* Key is declared with a lifetime not known to us */
        (void)status;
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    /* Use generic fallback for basic key types */
    return psa_generate_key_internal(
        attributes, key_buffer, key_buffer_size, key_buffer_length);
}

psa_status_t psa_driver_wrapper_import_key(
    const psa_key_attributes_t *attributes,
    const uint8_t *data, size_t data_length,
    uint8_t *key_buffer, size_t key_buffer_size, size_t *key_buffer_length,
    size_t *bits)
{
    psa_status_t status;

    switch (PSA_KEY_LIFETIME_GET_LOCATION(attributes->lifetime)) {
    case PSA_KEY_LOCATION_LOCAL_STORAGE:
        /* Add cases for transparent drivers here */
        // status = acme_import_key(
        //     attributes, data, data_length,
        //     key_buffer, key_buffer_size,
        //     key_buffer_length, bits);
        // if (status != PSA_ERROR_NOT_SUPPORTED) return status;
        break;

    /* Add cases for opaque drivers here */
    // case ACME_OPAQUE_DRIVER_LOCATION:
    //     return acme_opaque_import_key(
    //         attributes, data, data_length,
    //         key_buffer, key_buffer_size,
    //         key_buffer_length, bits);

    default:
        (void)status;
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    /* Use generic fallback for simple cases */
    return psa_import_key_into_slot(
        attributes, data, data_length,
        key_buffer, key_buffer_size,
        key_buffer_length, bits);
}

psa_status_t psa_driver_wrapper_export_key(
    const psa_key_attributes_t *attributes,
    const uint8_t *key_buffer, size_t key_buffer_size,
    uint8_t *data, size_t data_size, size_t *data_length)

{
    switch (PSA_KEY_LIFETIME_GET_LOCATION(attributes->lifetime)) {
    case PSA_KEY_LOCATION_LOCAL_STORAGE:
        /* Add cases for transparent drivers here */
        return psa_export_key_internal(
            attributes, key_buffer, key_buffer_size,
            data, data_size, data_length);

    /* Add cases for opaque drivers here */
    // case ACME_OPAQUE_DRIVER_LOCATION:
    //     return acme_opaque_export_key(
    //         attributes, key_buffer, key_buffer_size,
    //         data, data_size, data_length);

    default:
        /* Key is declared with a lifetime not known to us */
        (void)key_buffer;
        (void)key_buffer_size;
        (void)data;
        (void)data_size;
        (void)data_length;
        return PSA_ERROR_INVALID_ARGUMENT;
    }
}

psa_status_t psa_driver_wrapper_export_public_key(
    const psa_key_attributes_t *attributes,
    const uint8_t *key_buffer, size_t key_buffer_size,
    uint8_t *data, size_t data_size, size_t *data_length)

{
    psa_status_t status;

    switch (PSA_KEY_LIFETIME_GET_LOCATION(attributes->lifetime)) {
    case PSA_KEY_LOCATION_LOCAL_STORAGE:
        /* Add cases for transparent drivers here */
        // status = acme_export_public_key(
        //     attributes, key_buffer, key_buffer_size,
        //     data, data_size, data_length);
        // if (status != PSA_ERROR_NOT_SUPPORTED) return status;
        break;

    /* Add cases for opaque drivers here */
    // case ACME_OPAQUE_DRIVER_LOCATION:
    //     return acme_opaque_export_public_key(
    //         attributes, key_buffer, key_buffer_size,
    //         data, data_size, data_length);

    default:
        /* Key is declared with a lifetime not known to us */
        (void)status;
        (void)key_buffer;
        (void)key_buffer_size;
        (void)data;
        (void)data_size;
        (void)data_length;
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    /* Use generic fallback for simple cases */
    return psa_export_public_key_internal(
        attributes, key_buffer, key_buffer_size,
        data, data_size, data_length);
}

#ifdef MBEDTLS_PSA_CRYPTO_BUILTIN_KEYS
psa_status_t psa_driver_wrapper_get_builtin_key(
    psa_drv_slot_number_t slot_number,
    psa_key_attributes_t *attributes,
    uint8_t *key_buffer, size_t key_buffer_size, size_t *key_buffer_length)
{
    switch (PSA_KEY_LIFETIME_GET_LOCATION(attributes->lifetime)) {
    default:
        (void)slot_number;
        (void)key_buffer;
        (void)key_buffer_size;
        (void)key_buffer_length;
        return PSA_ERROR_DOES_NOT_EXIST;
    }
}
#endif /* MBEDTLS_PSA_CRYPTO_BUILTIN_KEYS */

psa_status_t psa_driver_wrapper_copy_key(
    psa_key_attributes_t *attributes,
    const uint8_t *source_key, size_t source_key_length,
    uint8_t *target_key_buffer, size_t target_key_buffer_size,
    size_t *target_key_buffer_length)
{
    switch (PSA_KEY_LIFETIME_GET_LOCATION(attributes->lifetime)) {
    /* Add cases for opaque drivers here */
    // case ACME_OPAQUE_DRIVER_LOCATION:
    //     return acme_opaque_copy_key(
    //         attributes, source_key, source_key_length,
    //         target_key_buffer, target_key_buffer_size, target_key_buffer_length);

    default:
        (void)source_key;
        (void)source_key_length;
        (void)target_key_buffer;
        (void)target_key_buffer_size;
        (void)target_key_buffer_length;
        return PSA_ERROR_INVALID_ARGUMENT;
    }
}

psa_status_t psa_driver_wrapper_derive_key(
    const psa_key_attributes_t *attributes,
    const uint8_t *input, size_t input_length,
    uint8_t *key_buffer, size_t key_buffer_size, size_t *key_buffer_length)
{
    switch (PSA_KEY_LIFETIME_GET_LOCATION(attributes->lifetime)) {
    case PSA_KEY_LOCATION_LOCAL_STORAGE:
        /* Add cases for transparent drivers here */
        // return acme_derive_key(
        //     attributes, input, input_length,
        //     key_buffer, key_buffer_size, key_buffer_length);
        return PSA_ERROR_NOT_SUPPORTED;

    /* Add cases for opaque drivers here */
    // case ACME_OPAQUE_DRIVER_LOCATION:
    //     return acme_opaque_derive_key(
    //         attributes, input, input_length,
    //         key_buffer, key_buffer_size, key_buffer_length);

    default:
        /* Key is declared with a lifetime not known to us */
        (void) input;
        (void) input_length;
        (void) key_buffer;
        (void) key_buffer_size;
        (void) key_buffer_length;
        return PSA_ERROR_INVALID_ARGUMENT;
    }
}

psa_status_t psa_driver_wrapper_destroy_key(
    const psa_key_attributes_t *attributes,
    const uint8_t *key_buffer,
    size_t key_buffer_size)
{
    switch (PSA_KEY_LIFETIME_GET_LOCATION(attributes->lifetime)) {
    /* Add cases for opaque drivers here */
    // case ACME_OPAQUE_DRIVER_LOCATION:
    //     return acme_opaque_destroy_key(
    //         attributes, key_buffer, key_buffer_size);

    default:
        (void)key_buffer;
        (void)key_buffer_size;
        return PSA_SUCCESS;
    }
}

/*
 * Cipher functions
 */
psa_status_t psa_driver_wrapper_cipher_encrypt(
    const psa_key_attributes_t *attributes,
    const uint8_t *key_buffer, size_t key_buffer_size,
    psa_algorithm_t alg,
    const uint8_t *iv, size_t iv_length,
    const uint8_t *input, size_t input_length,
    uint8_t *output, size_t output_size, size_t *output_length)
{
    psa_status_t status;

    switch (PSA_KEY_LIFETIME_GET_LOCATION(attributes->lifetime)) {
    case PSA_KEY_LOCATION_LOCAL_STORAGE:
        /* Add cases for transparent drivers here */
#ifdef PSA_NEED_ACME_AES_DRIVER
        status = acme_cipher_encrypt(
            attributes, key_buffer, key_buffer_size,
            alg,
            iv, iv_length,
            input, input_length,
            output, output_size, output_length);
        if (status != PSA_ERROR_NOT_SUPPORTED) return status;
#endif /* PSA_NEED_ACME_AES_DRIVER */
        /* Add fallback driver call here */
        return PSA_ERROR_NOT_SUPPORTED;

    /* Add cases for opaque drivers here */
    // case ACME_OPAQUE_DRIVER_LOCATION:
    //     return acme_opaque_cipher_encrypt(
    //         attributes, key_buffer, key_buffer_size,
    //         alg,
    //         iv, iv_length,
    //         input, input_length,
    //         output, output_size, output_length);

    default:
        /* Key is declared with a lifetime not known to us */
        (void)key_buffer;
        (void)key_buffer_size;
        (void)alg;
        (void)iv;
        (void)iv_length;
        (void)input;
        (void)input_length;
        (void)output;
        (void)output_size;
        (void)output_length;
        (void)status;
        return PSA_ERROR_INVALID_ARGUMENT;
    }
}

psa_status_t psa_driver_wrapper_cipher_decrypt(
    const psa_key_attributes_t *attributes,
    const uint8_t *key_buffer, size_t key_buffer_size,
    psa_algorithm_t alg,
    const uint8_t *input, size_t input_length,
    uint8_t *output, size_t output_size, size_t *output_length)
{
    psa_status_t status;

    switch (PSA_KEY_LIFETIME_GET_LOCATION(attributes->lifetime)) {
    case PSA_KEY_LOCATION_LOCAL_STORAGE:
        /* Add cases for transparent drivers here */
#ifdef PSA_NEED_ACME_AES_DRIVER
        status = acme_cipher_decrypt(
            attributes, key_buffer, key_buffer_size,
            alg,
            input, input_length,
            output, output_size, output_length);
        if (status != PSA_ERROR_NOT_SUPPORTED) return status;
#endif /* PSA_NEED_ACME_AES_DRIVER */
        /* Add fallback driver call here */
        return PSA_ERROR_NOT_SUPPORTED;

    /* Add cases for opaque drivers here */
    // case ACME_OPAQUE_DRIVER_LOCATION:
    //     return acme_opaque_cipher_decrypt(
    //         attributes, key_buffer, key_buffer_size,
    //         alg,
    //         input, input_length,
    //         output, output_size, output_length);

    default:
        /* Key is declared with a lifetime not known to us */
        (void)key_buffer;
        (void)key_buffer_size;
        (void)alg;
        (void)input;
        (void)input_length;
        (void)output;
        (void)output_size;
        (void)output_length;
        (void)status;
        return PSA_ERROR_INVALID_ARGUMENT;
    }
}

psa_status_t psa_driver_wrapper_cipher_encrypt_setup(
    psa_cipher_operation_t *operation,
    const psa_key_attributes_t *attributes,
    const uint8_t *key_buffer, size_t key_buffer_size,
    psa_algorithm_t alg)
{
    psa_status_t status;

    switch (PSA_KEY_LIFETIME_GET_LOCATION(attributes->lifetime)) {
    case PSA_KEY_LOCATION_LOCAL_STORAGE:
        /* Add cases for transparent drivers here */
#ifdef PSA_NEED_ACME_AES_DRIVER
        status = acme_cipher_encrypt_setup(
            &operation->ctx.acme_cipher_ctx,
            attributes, key_buffer, key_buffer_size,
            alg);
        if (status == PSA_SUCCESS) operation->id = ACME_AES_DRIVER_ID;
        if (status != PSA_ERROR_NOT_SUPPORTED) return status;
#endif /* PSA_NEED_ACME_AES_DRIVER */
        /* Add fallback driver call here */
        return PSA_ERROR_NOT_SUPPORTED;

    /* Add cases for opaque drivers here */
    // case ACME_OPAQUE_DRIVER_LOCATION:
    //     status = acme_opaque_cipher_encrypt_setup(
    //         &operation->ctx.opaque_cipher_ctx,
    //         attributes, key_buffer, key_buffer_size,
    //         alg);
    //     if (status == PSA_SUCCESS) operation->id = ACME_OPAQUE_DRIVER_ID;
    //     return status;

    default:
        /* Key is declared with a lifetime not known to us */
        (void)status;
        (void)operation;
        (void)key_buffer;
        (void)key_buffer_size;
        (void)alg;
        return PSA_ERROR_INVALID_ARGUMENT;
    }
}

psa_status_t psa_driver_wrapper_cipher_decrypt_setup(
    psa_cipher_operation_t *operation,
    const psa_key_attributes_t *attributes,
    const uint8_t *key_buffer, size_t key_buffer_size,
    psa_algorithm_t alg)
{
    psa_status_t status;

    switch (PSA_KEY_LIFETIME_GET_LOCATION(attributes->lifetime)) {
    case PSA_KEY_LOCATION_LOCAL_STORAGE:
        /* Add cases for transparent drivers here */
#ifdef PSA_NEED_ACME_AES_DRIVER
        status = acme_cipher_decrypt_setup(
            &operation->ctx.acme_cipher_ctx,
            attributes, key_buffer, key_buffer_size,
            alg);
        if (status == PSA_SUCCESS) operation->id = ACME_AES_DRIVER_ID;
        if (status != PSA_ERROR_NOT_SUPPORTED) return status;
#endif /* PSA_NEED_ACME_AES_DRIVER */
        /* Add fallback driver call here */
        return PSA_ERROR_NOT_SUPPORTED;

    /* Add cases for opaque drivers here */
    // case ACME_OPAQUE_DRIVER_LOCATION:
    //     status = acme_opaque_cipher_decrypt_setup(
    //         &operation->ctx.opaque_cipher_ctx,
    //         attributes, key_buffer, key_buffer_size,
    //         alg);
    //     if (status == PSA_SUCCESS) operation->id = ACME_OPAQUE_DRIVER_ID;
    //     return status;

    default:
        /* Key is declared with a lifetime not known to us */
        (void)status;
        (void)operation;
        (void)key_buffer;
        (void)key_buffer_size;
        (void)alg;
        return PSA_ERROR_INVALID_ARGUMENT;
    }
}

psa_status_t psa_driver_wrapper_cipher_set_iv(
    psa_cipher_operation_t *operation,
    const uint8_t *iv, size_t iv_length)
{
    switch (operation->id) {
#ifdef PSA_NEED_ACME_AES_DRIVER
    case ACME_AES_DRIVER_ID:
        return acme_cipher_set_iv(
            &operation->ctx.acme_cipher_ctx,
            iv, iv_length);
#endif /* PSA_NEED_ACME_AES_DRIVER */

    // case ACME_OPAQUE_DRIVER_ID:
    //     return acme_opaque_cipher_set_iv(
    //         &operation->ctx.opaque_cipher_ctx,
    //         iv, iv_length);

    default:
        (void)iv;
        (void)iv_length;
        return PSA_ERROR_BAD_STATE;
    }
}

psa_status_t psa_driver_wrapper_cipher_update(
    psa_cipher_operation_t *operation,
    const uint8_t *input, size_t input_length,
    uint8_t *output, size_t output_size, size_t *output_length)
{
    switch (operation->id) {

#ifdef PSA_NEED_ACME_AES_DRIVER
    case ACME_AES_DRIVER_ID:
        return acme_cipher_update(
            &operation->ctx.acme_cipher_ctx,
            input, input_length,
            output, output_size, output_length);
#endif /* PSA_NEED_ACME_AES_DRIVER */

    // case ACME_OPAQUE_DRIVER_ID:
    //     return acme_opaque_cipher_update(
    //         &operation->ctx.opaque_cipher_ctx,
    //         input, input_length,
    //         output, output_size, output_length);

    default:
        (void)input;
        (void)input_length;
        (void)output;
        (void)output_size;
        (void)output_length;
        return PSA_ERROR_BAD_STATE;
    }
}

psa_status_t psa_driver_wrapper_cipher_finish(
    psa_cipher_operation_t *operation,
    uint8_t *output,
    size_t output_size,
    size_t *output_length)
{
    switch (operation->id) {

#ifdef PSA_NEED_ACME_AES_DRIVER
    case ACME_AES_DRIVER_ID:
        return acme_cipher_finish(
            &operation->ctx.acme_cipher_ctx,
            output, output_size, output_length);
#endif /* PSA_NEED_ACME_AES_DRIVER */

    // case ACME_OPAQUE_DRIVER_ID:
    //     return acme_opaque_cipher_finish(
    //         &operation->ctx.opaque_cipher_ctx,
    //         output, output_size, output_length);

    default:
        (void)output;
        (void)output_size;
        (void)output_length;
        return PSA_ERROR_BAD_STATE;
    }
}

psa_status_t psa_driver_wrapper_cipher_abort(
    psa_cipher_operation_t *operation)
{
    switch (operation->id) {

#ifdef PSA_NEED_ACME_AES_DRIVER
    case ACME_AES_DRIVER_ID:
        return acme_cipher_abort(&operation->ctx.acme_cipher_ctx);
#endif /* PSA_NEED_ACME_AES_DRIVER */

    // case ACME_OPAQUE_DRIVER_ID:
    //     return acme_opaque_cipher_abort(&operation->ctx.opaque_cipher_ctx);

    default:
        return PSA_SUCCESS;
    }
}

/*
 * Hashing functions
 */
psa_status_t psa_driver_wrapper_hash_compute(
    psa_algorithm_t alg,
    const uint8_t *input, size_t input_length,
    uint8_t *hash, size_t hash_size, size_t *hash_length)
{
    psa_status_t status;

    /* Add cases for transparent drivers here */
#ifdef PSA_NEED_ACME_SHA_DRIVER
    status = acme_hash_compute(
        alg, input, input_length, hash, hash_size, hash_length);
    if (status != PSA_ERROR_NOT_SUPPORTED) return status;
#endif /* PSA_NEED_ACME_SHA_DRIVER */
    /* Add fallback driver call here */

    (void)status;
    (void)alg;
    (void)input;
    (void)input_length;
    (void)hash;
    (void)hash_size;
    (void)hash_length;
    return PSA_ERROR_NOT_SUPPORTED;
}

psa_status_t psa_driver_wrapper_hash_setup(
    psa_hash_operation_t *operation,
    psa_algorithm_t alg)
{
    psa_status_t status;

    /* Add cases for transparent drivers here */
#ifdef PSA_NEED_ACME_SHA_DRIVER
    status = acme_hash_setup(
        &operation->ctx.acme_hash_ctx, alg);
    if (status == PSA_SUCCESS) operation->id = ACME_SHA_DRIVER_ID;
    if (status != PSA_ERROR_NOT_SUPPORTED) return status;
#endif /* PSA_NEED_ACME_SHA_DRIVER */
    /* Add fallback driver call here */

    (void)status;
    (void)operation;
    (void)alg;
    return PSA_ERROR_NOT_SUPPORTED;
}

psa_status_t psa_driver_wrapper_hash_clone(
    const psa_hash_operation_t *source_operation,
    psa_hash_operation_t *target_operation)
{
    switch (source_operation->id) {

#ifdef PSA_NEED_ACME_SHA_DRIVER
    case ACME_SHA_DRIVER_ID:
        target_operation->id = ACME_SHA_DRIVER_ID;
        return acme_hash_clone(
            &source_operation->ctx.acme_hash_ctx,
            &target_operation->ctx.acme_hash_ctx);
#endif /* PSA_NEED_ACME_SHA_DRIVER */

    default:
        (void)target_operation;
        return PSA_ERROR_BAD_STATE;
    }
}

psa_status_t psa_driver_wrapper_hash_update(
    psa_hash_operation_t *operation,
    const uint8_t *input, size_t input_length)
{
    switch (operation->id) {

#ifdef PSA_NEED_ACME_SHA_DRIVER
    case ACME_SHA_DRIVER_ID:
        return acme_hash_update(
            &operation->ctx.acme_hash_ctx,
            input, input_length);
#endif /* PSA_NEED_ACME_SHA_DRIVER */

    default:
        (void)input;
        (void)input_length;
        return PSA_ERROR_BAD_STATE;
    }
}

psa_status_t psa_driver_wrapper_hash_finish(
    psa_hash_operation_t *operation,
    uint8_t *hash,
    size_t hash_size,
    size_t *hash_length)
{
    switch (operation->id) {

#ifdef PSA_NEED_ACME_SHA_DRIVER
    case ACME_SHA_DRIVER_ID:
        return acme_hash_finish(
            &operation->ctx.acme_hash_ctx,
            hash, hash_size, hash_length);
#endif /* PSA_NEED_ACME_SHA_DRIVER */

    default:
        (void)hash;
        (void)hash_size;
        (void)hash_length;
        return PSA_ERROR_BAD_STATE;
    }
}

psa_status_t psa_driver_wrapper_hash_abort(
    psa_hash_operation_t *operation)
{
    switch (operation->id) {

#ifdef PSA_NEED_ACME_SHA_DRIVER
    case ACME_SHA_DRIVER_ID:
        return acme_hash_abort(&operation->ctx.acme_hash_ctx);
#endif /* PSA_NEED_ACME_SHA_DRIVER */

    default:
        return PSA_SUCCESS;
    }
}

/*
 * XOF functions
 */
psa_status_t psa_driver_wrapper_xof_setup(
    psa_xof_operation_t *operation,
    psa_algorithm_t alg)
{
    psa_status_t status;
    /* Add cases for transparent drivers here */

    // status = acme_xof_setup(
    //     &operation->ctx.acme_xof_ctx, alg);
    // if (status == PSA_SUCCESS) operation->id = ACME_DRIVER_ID;
    // return status;

    (void)status;
    (void)operation;
    (void)alg;
    return PSA_ERROR_NOT_SUPPORTED;
}

psa_status_t psa_driver_wrapper_xof_set_context(psa_xof_operation_t *operation,
    const uint8_t *context,
    size_t context_length)
{
    switch (operation->id) {
        
    // case ACME_DRIVER_ID:
    //     return acme_xof_set_context(
    //         &operation->ctx.acme_xof_ctx,
    //         context, context_length);

    default:
        (void)context;
        (void)context_length;
        return PSA_ERROR_BAD_STATE;
    }
}

psa_status_t psa_driver_wrapper_xof_update(
    psa_xof_operation_t *operation,
    const uint8_t *input, size_t input_length)
{
    switch (operation->id) {

    // case ACME_DRIVER_ID:
    //     return acme_xof_update(
    //         &operation->ctx.acme_xof_ctx,
    //         input, input_length);

    default:
        (void)input;
        (void)input_length;
        return PSA_ERROR_BAD_STATE;
    }
}

psa_status_t psa_driver_wrapper_xof_output(
    psa_xof_operation_t *operation,
    uint8_t *output,
    size_t output_length)
{
    switch (operation->id) {

    // case ACME_DRIVER_ID:
    //     return acme_xof_output(
    //         &operation->ctx.acme_xof_ctx,
    //         output, output_length);

    default:
        (void)output;
        (void)output_length;
        return PSA_ERROR_BAD_STATE;
    }
}

psa_status_t psa_driver_wrapper_xof_abort(
    psa_xof_operation_t *operation)
{
    switch (operation->id) {

    // case ACME_DRIVER_ID:
    // return acme_xof_abort(&operation->ctx.acme_xof_ctx);

    default:
        return PSA_SUCCESS;
    }
}

psa_status_t psa_driver_wrapper_aead_encrypt(
    const psa_key_attributes_t *attributes,
    const uint8_t *key_buffer, size_t key_buffer_size,
    psa_algorithm_t alg,
    const uint8_t *nonce, size_t nonce_length,
    const uint8_t *additional_data, size_t additional_data_length,
    const uint8_t *plaintext, size_t plaintext_length,
    uint8_t *ciphertext, size_t ciphertext_size, size_t *ciphertext_length)
{
    psa_status_t status;

    switch (PSA_KEY_LIFETIME_GET_LOCATION(attributes->lifetime)) {
    case PSA_KEY_LOCATION_LOCAL_STORAGE:
        /* Add cases for transparent drivers here */
        // return acme_aead_encrypt(
        //     attributes, key_buffer, key_buffer_size,
        //     alg,
        //     nonce, nonce_length,
        //     additional_data, additional_data_length,
        //     plaintext, plaintext_length,
        //     ciphertext, ciphertext_size, ciphertext_length);
        return PSA_ERROR_NOT_SUPPORTED;

    /* Add cases for opaque drivers here */

    default:
        /* Key is declared with a lifetime not known to us */
        (void)key_buffer;
        (void)key_buffer_size;
        (void)alg;
        (void)nonce;
        (void)nonce_length;
        (void)additional_data;
        (void)additional_data_length;
        (void)plaintext;
        (void)plaintext_length;
        (void)ciphertext;
        (void)ciphertext_size;
        (void)ciphertext_length;
        (void)status;
        return PSA_ERROR_INVALID_ARGUMENT;
    }
}

psa_status_t psa_driver_wrapper_aead_decrypt(
    const psa_key_attributes_t *attributes,
    const uint8_t *key_buffer, size_t key_buffer_size,
    psa_algorithm_t alg,
    const uint8_t *nonce, size_t nonce_length,
    const uint8_t *additional_data, size_t additional_data_length,
    const uint8_t *ciphertext, size_t ciphertext_length,
    uint8_t *plaintext, size_t plaintext_size, size_t *plaintext_length)
{
    psa_status_t status;

    switch (PSA_KEY_LIFETIME_GET_LOCATION(attributes->lifetime)) {
    case PSA_KEY_LOCATION_LOCAL_STORAGE:
        /* Add cases for transparent drivers here */
        // return acme_aead_decrypt(
        //     attributes, key_buffer, key_buffer_size,
        //     alg,
        //     nonce, nonce_length,
        //     additional_data, additional_data_length,
        //     ciphertext, ciphertext_length,
        //     plaintext, plaintext_size, plaintext_length);
        return PSA_ERROR_NOT_SUPPORTED;

    /* Add cases for opaque drivers here */

    default:
        /* Key is declared with a lifetime not known to us */
        (void)key_buffer;
        (void)key_buffer_size;
        (void)alg;
        (void)nonce;
        (void)nonce_length;
        (void)additional_data;
        (void)additional_data_length;
        (void)ciphertext;
        (void)ciphertext_length;
        (void)plaintext;
        (void)plaintext_size;
        (void)plaintext_length;
        (void)status;
        return PSA_ERROR_INVALID_ARGUMENT;
    }
}

psa_status_t psa_driver_wrapper_aead_encrypt_setup(
    psa_aead_operation_t *operation,
    const psa_key_attributes_t *attributes,
    const uint8_t *key_buffer, size_t key_buffer_size,
    psa_algorithm_t alg)
{
    psa_status_t status;

    switch (PSA_KEY_LIFETIME_GET_LOCATION(attributes->lifetime)) {
    case PSA_KEY_LOCATION_LOCAL_STORAGE:
        /* Add cases for transparent drivers here */
        // status = acme_aead_encrypt_setup(
        //     &operation->ctx.acme_aead_ctx,
        //     attributes, key_buffer, key_buffer_size,
        //     alg);
        // if (status == PSA_SUCCESS) operation->id = ACME_DRIVER_ID;
        // return status;
        return PSA_ERROR_NOT_SUPPORTED;

    /* Add cases for opaque drivers here */

    default:
        /* Key is declared with a lifetime not known to us */
        (void)status;
        (void)operation;
        (void)key_buffer;
        (void)key_buffer_size;
        (void)alg;
        return PSA_ERROR_NOT_SUPPORTED;
    }
}

psa_status_t psa_driver_wrapper_aead_decrypt_setup(
    psa_aead_operation_t *operation,
    const psa_key_attributes_t *attributes,
    const uint8_t *key_buffer, size_t key_buffer_size,
    psa_algorithm_t alg)
{
    psa_status_t status;

    switch (PSA_KEY_LIFETIME_GET_LOCATION(attributes->lifetime)) {
    case PSA_KEY_LOCATION_LOCAL_STORAGE:
        /* Add cases for transparent drivers here */
        // status = acme_aead_decrypt_setup(
        //     &operation->ctx.acme_aead_ctx,
        //     attributes, key_buffer, key_buffer_size,
        //     alg);
        // if (status == PSA_SUCCESS) operation->id = ACME_DRIVER_ID;
        // return status;
        return PSA_ERROR_NOT_SUPPORTED;

    /* Add cases for opaque drivers here */

    default:
        /* Key is declared with a lifetime not known to us */
        (void)status;
        (void)operation;
        (void)key_buffer;
        (void)key_buffer_size;
        (void)alg;
        return PSA_ERROR_NOT_SUPPORTED;
    }
}

psa_status_t psa_driver_wrapper_aead_set_nonce(
    psa_aead_operation_t *operation,
    const uint8_t *nonce, size_t nonce_length)
{
    switch (operation->id) {

    // case ACME_DRIVER_ID:
    //     return acme_aead_set_nonce(
    //         &operation->ctx.acme_aead_ctx,
    //         nonce, nonce_length);

    default:
        (void)nonce;
        (void)nonce_length;
        return PSA_ERROR_BAD_STATE;
    }
}

psa_status_t psa_driver_wrapper_aead_set_lengths(
    psa_aead_operation_t *operation,
    size_t ad_length,
    size_t plaintext_length)
{
    switch (operation->id) {

    // case ACME_DRIVER_ID:
    //     return acme_aead_set_lengths(
    //         &operation->ctx.acme_aead_ctx,
    //         ad_length, plaintext_length);

    default:
        (void)ad_length;
        (void)plaintext_length;
        return PSA_ERROR_BAD_STATE;
    }
}

psa_status_t psa_driver_wrapper_aead_update_ad(
    psa_aead_operation_t *operation,
    const uint8_t *input, size_t input_length)
{
    switch (operation->id) {

    // case ACME_DRIVER_ID:
    //     return acme_aead_update_ad(
    //         &operation->ctx.acme_aead_ctx,
    //         input, input_length);

    default:
        (void)input;
        (void)input_length;
        return PSA_ERROR_BAD_STATE;
    }
}

psa_status_t psa_driver_wrapper_aead_update(
    psa_aead_operation_t *operation,
    const uint8_t *input, size_t input_length,
    uint8_t *output, size_t output_size, size_t *output_length)
{
    switch (operation->id) {

    // case ACME_DRIVER_ID:
    //     return acme_aead_update(
    //         &operation->ctx.acme_aead_ctx,
    //         input, input_length,
    //         output, output_size, output_length);

    default:
        (void)input;
        (void)input_length;
        (void)output;
        (void)output_size;
        (void)output_length;
        return PSA_ERROR_BAD_STATE;
    }
}

psa_status_t psa_driver_wrapper_aead_finish(
    psa_aead_operation_t *operation,
    uint8_t *ciphertext, size_t ciphertext_size, size_t *ciphertext_length,
    uint8_t *tag, size_t tag_size, size_t *tag_length)
{
    switch (operation->id) {

    // case ACME_DRIVER_ID:
    //     return acme_aead_finish(
    //         &operation->ctx.acme_aead_ctx,
    //         ciphertext, ciphertext_size, ciphertext_length,
    //         tag, tag_size, tag_length);

    default:
        (void)ciphertext;
        (void)ciphertext_size;
        (void)ciphertext_length;
        (void)tag;
        (void)tag_size;
        (void)tag_length;
        return PSA_ERROR_BAD_STATE;
    }
}

psa_status_t psa_driver_wrapper_aead_verify(
    psa_aead_operation_t *operation,
    uint8_t *plaintext, size_t plaintext_size, size_t *plaintext_length,
    const uint8_t *tag, size_t tag_length)
{
    switch (operation->id) {

    // case ACME_DRIVER_ID:
    //     return acme_aead_verify(
    //         &operation->ctx.acme_aead_ctx,
    //         plaintext, plaintext_size, plaintext_length,
    //         tag, tag_length);

    default:
        (void)plaintext;
        (void)plaintext_size;
        (void)plaintext_length;
        (void)tag;
        (void)tag_length;
        return PSA_ERROR_BAD_STATE;
    }
}

psa_status_t psa_driver_wrapper_aead_abort(
    psa_aead_operation_t *operation)
{
    switch (operation->id) {

    // case ACME_DRIVER_ID:
    //     return acme_aead_abort(&operation->ctx.acme_aead_ctx);

    default:
        return PSA_SUCCESS;
    }
}

/*
 * Asymmetric functions
 */
psa_status_t psa_driver_wrapper_asymmetric_encrypt(
    const psa_key_attributes_t *attributes,
    const uint8_t *key_buffer, size_t key_buffer_size,
    psa_algorithm_t alg,
    const uint8_t *input, size_t input_length,
    const uint8_t *salt, size_t salt_length,
    uint8_t *output, size_t output_size, size_t *output_length)
{
    switch (PSA_KEY_LIFETIME_GET_LOCATION(attributes->lifetime)) {
    case PSA_KEY_LOCATION_LOCAL_STORAGE:
        /* Add cases for transparent drivers here */
        // return acme_asymmetric_encrypt(
        //     attributes, key_buffer, key_buffer_size,
        //     alg,
        //     input, input_length,
        //     salt, salt_length,
        //     output, output_size, output_length);
        return PSA_ERROR_NOT_SUPPORTED;

    /* Add cases for opaque drivers here */

    default:
        /* Key is declared with a lifetime not known to us */
        (void)key_buffer;
        (void)key_buffer_size;
        (void)alg;
        (void)input;
        (void)input_length;
        (void)salt;
        (void)salt_length;
        (void)output;
        (void)output_size;
        (void)output_length;
        return PSA_ERROR_INVALID_ARGUMENT;
    }
}

psa_status_t psa_driver_wrapper_asymmetric_decrypt(
    const psa_key_attributes_t *attributes,
    const uint8_t *key_buffer, size_t key_buffer_size,
    psa_algorithm_t alg,
    const uint8_t *input, size_t input_length,
    const uint8_t *salt, size_t salt_length,
    uint8_t *output, size_t output_size, size_t *output_length)
{
    switch (PSA_KEY_LIFETIME_GET_LOCATION(attributes->lifetime)) {
    case PSA_KEY_LOCATION_LOCAL_STORAGE:
        /* Add cases for transparent drivers here */
        // return acme_asymmetric_decrypt(
        //     attributes, key_buffer, key_buffer_size,
        //     alg,
        //     input, input_length,
        //     salt, salt_length,
        //     output, output_size, output_length);
        return PSA_ERROR_NOT_SUPPORTED;

    /* Add cases for opaque drivers here */

    default:
        /* Key is declared with a lifetime not known to us */
        (void)key_buffer;
        (void)key_buffer_size;
        (void)alg;
        (void)input;
        (void)input_length;
        (void)salt;
        (void)salt_length;
        (void)output;
        (void)output_size;
        (void)output_length;
        return PSA_ERROR_INVALID_ARGUMENT;
    }
}

/*
 * MAC functions
 */
psa_status_t psa_driver_wrapper_mac_compute(
    const psa_key_attributes_t *attributes,
    const uint8_t *key_buffer, size_t key_buffer_size,
    psa_algorithm_t alg,
    const uint8_t *input, size_t input_length,
    uint8_t *mac, size_t mac_size, size_t *mac_length)
{
    psa_status_t status;

    switch (PSA_KEY_LIFETIME_GET_LOCATION(attributes->lifetime)) {
    case PSA_KEY_LOCATION_LOCAL_STORAGE:
        /* Add cases for transparent drivers here */
#ifdef PSA_NEED_ACME_MAC_DRIVER
        status = acme_mac_compute(
            attributes, key_buffer, key_buffer_size,
            alg,
            input, input_length,
            mac, mac_size, mac_length);
        if (status != PSA_ERROR_NOT_SUPPORTED) return status;
#endif /* PSA_NEED_ACME_MAC_DRIVER */
        /* Add fallback driver call here */
        return PSA_ERROR_NOT_SUPPORTED;

    /* Add cases for opaque drivers here */

    default:
        /* Key is declared with a lifetime not known to us */
        (void)key_buffer;
        (void)key_buffer_size;
        (void)alg;
        (void)input;
        (void)input_length;
        (void)mac;
        (void)mac_size;
        (void)mac_length;
        (void)status;
        return PSA_ERROR_INVALID_ARGUMENT;
    }
}

psa_status_t psa_driver_wrapper_mac_sign_setup(
    psa_mac_operation_t *operation,
    const psa_key_attributes_t *attributes,
    const uint8_t *key_buffer, size_t key_buffer_size,
    psa_algorithm_t alg)
{
    psa_status_t status;

    switch (PSA_KEY_LIFETIME_GET_LOCATION(attributes->lifetime)) {
    case PSA_KEY_LOCATION_LOCAL_STORAGE:
        /* Add cases for transparent drivers here */
#ifdef PSA_NEED_ACME_MAC_DRIVER
        status = acme_mac_sign_setup(
            &operation->ctx.acme_mac_ctx,
            attributes, key_buffer, key_buffer_size,
            alg);
        if (status == PSA_SUCCESS) operation->id = ACME_MAC_DRIVER_ID;
        if (status != PSA_ERROR_NOT_SUPPORTED) return status;
#endif /* PSA_NEED_ACME_MAC_DRIVER */
        /* Add fallback driver call here */
        return PSA_ERROR_NOT_SUPPORTED;

    /* Add cases for opaque drivers here */

    default:
        /* Key is declared with a lifetime not known to us */
        (void)status;
        (void)operation;
        (void)key_buffer;
        (void)key_buffer_size;
        (void)alg;
        return PSA_ERROR_INVALID_ARGUMENT;
    }
}

psa_status_t psa_driver_wrapper_mac_verify_setup(
    psa_mac_operation_t *operation,
    const psa_key_attributes_t *attributes,
    const uint8_t *key_buffer, size_t key_buffer_size,
    psa_algorithm_t alg)
{
    psa_status_t status;

    switch (PSA_KEY_LIFETIME_GET_LOCATION(attributes->lifetime)) {
    case PSA_KEY_LOCATION_LOCAL_STORAGE:
        /* Add cases for transparent drivers here */
#ifdef PSA_NEED_ACME_MAC_DRIVER
        status = acme_mac_verify_setup(
            &operation->ctx.acme_mac_ctx,
            attributes, key_buffer, key_buffer_size,
            alg);
        if (status == PSA_SUCCESS) operation->id = ACME_MAC_DRIVER_ID;
        if (status != PSA_ERROR_NOT_SUPPORTED) return status;
#endif /* PSA_NEED_ACME_MAC_DRIVER */
        /* Add fallback driver call here */
        return PSA_ERROR_NOT_SUPPORTED;

    /* Add cases for opaque drivers here */

    default:
        /* Key is declared with a lifetime not known to us */
        (void)status;
        (void)operation;
        (void)key_buffer;
        (void)key_buffer_size;
        (void)alg;
        return PSA_ERROR_INVALID_ARGUMENT;
    }
}

psa_status_t psa_driver_wrapper_mac_update(
    psa_mac_operation_t *operation,
    const uint8_t *input, size_t input_length)
{
    switch (operation->id) {
#ifdef PSA_NEED_ACME_MAC_DRIVER
    case ACME_MAC_DRIVER_ID:
        return acme_mac_update(
            &operation->ctx.acme_mac_ctx,
            input, input_length);
#endif /* PSA_NEED_ACME_MAC_DRIVER */

    default:
        (void)input;
        (void)input_length;
        return PSA_ERROR_BAD_STATE;
    }
}

psa_status_t psa_driver_wrapper_mac_sign_finish(
    psa_mac_operation_t *operation,
    uint8_t *mac, size_t mac_size, size_t *mac_length)
{
    switch (operation->id) {
#ifdef PSA_NEED_ACME_MAC_DRIVER
    case ACME_MAC_DRIVER_ID:
        return acme_mac_sign_finish(
            &operation->ctx.acme_mac_ctx,
            mac, mac_size, mac_length);
#endif /* PSA_NEED_ACME_MAC_DRIVER */

    default:
        (void)mac;
        (void)mac_size;
        (void)mac_length;
        return PSA_ERROR_BAD_STATE;
    }
}

psa_status_t psa_driver_wrapper_mac_verify_finish(
    psa_mac_operation_t *operation,
    const uint8_t *mac, size_t mac_length)
{
    switch (operation->id) {
#ifdef PSA_NEED_ACME_MAC_DRIVER
    case ACME_MAC_DRIVER_ID:
        return acme_mac_verify_finish(
            &operation->ctx.acme_mac_ctx,
            mac, mac_length);
#endif /* PSA_NEED_ACME_MAC_DRIVER */

    default:
        (void)mac;
        (void)mac_length;
        return PSA_ERROR_BAD_STATE;
    }
}

psa_status_t psa_driver_wrapper_mac_abort(
    psa_mac_operation_t *operation)
{
    switch (operation->id) {
#ifdef PSA_NEED_ACME_MAC_DRIVER
    case ACME_MAC_DRIVER_ID:
        return acme_mac_abort(&operation->ctx.acme_mac_ctx);
#endif /* PSA_NEED_ACME_MAC_DRIVER */

    default:
        return PSA_SUCCESS;
    }
}

/*
 * Key derivation functions
 */
psa_status_t psa_driver_wrapper_key_derivation_setup(
    psa_key_derivation_operation_t *operation,
    const psa_key_attributes_t *attributes,
    psa_algorithm_t alg)
{
    psa_status_t status;

    switch (PSA_KEY_LIFETIME_GET_LOCATION(attributes->lifetime)) {
    case PSA_KEY_LOCATION_LOCAL_STORAGE:
        /* Add cases for transparent drivers here */
#ifdef PSA_NEED_ACME_KDF_DRIVER
        status = acme_key_derivation_setup(
            &operation->ctx.acme_kdf_ctx,
            attributes, alg);
        if (status == PSA_SUCCESS) operation->id = ACME_KDF_DRIVER_ID;
        return status;
#endif /* PSA_NEED_ACME_KDF_DRIVER */
        return PSA_ERROR_NOT_SUPPORTED;

    /* Add cases for opaque drivers here */
    // case ACME_OPAQUE_DRIVER_LOCATION:
    //     status = acme_opaque_key_derivation_setup(
    //         &operation->ctx.opaque_kdf_ctx,
    //         attributes,
    //         alg);
    //     if (status == PSA_SUCCESS) operation->id = ACME_OPAQUE_DRIVER_ID;
    //     return status;

    default:
        /* Key is declared with a lifetime not known to us */
        (void)status;
        (void)operation;
        (void)alg;
        return PSA_ERROR_NOT_SUPPORTED;
    }
}

psa_status_t psa_driver_wrapper_key_derivation_set_capacity(
    psa_key_derivation_operation_t *operation,
    size_t capacity)
{
    switch (operation->id) {
    // case ACME_DRIVER_ID:
    //     return acme_key_derivation_set_capacity(
    //         &operation->ctx.acme_kdf_ctx,
    //         capacity);

    // case ACME_OPAQUE_DRIVER_ID:
    //     return acme_opaque_key_derivation_set_capacity(
    //         &operation->ctx.opaque_kdf_ctx,
    //         capacity);

    default:
        (void)capacity;
        return PSA_SUCCESS;
    }
}

psa_status_t psa_driver_wrapper_key_derivation_input_bytes(
    psa_key_derivation_operation_t *operation,
    psa_key_derivation_step_t step,
    const uint8_t *data, size_t data_length)
{
    switch (operation->id) {
#ifdef PSA_NEED_ACME_KDF_DRIVER
    case ACME_KDF_DRIVER_ID:
        return acme_key_derivation_input_bytes(
            &operation->ctx.acme_kdf_ctx,
            step,
            data, data_length);
#endif /* PSA_NEED_ACME_KDF_DRIVER */

    // case ACME_OPAQUE_DRIVER_ID:
    //     return acme_opaque_key_derivation_input_bytes(
    //        &operation->ctx.opaque_kdf_ctx,
    //        step,
    //        data, data_length);

    default:
        (void)step;
        (void)data;
        (void)data_length;
        return PSA_ERROR_BAD_STATE;
    }
}

psa_status_t psa_driver_wrapper_key_derivation_input_key(
    psa_key_derivation_operation_t *operation,
    psa_key_derivation_step_t step,
    const psa_key_attributes_t *attributes,
    const uint8_t *key, size_t key_length)
{
    switch (operation->id) {
#ifdef PSA_NEED_ACME_KDF_DRIVER
    case ACME_KDF_DRIVER_ID:
        if (PSA_KEY_LIFETIME_GET_LOCATION(attributes->lifetime) != PSA_KEY_LOCATION_LOCAL_STORAGE) break;
        return acme_key_derivation_input_bytes(
            &operation->ctx.acme_kdf_ctx,
            step,
            key, key_length);
#endif /* PSA_NEED_ACME_KDF_DRIVER */

    // case ACME_OPAQUE_DRIVER_ID:
    //     switch (PSA_KEY_LIFETIME_GET_LOCATION(attributes->lifetime)) {
    //     case PSA_KEY_LOCATION_LOCAL_STORAGE:
    //         return acme_opaque_key_derivation_input_bytes(
    //             &operation->ctx.opaque_kdf_ctx,
    //             step,
    //             key, key_length);
    //     case ACME_OPAQUE_DRIVER_LOCATION:
    //         return acme_opaque_key_derivation_input_key(
    //             &operation->ctx.opaque_kdf_ctx,
    //             step,
    //             attributes,
    //             key, key_length);
    //     default:
    //         break; // key is in a different opaque driver
    //     }
    //     break;

    default:
        (void)step;
        (void)attributes;
        (void)key;
        (void)key_length;
        return PSA_ERROR_BAD_STATE;
    }

    /* Try export(); input_bytes() if key is at a different location */
    // return psa_derivation_input_copy_builtin(
    //     operation, step, attributes, key, key_length);
    return PSA_ERROR_NOT_SUPPORTED;
}

psa_status_t psa_driver_wrapper_key_derivation_input_integer(
    psa_key_derivation_operation_t *operation,
    psa_key_derivation_step_t step,
    uint64_t value)
{
    switch (operation->id) {
    // case ACME_DRIVER_ID:
    //     return acme_key_derivation_input_integer(
    //         &operation->ctx.acme_kdf_ctx,
    //         step,
    //         value);

    // case ACME_OPAQUE_DRIVER_ID:
    //     return acme_opaque_key_derivation_input_integer(
    //         &operation->ctx.opaque_kdf_ctx,
    //         step,
    //         value);

    default:
        (void)step;
        (void)value;
        return PSA_ERROR_BAD_STATE;
    }
}

psa_status_t psa_driver_wrapper_key_derivation_output_bytes(
    psa_key_derivation_operation_t *operation,
    uint8_t *output, size_t output_length)
{
    switch (operation->id) {
#ifdef PSA_NEED_ACME_KDF_DRIVER
    case ACME_KDF_DRIVER_ID:
        return acme_key_derivation_output_bytes(
            &operation->ctx.acme_kdf_ctx,
            output, output_length);
#endif /* PSA_NEED_ACME_KDF_DRIVER */

    // case ACME_OPAQUE_DRIVER_ID:
    //    return acme_opaque_key_derivation_output_bytes(
    //        &operation->ctx.opaque_kdf_ctx,
    //        output, output_length);

    default:
        (void)output;
        (void)output_length;
        return PSA_ERROR_BAD_STATE;
    }
}

psa_status_t psa_driver_wrapper_key_derivation_output_key(
    psa_key_derivation_operation_t *operation,
    const psa_key_attributes_t *key_attributes,
    uint8_t *key, size_t key_size, size_t *key_length)
{
    switch (operation->id) {

    // case ACME_OPAQUE_DRIVER_ID:
    //     if (PSA_KEY_LIFETIME_GET_LOCATION(key_attributes->lifetime) != ACME_OPAQUE_DRIVER_LOCATION) {
    //         return PSA_ERROR_NOT_SUPPORTED;
    //     }
    //     return acme_opaque_key_derivation_output_key(
    //         &operation->ctx.opaque_kdf_ctx,
    //         key_attributes,
    //         key, key_size, key_length);

    default:
        (void)key_attributes;
        (void)key;
        (void)key_size;
        (void)key_length;
        return PSA_ERROR_BAD_STATE;
    }
}

psa_status_t psa_driver_wrapper_key_derivation_verify_key(
    psa_key_derivation_operation_t *operation,
    const psa_key_attributes_t *key_attributes,
    const uint8_t *key, size_t key_length)
{
    switch (operation->id) {

    // case ACME_OPAQUE_DRIVER_ID:
    //     if (PSA_KEY_LIFETIME_GET_LOCATION(key_attributes->lifetime) != ACME_OPAQUE_DRIVER_LOCATION) {
    //         return PSA_ERROR_NOT_SUPPORTED;
    //     }
    //     return acme_opaque_key_derivation_verify_key(
    //         &operation->ctx.opaque_kdf_ctx,
    //         key_attributes,
    //         key, key_length);

    default:
        (void)key_attributes;
        (void)key;
        (void)key_length;
        return PSA_ERROR_BAD_STATE;
    }
}

psa_status_t psa_driver_wrapper_key_derivation_abort(
    psa_key_derivation_operation_t *operation)
{
    switch (operation->id) {
#ifdef PSA_NEED_ACME_KDF_DRIVER
    case ACME_KDF_DRIVER_ID:
        return acme_key_derivation_abort(&operation->ctx.acme_kdf_ctx);
#endif /* PSA_NEED_ACME_KDF_DRIVER */

    // case ACME_OPAQUE_DRIVER_ID:
    //     return acme_opaque_key_derivation_abort(&operation->ctx.opaque_kdf_ctx);

    default:
        return PSA_SUCCESS;
    }
}

/*
 * Key agreement functions
 */
psa_status_t psa_driver_wrapper_key_agreement(
    const psa_key_attributes_t *attributes,
    const uint8_t *key, size_t key_length,
    psa_algorithm_t alg,
    const uint8_t *peer_key, size_t peer_key_length,
    uint8_t *output, size_t output_size, size_t *output_length)
{
    switch (PSA_KEY_LIFETIME_GET_LOCATION(attributes->lifetime)) {
    case PSA_KEY_LOCATION_LOCAL_STORAGE:
        /* Add cases for transparent drivers here */
        // return acme_key_agreement(
        //     attributes, key, key_length,
        //     alg,
        //     peer_key, peer_key_length,
        //     output, output_size, output_length);
        return PSA_ERROR_NOT_SUPPORTED;

    /* Add cases for opaque drivers here */
    // case ACME_OPAQUE_DRIVER_LOCATION:
    //     return acme_opaque_key_agreement(
    //         attributes, key, key_length,
    //         alg,
    //         peer_key, peer_key_length,
    //         output, output_size, output_length);
    default:
        /* Key is declared with a lifetime not known to us */
        (void)alg;
        (void)key;
        (void)key_length;
        (void)peer_key;
        (void)peer_key_length;
        (void)output;
        (void)output_size;
        (void)output_length;
        return PSA_ERROR_INVALID_ARGUMENT;
    }
}

psa_status_t psa_driver_wrapper_key_agreement_to_key(
    const psa_key_attributes_t *attributes,
    const uint8_t *key, size_t key_length,
    psa_algorithm_t alg,
    const uint8_t *peer_key, size_t peer_key_length,
    const psa_key_attributes_t *output_attributes,
    uint8_t *output, size_t output_size, size_t *output_length)
{
    switch (PSA_KEY_LIFETIME_GET_LOCATION(attributes->lifetime)) {
    case PSA_KEY_LOCATION_LOCAL_STORAGE:
        /* Add cases for transparent drivers here */
        // if (PSA_KEY_LIFETIME_GET_LOCATION(output_attributes->lifetime) != PSA_KEY_LOCATION_LOCAL_STORAGE) {
        //     return PSA_ERROR_NOT_SUPPORTED;
        // }
        // return acme_key_agreement(
        //     attributes, key, key_length,
        //     alg,
        //     peer_key, peer_key_length,
        //     output, output_size, output_length);
        return PSA_ERROR_NOT_SUPPORTED;

    /* Add cases for opaque drivers here */
    // case ACME_OPAQUE_DRIVER_LOCATION:
    //     return acme_opaque_key_agreement_to_key(
    //         attributes, key, key_length,
    //         alg,
    //         peer_key, peer_key_length,
    //         output_attributes,
    //         output, output_size, output_length);

    default:
        /* Key is declared with a lifetime not known to us */
        (void)alg;
        (void)key;
        (void)key_length;
        (void)peer_key;
        (void)peer_key_length;
        (void)output_attributes;
        (void)output;
        (void)output_size;
        (void)output_length;
        return PSA_ERROR_INVALID_ARGUMENT;
    }
}

/*
 * Key encapsulation functions.
 */
psa_status_t psa_driver_wrapper_encapsulate(
    const psa_key_attributes_t *attributes,
    const uint8_t *key, size_t key_length,
    psa_algorithm_t alg,
    const psa_key_attributes_t *output_attributes,
    uint8_t *output_key, size_t output_key_size, size_t *output_key_length,
    uint8_t *ciphertext, size_t ciphertext_size, size_t *ciphertext_length)
{
    switch (PSA_KEY_LIFETIME_GET_LOCATION(attributes->lifetime)) {
    case PSA_KEY_LOCATION_LOCAL_STORAGE:
        /* Add cases for transparent drivers here */
        // if (PSA_KEY_LIFETIME_GET_LOCATION(output_attributes->lifetime) != PSA_KEY_LOCATION_LOCAL_STORAGE) {
        //     return PSA_ERROR_NOT_SUPPORTED;
        // }
        // return acme_encapsulate(
        //     attributes, key, key_length,
        //     alg, output_attributes,
        //     output_key, output_key_size, output_key_length,
        //     ciphertext, ciphertext_size, ciphertext_length);
        return PSA_ERROR_NOT_SUPPORTED;

    /* Add cases for opaque drivers here */

    default:
        /* Key is declared with a lifetime not known to us */
        (void)key;
        (void)key_length;
        (void)alg;
        (void)output_attributes;
        (void)output_key;
        (void)output_key_size;
        (void)output_key_length;
        (void)ciphertext;
        (void)ciphertext_size;
        (void)ciphertext_length;
        return PSA_ERROR_INVALID_ARGUMENT;
    }
}

psa_status_t psa_driver_wrapper_decapsulate(
    const psa_key_attributes_t *attributes,
    const uint8_t *key, size_t key_length,
    psa_algorithm_t alg,
    const uint8_t *ciphertext, size_t ciphertext_length,
    const psa_key_attributes_t *output_attributes,
    uint8_t *output_key, size_t output_key_size, size_t *output_key_length)
{
    switch (PSA_KEY_LIFETIME_GET_LOCATION(attributes->lifetime)) {
    case PSA_KEY_LOCATION_LOCAL_STORAGE:
        /* Add cases for transparent drivers here */
        // if (PSA_KEY_LIFETIME_GET_LOCATION(output_attributes->lifetime) != PSA_KEY_LOCATION_LOCAL_STORAGE) {
        //     return PSA_ERROR_NOT_SUPPORTED;
        // }
        // return acme_decapsulate(
        //     attributes, key, key_length,
        //     alg, ciphertext, ciphertext_length,
        //     output_attributes,
        //     output_key, output_key_size, output_key_length);
        return PSA_ERROR_NOT_SUPPORTED;

    /* Add cases for opaque drivers here */

    default:
        /* Key is declared with a lifetime not known to us */
        (void)key;
        (void)key_length;
        (void)alg;
        (void)ciphertext;
        (void)ciphertext_length;
        (void)output_attributes;
        (void)output_key;
        (void)output_key_size;
        (void)output_key_length;
        return PSA_ERROR_INVALID_ARGUMENT;
    }
}

/*
 * PAKE functions
 */
psa_status_t psa_driver_wrapper_pake_setup(
    psa_pake_operation_t *operation,
    const psa_key_attributes_t *attributes,
    const uint8_t *password, size_t password_length,
    const psa_pake_cipher_suite_t *cipher_suite)
{
    psa_status_t status;

    switch (PSA_KEY_LIFETIME_GET_LOCATION(attributes->lifetime)) {
    case PSA_KEY_LOCATION_LOCAL_STORAGE:
        /* Add cases for transparent drivers here */
        // status = acme_pake_setup(
        //     &operation->ctx.acme_pake_ctx,
        //     attributes, password, password_length,
        //     cipher_suite);
        // if (status == PSA_SUCCESS) operation->id = ACME_DRIVER_ID;
        // return status;
        return PSA_ERROR_NOT_SUPPORTED;

    /* Add cases for opaque drivers here */

    default:
        (void)status;
        (void)operation;
        (void)password;
        (void)password_length;
        (void)cipher_suite;
        return PSA_ERROR_INVALID_ARGUMENT;
    }
}

psa_status_t psa_driver_wrapper_pake_set_role(
    psa_pake_operation_t *operation,
    psa_pake_role_t role)
{
    switch (operation->id) {
    // case ACME_DRIVER_ID:
    //     return acme_pake_set_role(
    //         &operation->ctx.acme_pake_ctx,
    //         role);

    default:
        (void)role;
        return PSA_ERROR_BAD_STATE;
    }
}

psa_status_t psa_driver_wrapper_pake_set_user(
    psa_pake_operation_t *operation,
    const uint8_t *user_id, size_t user_id_length)
{
    switch (operation->id) {
    // case ACME_DRIVER_ID:
    //     return acme_pake_set_user(
    //         &operation->ctx.acme_pake_ctx,
    //         user_id, user_id_length);

    default:
        (void)user_id;
        (void)user_id_length;
        return PSA_ERROR_BAD_STATE;
    }
}

psa_status_t psa_driver_wrapper_pake_set_peer(
    psa_pake_operation_t *operation,
    const uint8_t *peer_id, size_t peer_id_length)
{
    switch (operation->id) {
    // case ACME_DRIVER_ID:
    //     return acme_pake_set_peer(
    //         &operation->ctx.acme_pake_ctx,
    //         peer_id, peer_id_length);

    default:
        (void)peer_id;
        (void)peer_id_length;
        return PSA_ERROR_BAD_STATE;
    }
}

psa_status_t psa_driver_wrapper_pake_set_context(
    psa_pake_operation_t *operation,
    const uint8_t *context, size_t context_length)
{
    switch (operation->id) {
    // case ACME_DRIVER_ID:
    //     return acme_pake_set_context(
    //         &operation->ctx.acme_pake_ctx,
    //         context, context_length);

    default:
        (void)context;
        (void)context_length;
        return PSA_ERROR_BAD_STATE;
    }
}

psa_status_t psa_driver_wrapper_pake_output(
    psa_pake_operation_t *operation,
    psa_pake_step_t step,
    uint8_t *output, size_t output_size, size_t *output_length)
{
    switch (operation->id) {
    // case ACME_DRIVER_ID:
    //     return acme_pake_output(
    //         &operation->ctx.acme_pake_ctx,
    //         step,
    //         output, output_size, output_length);

    default:
        (void)step;
        (void)output;
        (void)output_size;
        (void)output_length;
        return PSA_ERROR_BAD_STATE;
    }
}

psa_status_t psa_driver_wrapper_pake_input(
    psa_pake_operation_t *operation,
    psa_pake_step_t step,
    const uint8_t *input, size_t input_length)
{
    switch (operation->id) {
    // case ACME_DRIVER_ID:
    //     return acme_pake_input(
    //         &operation->ctx.acme_pake_ctx,
    //         step,
    //         input, input_length);

    default:
        (void)step;
        (void)input;
        (void)input_length;
        return PSA_ERROR_BAD_STATE;
    }
}

psa_status_t psa_driver_wrapper_pake_get_shared_key(
    psa_pake_operation_t *operation,
    const psa_key_attributes_t *attributes,
    uint8_t *key_buffer, size_t key_buffer_size, size_t *key_buffer_length)
{
    switch (operation->id) {
    // case ACME_DRIVER_ID:
    //     return acme_pake_get_shared_key(
    //         &operation->ctx.acme_pake_ctx,
    //         attributes,
    //         key_buffer, key_buffer_size, key_buffer_length);

    default:
        (void)attributes;
        (void)key_buffer;
        (void)key_buffer_size;
        (void)key_buffer_length;
        return PSA_ERROR_BAD_STATE;
    }
}

psa_status_t psa_driver_wrapper_pake_abort(
    psa_pake_operation_t *operation)
{
    switch (operation->id) {
    // case ACME_DRIVER_ID:
    //     return acme_pake_abort(&operation->ctx.acme_pake_ctx);

    default:
        return PSA_SUCCESS;
    }
}

/*
 * Key wrapping functions.
 */
psa_status_t psa_driver_wrapper_wrap_key(
    const psa_key_attributes_t *wrapping_key_attributes,
    const uint8_t *wrapping_key_data, size_t wrapping_key_size,
    psa_algorithm_t alg,
    const psa_key_attributes_t *key_attributes,
    const uint8_t *key_data, size_t key_size,
    uint8_t *data, size_t data_size, size_t *data_length)
{
    switch (PSA_KEY_LIFETIME_GET_LOCATION(wrapping_key_attributes->lifetime)) {
    case PSA_KEY_LOCATION_LOCAL_STORAGE:
        /* Add cases for transparent drivers here */
        // return acme_wrap_key(
        //     wrapping_key_attributes, wrapping_key_data, wrapping_key_size,
        //     alg,
        //     key_attributes, key_data, key_size,
        //     data, data_size, data_length);
        return PSA_ERROR_NOT_SUPPORTED;

    /* Add cases for opaque drivers here */

    default:
        /* Key is declared with a lifetime not known to us */
        (void)key_attributes;
        (void)key_data;
        (void)key_size;
        (void)wrapping_key_data;
        (void)wrapping_key_size;
        (void)alg;
        (void)data;
        (void)data_size;
        (void)data_length;
        return PSA_ERROR_INVALID_ARGUMENT;
    }
}

psa_status_t psa_driver_wrapper_unwrap_key(
    const psa_key_attributes_t *attributes,
    const psa_key_attributes_t *wrapping_key_attributes,
    const uint8_t *wrapping_key_data, size_t wrapping_key_size,
    psa_algorithm_t alg,
    const uint8_t *data, size_t data_length,
    uint8_t *key, size_t key_size, size_t *key_length, size_t *bits)
{
    switch (PSA_KEY_LIFETIME_GET_LOCATION(wrapping_key_attributes->lifetime)) {
    case PSA_KEY_LOCATION_LOCAL_STORAGE:
        /* Add cases for transparent drivers here */
        // return acme_unwrap_key(
        //     attributes,
        //     wrapping_key_attributes, wrapping_key_data, wrapping_key_size,
        //     alg,
        //     data, data_length,
        //     key, key_size, key_length, bits);
        return PSA_ERROR_NOT_SUPPORTED;

    /* Add cases for opaque drivers here */

    default:
        /* Key is declared with a lifetime not known to us */
        (void)attributes;
        (void)key_size;
        (void)wrapping_key_data;
        (void)wrapping_key_size;
        (void)alg;
        (void)data;
        (void)data_length;
        (void)key;
        (void)key_size;
        (void)key_length;
        (void)bits;
        return PSA_ERROR_INVALID_ARGUMENT;
    }
}

/*
 * Random
 */
psa_status_t psa_driver_wrapper_get_entropy(
    uint32_t flags,
    size_t *estimate_bits,
    uint8_t *output,
    size_t output_size)
{
    // status = acme_get_entropy(
    //     flags,
    //     estimate_bits, 
    //     output, output_size);
    // if (status == PSA_SUCCESS) operation->id = ACME_DRIVER_ID;
    // return status;

    /* get_entropy not supported */
    (void)flags;
    (void)output;
    (void)output_size;
    *estimate_bits = 0;
    return PSA_ERROR_INSUFFICIENT_ENTROPY;
}

psa_status_t psa_driver_wrapper_init_random(
    psa_driver_random_context_t *context)
{
#ifdef PSA_NEED_ACME_RNG_DRIVER
    return acme_rng_init(&context->acme_rng_ctx);
#endif /* PSA_NEED_ACME_RNG_DRIVER */

    (void)context;
    return PSA_SUCCESS;
}

psa_status_t psa_driver_wrapper_get_random(
    psa_driver_random_context_t *context,
    uint8_t *output, size_t output_size)
{
#ifdef PSA_NEED_ACME_RNG_DRIVER
    return acme_rng_get_random(&context->acme_rng_ctx, output, output_size);
#endif /* PSA_NEED_ACME_RNG_DRIVER */

    (void)context;
    (void)output;
    (void)output_size;
    return PSA_ERROR_NOT_SUPPORTED;
}

psa_status_t psa_driver_wrapper_random_reseed(
    psa_driver_random_context_t *context,
    const uint8_t *perso, size_t perso_size)
{
    // return acme_drbg_random_reseed(&context->acme_drbg_ctx, perso, perso_size);

    (void)context;
    (void)perso;
    (void)perso_size;
    return PSA_ERROR_NOT_SUPPORTED;
}

psa_status_t psa_driver_wrapper_random_deplete(
    psa_driver_random_context_t *context)
{
    // return acme_drbg_random_deplete(&context->acme_drbg_ctx);

    (void)context;
    return PSA_ERROR_NOT_SUPPORTED;
}

psa_status_t psa_driver_wrapper_random_set_prediction_resistance(
    psa_driver_random_context_t *context,
    unsigned enabled)
{
    // return acme_drbg_random_set_prediction_resistance(&context->acme_drbg_ctx, enabled);

    (void)context;
    (void)enabled;
    return PSA_ERROR_NOT_SUPPORTED;
}

psa_status_t psa_driver_wrapper_free_random(
    psa_driver_random_context_t *context)
{
#ifdef PSA_NEED_ACME_RNG_DRIVER
    return acme_rng_free(&context->acme_rng_ctx);
#endif /* PSA_NEED_ACME_RNG_DRIVER */

    (void)context;
    return PSA_SUCCESS;
}

#endif /* MBEDTLS_PSA_CRYPTO_C */
