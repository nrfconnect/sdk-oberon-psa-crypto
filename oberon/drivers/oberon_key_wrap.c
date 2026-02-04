/*
 * Copyright (c) 2016 - 2025 Nordic Semiconductor ASA
 * Copyright (c) since 2020 Oberon microsystems AG
 *
 * SPDX-License-Identifier: LicenseRef-Nordic-5-Clause
 */

//
// This file implements functions from the Arm PSA Crypto Driver API.

#include <string.h>

#include "psa/crypto.h"
#include "oberon_key_wrap.h"
#include "oberon_helpers.h"
#include "psa_crypto_driver_wrappers.h"


#ifdef PSA_NEED_OBERON_AES_KW
// AES-KW initialization vector
static const uint8_t IV1[] = {0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6};
#endif /* PSA_NEED_OBERON_AES_KW */
#ifdef PSA_NEED_OBERON_AES_KWP
// AES-KWP initialization vector
static const uint8_t IV2[] = {0xA6, 0x59, 0x59, 0xA6};
#endif /* PSA_NEED_OBERON_AES_KWP */


#if defined(PSA_NEED_OBERON_AES_KW) || defined(PSA_NEED_OBERON_AES_KWP)
static psa_status_t wrapping_function(psa_cipher_operation_t *op, uint8_t a[16], uint8_t *d, size_t n)
{
    size_t length, i, j, k, x, c = 1;
    psa_status_t status;

    for (j = 0; j <= 5; j++) {
        for (i = 0; i < n; i++) {
            // use block function
            memcpy(a + 8, &d[i * 8], 8);
            status = psa_driver_wrapper_cipher_update(op, a, 16, a, 16, &length);
            if (status != PSA_SUCCESS) return status;
            memcpy(&d[i * 8], a + 8, 8);
            // add index
            k = 8; x = c++;
            do {
                a[--k] ^= (uint8_t)x;
                x >>= 8;
            } while (k > 0 && x > 0);
        }
    }
    return PSA_SUCCESS;
}

static psa_status_t unwrapping_function(psa_cipher_operation_t *op, uint8_t a[16], uint8_t *d, size_t n)
{
    size_t length, i, j, k, x, c = n * 6;
    psa_status_t status;

    for (j = 0; j <= 5; j++) {
        for (i = n; i > 0;) {
            i--;
            // add index
            k = 8; x = c--;
            do {
                a[--k] ^= (uint8_t)x;
                x >>= 8;
            } while (k > 0 && x > 0);
            // use block function
            memcpy(a + 8, &d[i * 8], 8);
            status = psa_driver_wrapper_cipher_update(op, a, 16, a, 16, &length);
            if (status != PSA_SUCCESS) return status;
            memcpy(&d[i * 8], a + 8, 8);
        }
    }
    return PSA_SUCCESS;
}
#endif /* PSA_NEED_OBERON_AES_KW || PSA_NEED_OBERON_AES_KWP */



psa_status_t oberon_wrap_key(
    const psa_key_attributes_t *wrapping_key_attributes,
    const uint8_t *wrapping_key_data, size_t wrapping_key_size,
    psa_algorithm_t alg,
    const psa_key_attributes_t *key_attributes,
    const uint8_t *key_data, size_t key_size,
    uint8_t *data, size_t data_size, size_t *data_length)
{
#if defined(PSA_NEED_OBERON_AES_KW) || defined(PSA_NEED_OBERON_AES_KWP)
    psa_cipher_operation_t cipher_op;
    psa_key_type_t type = psa_get_key_type(wrapping_key_attributes);
    uint8_t a[16];
    size_t n;
    psa_status_t status;
#endif /* PSA_NEED_OBERON_AES_KW || PSA_NEED_OBERON_AES_KWP */
#ifdef PSA_NEED_OBERON_AES_KWP
    size_t pad_len;
#endif /* PSA_NEED_OBERON_AES_KWP */

    switch (alg) {
#ifdef PSA_NEED_OBERON_AES_KW
    case PSA_ALG_KW:
        if (type != PSA_KEY_TYPE_AES) return PSA_ERROR_NOT_SUPPORTED;
        if (key_size < 16 ||
#if SIZE_MAX > 0x1FFFFFFFFFFFFF8
            key_size > 0x1FFFFFFFFFFFFF8 ||
#endif
            (key_size & 0x7) != 0) {
            return PSA_ERROR_INVALID_ARGUMENT;
        }

        if (key_size + 8 > data_size) return PSA_ERROR_BUFFER_TOO_SMALL;

        memset(&cipher_op, 0, sizeof cipher_op);
        status = psa_driver_wrapper_cipher_encrypt_setup(
            &cipher_op,
            wrapping_key_attributes, wrapping_key_data, wrapping_key_size,
            PSA_ALG_ECB_NO_PADDING);
        if (status != PSA_SUCCESS) goto exit;

        n = key_size >> 3;
        memmove(data + 8, key_data, key_size);
        memcpy(a, IV1, 8);
        status = wrapping_function(&cipher_op, a, data + 8, n);
        if (status != PSA_SUCCESS) goto exit;
        memcpy(data, a, 8); // tag
        *data_length = key_size + 8;
        return psa_driver_wrapper_cipher_abort(&cipher_op);
#endif /* PSA_NEED_OBERON_AES_KW */
#ifdef PSA_NEED_OBERON_AES_KWP
    case PSA_ALG_KWP:
        if (type != PSA_KEY_TYPE_AES) return PSA_ERROR_NOT_SUPPORTED;
        if (key_size == 0 ||
#if SIZE_MAX > 0xFFFFFFFF
            key_size > 0xFFFFFFFF ||
#endif
            (sizeof(size_t) > 4 && key_size > 0xFFFFFFFF)) {
            return PSA_ERROR_INVALID_ARGUMENT;
        }

        n = (key_size + 7) >> 3;
        if (n * 8 + 8 > data_size) return PSA_ERROR_BUFFER_TOO_SMALL;

        memset(&cipher_op, 0, sizeof cipher_op);
        status = psa_driver_wrapper_cipher_encrypt_setup(
            &cipher_op,
            wrapping_key_attributes, wrapping_key_data, wrapping_key_size,
            PSA_ALG_ECB_NO_PADDING);
        if (status != PSA_SUCCESS) goto exit;

        pad_len = n * 8 - key_size;
        memmove(data + 8, key_data, key_size);
        if (pad_len) {
            memset(data + 8 + key_size, 0, pad_len);
        }
        memcpy(a, IV2, 4);
        a[4] = (uint8_t)(key_size >> 24);
        a[5] = (uint8_t)(key_size >> 16);
        a[6] = (uint8_t)(key_size >> 8);
        a[7] = (uint8_t)key_size;
        if (n == 1) {
            memcpy(a + 8, data + 8, 8);
            status = psa_driver_wrapper_cipher_update(&cipher_op, a, 16, data, data_size, data_length);
            if (status != PSA_SUCCESS) goto exit;
        } else {
            status = wrapping_function(&cipher_op, a, data + 8, n);
            if (status != PSA_SUCCESS) goto exit;
            memcpy(data, a, 8);
            *data_length = n * 8 + 8;
        }
        return psa_driver_wrapper_cipher_abort(&cipher_op);
#endif /* PSA_NEED_OBERON_AES_KWP */
    default:
        (void)key_attributes;
        (void)key_data;
        (void)key_size;
        (void)wrapping_key_attributes;
        (void)wrapping_key_data;
        (void)wrapping_key_size;
        (void)data;
        (void)data_size;
        (void)data_length;
        return PSA_ERROR_NOT_SUPPORTED;
    }

#if defined(PSA_NEED_OBERON_AES_KW) || defined(PSA_NEED_OBERON_AES_KWP)
    exit:
    psa_driver_wrapper_cipher_abort(&cipher_op);
    return status;
#endif /* PSA_NEED_OBERON_AES_KW || PSA_NEED_OBERON_AES_KWP */
}

psa_status_t oberon_unwrap_key(
    const psa_key_attributes_t *attributes,
    const psa_key_attributes_t *wrapping_key_attributes,
    const uint8_t *wrapping_key_data, size_t wrapping_key_size,
    psa_algorithm_t alg,
    const uint8_t *data, size_t data_length,
    uint8_t *key, size_t key_size, size_t *key_length)
{
#if defined(PSA_NEED_OBERON_AES_KW) || defined(PSA_NEED_OBERON_AES_KWP)
    psa_cipher_operation_t cipher_op;
    psa_key_type_t type = psa_get_key_type(wrapping_key_attributes);
    uint8_t a[16];
    size_t n = (data_length - 8) >> 3;
    psa_status_t status;
#endif /* PSA_NEED_OBERON_AES_KW || PSA_NEED_OBERON_AES_KWP */
#ifdef PSA_NEED_OBERON_AES_KWP
    size_t len, pad_len, length;
#endif /* PSA_NEED_OBERON_AES_KWP */

    switch (alg) {
#ifdef PSA_NEED_OBERON_AES_KW
    case PSA_ALG_KW:
        if (type != PSA_KEY_TYPE_AES) return PSA_ERROR_NOT_SUPPORTED;
        if (data_length < 24 ||
#if SIZE_MAX > 0x200000000000000
            data_length > 0x200000000000000 ||
#endif
            (data_length & 0x7) != 0) {
            return PSA_ERROR_INVALID_ARGUMENT;
        }

        if (data_length - 8 > key_size) return PSA_ERROR_BUFFER_TOO_SMALL;

        memset(&cipher_op, 0, sizeof cipher_op);
        status = psa_driver_wrapper_cipher_decrypt_setup(
            &cipher_op,
            wrapping_key_attributes, wrapping_key_data, wrapping_key_size,
            PSA_ALG_ECB_NO_PADDING);
        if (status != PSA_SUCCESS) goto exit;

        memmove(key, data + 8, data_length - 8);
        memcpy(a, data, 8);
        status = unwrapping_function(&cipher_op, a, key, n);
        if (status != PSA_SUCCESS) goto exit;
        if (oberon_ct_compare(a, IV1, 8) != 0) {
            status = PSA_ERROR_INVALID_SIGNATURE;
            goto exit;
        }
        *key_length = data_length - 8;
        return psa_driver_wrapper_cipher_abort(&cipher_op);
#endif /* PSA_NEED_OBERON_AES_KW */
#ifdef PSA_NEED_OBERON_AES_KWP
    case PSA_ALG_KWP:
        if (type != PSA_KEY_TYPE_AES) return PSA_ERROR_NOT_SUPPORTED;
        if (data_length < 16 ||
#if SIZE_MAX > 0x100000008
            data_length > 0x100000008 ||
#endif
            (data_length & 0x7) != 0) {
            return PSA_ERROR_INVALID_ARGUMENT;
        }

        if (data_length - 8 > key_size) return PSA_ERROR_BUFFER_TOO_SMALL;

        memset(&cipher_op, 0, sizeof cipher_op);
        status = psa_driver_wrapper_cipher_decrypt_setup(
            &cipher_op,
            wrapping_key_attributes, wrapping_key_data, wrapping_key_size,
            PSA_ALG_ECB_NO_PADDING);
        if (status != PSA_SUCCESS) goto exit;

        if (n == 1) {
            status = psa_driver_wrapper_cipher_update(&cipher_op, data, data_length, a, 16, &length);
            if (status != PSA_SUCCESS) goto exit;
            memcpy(key, a + 8, 8);
        } else {
            memmove(key, data + 8, data_length - 8);
            memcpy(a, data, 8);
            status = unwrapping_function(&cipher_op, a, key, n);
            if (status != PSA_SUCCESS) goto exit;
        }
        len = (size_t)a[4] << 24 | (size_t)a[5] << 16 | (size_t)a[6] << 8 | (size_t)a[7];
        pad_len = n * 8 - len;
        if (oberon_ct_compare(a, IV2, 4) != 0 ||
            pad_len > 7 ||
            (pad_len && oberon_ct_compare_zero(key + len, pad_len))) {
            status = PSA_ERROR_INVALID_SIGNATURE;
            goto exit;
        }
        *key_length = len;
        return psa_driver_wrapper_cipher_abort(&cipher_op);
#endif /* PSA_NEED_OBERON_AES_KWP */
    default:
        (void)attributes;
        (void)wrapping_key_attributes;
        (void)wrapping_key_data;
        (void)wrapping_key_size;
        (void)data;
        (void)data_length;
        (void)key;
        (void)key_size;
        (void)key_length;
        return PSA_ERROR_NOT_SUPPORTED;
    }

#if defined(PSA_NEED_OBERON_AES_KW) || defined(PSA_NEED_OBERON_AES_KWP)
    exit:
    psa_driver_wrapper_cipher_abort(&cipher_op);
    return status;
#endif /* PSA_NEED_OBERON_AES_KW || PSA_NEED_OBERON_AES_KWP */
}
