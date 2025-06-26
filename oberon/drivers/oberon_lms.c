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
#include "oberon_lms.h"
#include "oberon_helpers.h"
#include "psa_crypto_driver_wrappers.h"


/*           ots_type      w           lms_type      h
 *  SHA256:
 *           0x00000001    1           0x00000005     5
 *           0x00000002    2           0x00000006    10
 *           0x00000003    4           0x00000007    15
 *           0x00000004    8           0x00000008    20
 *                                     0x00000009    25
 *  SHAKE256/192:
 *           0x00000005    1           0x0000000A     5
 *           0x00000006    2           0x0000000B    10
 *           0x00000007    4           0x0000000C    15
 *           0x00000008    8           0x0000000D    20
 *                                     0x0000000E    25
 *  SHAKE256/256:
 *           0x00000009    1           0x0000000F     5
 *           0x0000000A    2           0x00000010    10
 *           0x0000000B    4           0x00000011    15
 *           0x0000000C    8           0x00000012    20
 *                                     0x00000013    25
 *  SHAKE256/192:
 *           0x0000000D    1           0x00000014     5
 *           0x0000000E    2           0x00000015    10
 *           0x0000000F    4           0x00000016    15
 *           0x00000010    8           0x00000017    20
 *                                     0x00000018    25
 */

#define D_PBLC 0x80
#define D_MESG 0x81
#define D_LEAF 0x82
#define D_INTR 0x83

// parameter macros
#define WRONG_OTS_TYPE(ots_type)         (ots_type - 1 >= 16)
#define WRONG_LMS_TYPE(lms_type)         (lms_type - 5 >= 20)

#define GET_H(lms_type, ots_type)        ((lms_type - ((ots_type - 1) >> 2) * 5 - 4) * 5)
#define GET_N(ots_type)                  (32 - ((ots_type - 1) & 4) * 2)
#define GET_W(ots_type)                  (1u << ((ots_type - 1) & 3))
#define GET_INV_W(ots_type)              (8u >> ((ots_type - 1) & 3))
#define GET_V(ots_type, n, invw)         (n == 24 && invw == 8 ? 8 : invw + 1)
#define GET_P(n, invw, v)                (n * invw + v)


/* helpers */

static uint32_t load_bigendian(const uint8_t data[4])
{
    return (data[0] << 24) | (data[1] << 16) | (data[2] << 8) | data[3];
}

static void store_bigendian(uint8_t data[4], uint32_t value)
{
    data[0] = (uint8_t)(value >> 24);
    data[1] = (uint8_t)(value >> 16);
    data[2] = (uint8_t)(value >> 8);
    data[3] = (uint8_t)(value >> 0);
}

static psa_status_t check_lms_key(const uint8_t *key, size_t key_length)
{
    uint32_t lms_type, ots_type;
    size_t n;

    if (key_length < 8) return PSA_ERROR_INVALID_ARGUMENT;
    lms_type = load_bigendian(key);
    if (WRONG_LMS_TYPE(lms_type)) return PSA_ERROR_INVALID_ARGUMENT;
    ots_type = load_bigendian(key + 4);
    if (WRONG_OTS_TYPE(ots_type)) return PSA_ERROR_INVALID_ARGUMENT;
    if (lms_type - (((ots_type + 3) >> 2) * 5) >= 5) return PSA_ERROR_INVALID_ARGUMENT; // inconsistent types
    n = GET_N(ots_type);
    if (key_length != n + 24) return PSA_ERROR_INVALID_ARGUMENT;
    return PSA_SUCCESS;
}


/* LMS signatures */

static psa_status_t oberon_lms_verify(
    const uint8_t *sig, size_t sig_len,
    const uint8_t *msg, size_t msg_len,
    const uint8_t *key, size_t key_len)
{
    psa_hash_operation_t hash_op;
    uint32_t lms_type, ots_type;
    uint32_t q, node_num, node_new;
    uint32_t idx, bits, max, sum, data, j;
    size_t n, p, w, iw, v, ls, h, i, len, length;
    const uint8_t *path;
    uint8_t block[32], temp[56];
    psa_algorithm_t hash_alg;
    psa_status_t status;

    // get parameters
    status = check_lms_key(key, key_len);
    if (status) return status;
    if (sig_len < 8) return PSA_ERROR_INVALID_SIGNATURE;
    lms_type = load_bigendian(key);
    ots_type = load_bigendian(key + 4);
    h = GET_H(lms_type, ots_type);

    // analyze signature
    q = load_bigendian(sig);
    sig += 4; // skip q
    if (load_bigendian(sig) != ots_type) return PSA_ERROR_INVALID_SIGNATURE; // inconsistent ots_type
    sig += 4; // skip type
    n = GET_N(ots_type);
    iw = GET_INV_W(ots_type); // 8 / w
    w = GET_W(ots_type);
    v = GET_V(ots_type, n, iw);
    p = GET_P(n, iw, v);
    ls = 32 - v * w;
    len = n * (p + 1);
    if (sig_len < len + 12) return PSA_ERROR_INVALID_SIGNATURE;
    path = sig + len;
    if (load_bigendian(path) != lms_type) return PSA_ERROR_INVALID_SIGNATURE; // inconsistent lms_type
    path += 4; // skip type
    if (q >= 1u << h || sig_len != len + 12 + n * h) return PSA_ERROR_INVALID_SIGNATURE;

    // get message hash
    memcpy(temp, key + 8, 16);     // I
    store_bigendian(temp + 16, q); // q
    temp[20] = temp[21] = D_MESG;
    hash_alg = ots_type >= 9 ? PSA_ALG_SHAKE256_256 : PSA_ALG_SHA_256;
    memset(&hash_op, 0, sizeof hash_op);
    status = psa_driver_wrapper_hash_setup(&hash_op, hash_alg);
    if (status) goto exit;
    status = psa_driver_wrapper_hash_update(&hash_op, temp, 22);
    if (status) goto exit;
    status = psa_driver_wrapper_hash_update(&hash_op, sig, n); // C
    if (status) goto exit;
    status = psa_driver_wrapper_hash_update(&hash_op, msg, msg_len);
    if (status) goto exit;
    status = psa_driver_wrapper_hash_finish(&hash_op, block, 32, &length); // Q
    if (status) goto exit;
    sig += n; // skip C

    // get candidate one-time public key
    temp[20] = temp[21] = D_PBLC;
    memset(&hash_op, 0, sizeof hash_op);
    status = psa_driver_wrapper_hash_setup(&hash_op, hash_alg);
    if (status) goto exit;
    status = psa_driver_wrapper_hash_update(&hash_op, temp, 22);
    if (status) goto exit;
    idx = 0; bits = 0; max = (1u << w) - 1; sum = 0;
    for (i = 0; i < p; i++) {
        temp[20] = (uint8_t)(i >> 8);
        temp[21] = (uint8_t)i;
        memcpy(temp + 23, sig, n); // y[i]
        sig += n;
        if (bits == 0) { // next byte
            if (idx == n) { // verify checksum
                data = sum << ls;
                bits = 16u;
            } else { // verify data
                data = block[idx++] << 24; // Q[idx]
                bits = 8u;
            }
        }
        j = data >> (32u - w); // coef(Q, i)
        sum += max - j; // accumulate checksum
        data <<= w;
        bits -= w;
        while (j < max) {
            temp[22] = (uint8_t)j;
            status = psa_driver_wrapper_hash_compute(hash_alg, temp, n + 23, temp + 23, 32, &length);
            if (status) goto exit;
            j++;
        }
        status = psa_driver_wrapper_hash_update(&hash_op, temp + 23, n);
        if (status) goto exit;
    }
    status = psa_driver_wrapper_hash_finish(&hash_op, temp + 22, 32, &length);
    if (status) goto exit;

    // handle leaf node of Merkle tree
    node_num = (1u << h) + q;
    store_bigendian(temp + 16, node_num);
    temp[20] = temp[21] = D_LEAF;
    status = psa_driver_wrapper_hash_compute(hash_alg, temp, n + 22, block, 32, &length);
    if (status) goto exit;

    // handle internal nodes of Merkle tree using authentication path
    temp[20] = temp[21] = D_INTR;
    i = 0;
    while (node_num > 1) {
        node_new = node_num >> 1;
        store_bigendian(temp + 16, node_new);
        memset(&hash_op, 0, sizeof hash_op);
        status = psa_driver_wrapper_hash_setup(&hash_op, hash_alg);
        if (status) goto exit;
        status = psa_driver_wrapper_hash_update(&hash_op, temp, 22);
        if (status) goto exit;
        status = psa_driver_wrapper_hash_update(&hash_op, node_num & 1 ? path : block, n);
        if (status) goto exit;
        status = psa_driver_wrapper_hash_update(&hash_op, node_num & 1 ? block : path, n);
        if (status) goto exit;
        status = psa_driver_wrapper_hash_finish(&hash_op, block, 32, &length);
        if (status) goto exit;
        node_num = node_new;
        i++;
        path += n;
    }

    // compare top node to root key
    if (oberon_ct_compare(block, key + 24, n)) return PSA_ERROR_INVALID_SIGNATURE;
    return PSA_SUCCESS;

exit:
    psa_driver_wrapper_hash_abort(&hash_op);
    return status;
}


/* HSS signatures */

static psa_status_t oberon_hss_verify(
    const uint8_t *sig, size_t sig_len,
    const uint8_t *msg, size_t msg_len,
    const uint8_t *key, size_t key_len)
{
    uint32_t L, nspk, ots_type, lms_type;
    size_t i, n, p, h, s_len, k_len, m_len;
    const uint8_t *k, *s, *m;
    psa_status_t status;

    // HSS prefix
    if (sig_len < 4) return PSA_ERROR_INVALID_SIGNATURE;
    L = load_bigendian(key);
    nspk = load_bigendian(sig);
    if (nspk >= 8 || nspk != L - 1) return PSA_ERROR_INVALID_SIGNATURE;
    sig += 4; sig_len -= 4;
    key += 4; key_len -= 4;

    // traverse LMS signatures and keys
    k = key; k_len = key_len;
    for (i = 0; i <= nspk; i++) {
        // next signature
        if (sig_len < 8) return PSA_ERROR_INVALID_SIGNATURE;
        ots_type = load_bigendian(sig + 4);
        n = GET_N(ots_type);
        p = GET_P(n, GET_INV_W(ots_type), GET_V(ots_type, n, GET_INV_W(ots_type)));
        s_len = n * (p + 1);
        if (sig_len < s_len + 12) return PSA_ERROR_INVALID_SIGNATURE;
        lms_type = load_bigendian(sig + s_len + 8);
        h = GET_H(lms_type, ots_type);
        s_len = s_len + 12 + n * h;
        if (sig_len < s_len) return PSA_ERROR_INVALID_SIGNATURE;
        s = sig; sig += s_len; sig_len -= s_len;
        if (i == nspk) {
            // verify message
            m = msg; m_len = msg_len;
        } else {
            // verify next buplic key
            if (sig_len < 8) return PSA_ERROR_INVALID_SIGNATURE;
            ots_type = load_bigendian(sig + 4);
            n = GET_N(ots_type);
            m = sig; m_len = n + 24;
            if (sig_len < m_len) return PSA_ERROR_INVALID_SIGNATURE;
            sig += m_len; sig_len -= m_len;
        }
        status = oberon_lms_verify(s, s_len, m, m_len, k, k_len);
        if (status) return status;
        k = m; k_len = m_len;
    }
    if (sig_len != 0) return PSA_ERROR_INVALID_SIGNATURE;

    return status;
}


psa_status_t oberon_import_lms_key(
    const psa_key_attributes_t *attributes,
    const uint8_t *data, size_t data_length,
    uint8_t *key, size_t key_size, size_t *key_length,
    size_t *key_bits)
{
    uint32_t ots_type;
    size_t bits;
    psa_status_t status;
    (void)attributes;

    status = check_lms_key(data, data_length);
    if (status) return status;
    ots_type = load_bigendian(data + 4);
    bits = GET_N(ots_type) * 8;
    if (*key_bits != 0 && *key_bits != bits) return PSA_ERROR_INVALID_ARGUMENT;
    if (data_length > key_size) return PSA_ERROR_BUFFER_TOO_SMALL;
    memcpy(key, data, data_length);
    *key_length = data_length;
    *key_bits = bits;
    return PSA_SUCCESS;
}

psa_status_t oberon_import_hss_key(
    const psa_key_attributes_t *attributes,
    const uint8_t *data, size_t data_length,
    uint8_t *key, size_t key_size, size_t *key_length,
    size_t *key_bits)
{
    uint32_t L, ots_type;
    size_t bits;
    psa_status_t status;
    (void)attributes;

    if (data_length < 12) return PSA_ERROR_INVALID_ARGUMENT; 
    L = load_bigendian(data);
    if ((L - 1) >= 8) return PSA_ERROR_INVALID_ARGUMENT;
    status = check_lms_key(data + 4, data_length - 4);
    if (status) return status;
    ots_type = load_bigendian(data + 8);
    bits = GET_N(ots_type) * 8;
    if (*key_bits != 0 && *key_bits != bits) return PSA_ERROR_INVALID_ARGUMENT;
    if (data_length > key_size) return PSA_ERROR_BUFFER_TOO_SMALL;
    memcpy(key, data, data_length);
    *key_length = data_length;
    *key_bits = bits;
    return PSA_SUCCESS;
}

psa_status_t oberon_lms_verify_message(
    const psa_key_attributes_t *attributes,
    const uint8_t *key, size_t key_length,
    psa_algorithm_t alg,
    const uint8_t *input, size_t input_length,
    const uint8_t *signature, size_t signature_length)
{
    (void)attributes;
    if (alg != PSA_ALG_LMS) return PSA_ERROR_INVALID_ARGUMENT;
    return oberon_lms_verify(signature, signature_length, input, input_length, key, key_length);
}

psa_status_t oberon_hss_verify_message(
    const psa_key_attributes_t *attributes,
    const uint8_t *key, size_t key_length,
    psa_algorithm_t alg,
    const uint8_t *input, size_t input_length,
    const uint8_t *signature, size_t signature_length)
{
    (void)attributes;
    if (alg != PSA_ALG_HSS) return PSA_ERROR_INVALID_ARGUMENT;
    return oberon_hss_verify(signature, signature_length, input, input_length, key, key_length);
}
