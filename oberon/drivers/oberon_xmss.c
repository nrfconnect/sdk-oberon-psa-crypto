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
#include "oberon_xmss.h"
#include "oberon_helpers.h"
#include "psa_crypto_driver_wrappers.h"


/*           XMSS id        h       XMSS^HT id     h   d  h/d
*  SHA256:                                                             
*           0x00000001    10       0x00000001    20   2  10
*           0x00000002    16       0x00000002    20   4   5
*           0x00000003    20       0x00000003    40   2  20
*                                  0x00000004    40   4  10
*           n = 32                 0x00000005    40   8   5
*           w = 16                 0x00000006    60   3  20
*           len = 67               0x00000007    60   6  10
*                                  0x00000008    60  12   5
*  SHA256/192:
*           0x0000000D    10       0x00000021    20   2  10
*           0x0000000E    16       0x00000022    20   4   5
*           0x0000000F    20       0x00000023    40   2  20
*                                  0x00000024    40   4  10
*           n = 24                 0x00000025    40   8   5
*           w = 16                 0x00000026    60   3  20
*           len = 51               0x00000027    60   6  10
*                                  0x00000028    60  12   5
*  SHAKE256/256:
*           0x00000010    10       0x00000029    20   2  10
*           0x00000011    16       0x0000002A    20   4   5
*           0x00000012    20       0x0000002B    40   2  20
*                                  0x0000002C    40   4  10
*           n = 32                 0x0000002D    40   8   5
*           w = 16                 0x0000002E    60   3  20
*           len = 67               0x0000002F    60   6  10
*                                  0x00000030    60  12   5
*  SHAKE256/192:
*           0x00000013    10       0x00000031    20   2  10
*           0x00000014    16       0x00000032    20   4   5
*           0x00000015    20       0x00000033    40   2  20
*                                  0x00000034    40   4  10
*           n = 24                 0x00000035    40   8   5
*           w = 16                 0x00000036    60   3  20
*           len = 51               0x00000037    60   6  10
*                                  0x00000038    60  12   5
*/

static const uint8_t xmss_h[3]   = {10, 16, 20};
static const uint8_t xmssmt_d[8] = {2, 4, 2, 4, 8, 3, 6, 12};
static const uint8_t xmssmt_q[8] = {10, 5, 20, 10, 5, 20, 10, 5}; // h/d


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

static psa_status_t xmss_prf(
    uint8_t *rand, const uint8_t *seed, uint8_t adrs[32], uint32_t mask, uint32_t n, psa_hash_operation_t *hash_op, psa_algorithm_t hash_alg)
{
    uint8_t pre[32];
    size_t length;
    psa_status_t status;

    adrs[31] = (uint8_t)mask;

    memset(hash_op, 0, sizeof *hash_op);
    status = psa_driver_wrapper_hash_setup(hash_op, hash_alg);
    if (status) goto exit;
    if (n == 32) {
        memset(pre, 0, 31);
        pre[31] = 3; // PRF
        status = psa_driver_wrapper_hash_update(hash_op, pre, 32);
        if (status) goto exit;
    } else {
        memset(pre, 0, 3);
        pre[3] = 3; // PRF
        status = psa_driver_wrapper_hash_update(hash_op, pre, 4);
        if (status) goto exit;
    }
    status = psa_driver_wrapper_hash_update(hash_op, seed, n);
    if (status) goto exit;
    status = psa_driver_wrapper_hash_update(hash_op, adrs, 32);
    if (status) goto exit;
    status = psa_driver_wrapper_hash_finish(hash_op, rand, 32, &length);
    if (status) goto exit;
    return PSA_SUCCESS;

exit:
    psa_driver_wrapper_hash_abort(hash_op);
    return status;
}

static psa_status_t xmss_get_message_hash(
    uint8_t *hash, const uint8_t *rand, const uint8_t *root, const uint8_t *msg, size_t msg_len,
    uint64_t idx, uint32_t n, psa_algorithm_t hash_alg)
{
    psa_hash_operation_t hash_op;
    uint8_t pre[32];
    size_t length;
    psa_status_t status;

    memset(&hash_op, 0, sizeof hash_op);
    status = psa_driver_wrapper_hash_setup(&hash_op, hash_alg);
    if (status) goto exit;
    if (n == 32) {
        memset(pre, 0, 31);
        pre[31] = 2; // H_msg
        status = psa_driver_wrapper_hash_update(&hash_op, pre, 32);
        if (status) goto exit;
    } else {
        memset(pre, 0, 3);
        pre[3] = 2; // H_msg
        status = psa_driver_wrapper_hash_update(&hash_op, pre, 4);
        if (status) goto exit;
    }
    status = psa_driver_wrapper_hash_update(&hash_op, rand, n);
    if (status) goto exit;
    status = psa_driver_wrapper_hash_update(&hash_op, root, n);
    if (status) goto exit;
    memset(pre, 0, n - 8);
    store_bigendian(&pre[n - 8], (uint32_t)(idx >> 32));
    store_bigendian(&pre[n - 4], (uint32_t)idx);
    status = psa_driver_wrapper_hash_update(&hash_op, pre, n);
    if (status) goto exit;
    status = psa_driver_wrapper_hash_update(&hash_op, msg, msg_len);
    if (status) goto exit;
    status = psa_driver_wrapper_hash_finish(&hash_op, hash, 32, &length);
    if (status) goto exit;
    return PSA_SUCCESS;

exit:
    psa_driver_wrapper_hash_abort(&hash_op);
    return status;
}

static psa_status_t ots_hash(
    uint8_t *hash, const uint8_t *node, const uint8_t *seed, uint8_t adrs[32], uint32_t n, psa_algorithm_t hash_alg)
{
    psa_hash_operation_t hash_op;
    uint8_t pre[32], key[32], bm[32];
    size_t length;
    psa_status_t status;

    xmss_prf(key, seed, adrs, 0, n, &hash_op, hash_alg);
    xmss_prf(bm, seed, adrs, 1, n, &hash_op, hash_alg);

    oberon_xor(bm, bm, node, n);

    memset(&hash_op, 0, sizeof hash_op);
    status = psa_driver_wrapper_hash_setup(&hash_op, hash_alg);
    if (status) goto exit;
    if (n == 32) {
        memset(pre, 0, 31);
        pre[31] = 0; // F
        status = psa_driver_wrapper_hash_update(&hash_op, pre, 32);
        if (status) goto exit;
    } else {
        memset(pre, 0, 3);
        pre[3] = 0; // F
        status = psa_driver_wrapper_hash_update(&hash_op, pre, 4);
        if (status) goto exit;
    }
    status = psa_driver_wrapper_hash_update(&hash_op, key, n);
    if (status) goto exit;
    status = psa_driver_wrapper_hash_update(&hash_op, bm, n);
    if (status) goto exit;
    status = psa_driver_wrapper_hash_finish(&hash_op, hash, 32, &length);
    if (status) goto exit;
    return PSA_SUCCESS;

exit:
    psa_driver_wrapper_hash_abort(&hash_op);
    return status;
}

static psa_status_t rand_hash(
    uint8_t *hash, const uint8_t *left, const uint8_t *right, const uint8_t *seed, uint8_t adrs[32],
    uint32_t n, psa_algorithm_t hash_alg)
{
    psa_hash_operation_t hash_op;
    uint8_t pre[32], key[32], bm0[32], bm1[32];
    size_t length;
    psa_status_t status;

    xmss_prf(key, seed, adrs, 0, n, &hash_op, hash_alg);
    xmss_prf(bm0, seed, adrs, 1, n, &hash_op, hash_alg);
    xmss_prf(bm1, seed, adrs, 2, n, &hash_op, hash_alg);

    oberon_xor(bm0, bm0, left, n);
    oberon_xor(bm1, bm1, right, n);

    memset(&hash_op, 0, sizeof hash_op);
    status = psa_driver_wrapper_hash_setup(&hash_op, hash_alg);
    if (status) goto exit;
    if (n == 32) {
        memset(pre, 0, 31);
        pre[31] = 1; // H
        status = psa_driver_wrapper_hash_update(&hash_op, pre, 32);
        if (status) goto exit;
    } else {
        memset(pre, 0, 3);
        pre[3] = 1; // H
        status = psa_driver_wrapper_hash_update(&hash_op, pre, 4);
        if (status) goto exit;
    }
    status = psa_driver_wrapper_hash_update(&hash_op, key, n);
    if (status) goto exit;
    status = psa_driver_wrapper_hash_update(&hash_op, bm0, n);
    if (status) goto exit;
    status = psa_driver_wrapper_hash_update(&hash_op, bm1, n);
    if (status) goto exit;
    status = psa_driver_wrapper_hash_finish(&hash_op, hash, 32, &length);
    if (status) goto exit;
    return PSA_SUCCESS;

exit:
    psa_driver_wrapper_hash_abort(&hash_op);
    return status;
}

static void xmss_root_from_sig(
    uint8_t *node, const uint8_t *sig, const uint8_t *msg, const uint8_t *seed, uint8_t adrs[32],
    uint32_t idx, uint32_t n, uint32_t h, psa_algorithm_t hash_alg)
{
    uint32_t hidx, bits, sum, data;
    uint32_t height, i, j, ni, hi, len, last;
    const uint8_t *path; // authentication path in sig
    uint8_t tree[7][32]; // temporary L-tree nodes

    len = n * 2 + 3;
    last = len - 1;
    path = sig + n * len;

    // tree node from signature
    store_bigendian(&adrs[16], idx); // OTS/L-tree address
    ni = 0; bits = 0; sum = n * 30;
    for (i = 0; i <= last; i++) {
        // get pk[i]
        memcpy(node, sig, n);
        sig += n;
        if (bits == 0) { // next byte
            if (ni == n) { // verify checksum
                data = sum << 20; // left adjust checksum
                bits = 12u;
            } else { // verify data
                data = msg[ni++] << 24; // M[ni]
                bits = 8u;
            }
        }
        j = data >> 28; // next base w digit
        sum -= j; // accumulate checksum
        data <<= 4;
        bits -= 4;
        adrs[15] = 0; // type = OTS hash
        store_bigendian(&adrs[20], i); // chain address
        while (j < 15) {
            store_bigendian(&adrs[24], j); // hash address
            ots_hash(node, node, seed, adrs, n, hash_alg);
            j++;
        }

        // add pk to L-tree
        adrs[15] = 1; // type = L-tree
        height = 0;
        hi = i;
        while (1) {
            if (hi & 1) {
                hi >>= 1; // indx at height
                store_bigendian(&adrs[20], height); // tree height
                store_bigendian(&adrs[24], hi);     // tree index
                rand_hash(node, tree[height], node, seed, adrs, n, hash_alg);
            } else {
                if (i < last) {
                    memcpy(tree[height], node, n);
                    break;
                }
                hi >>= 1;
                if (hi == 0) break;
            }
            height++;
        }
    }

    // authentication path
    adrs[15] = 2; // type = Hash tree
    store_bigendian(&adrs[16], 0);
    for (i = 0; i < h; i++) {
        hidx = idx >> 1;
        store_bigendian(&adrs[20], i);    // tree height
        store_bigendian(&adrs[24], hidx); // tree index
        if (idx & 1) {
            rand_hash(node, path, node, seed, adrs, n, hash_alg);
        } else {
            rand_hash(node, node, path, seed, adrs, n, hash_alg);
        }
        idx = hidx;
        path += n;
    }
}


/* XMSS signatures */

static psa_status_t oberon_xmss_verify(
    const uint8_t *sig, size_t sig_len,
    const uint8_t *msg, size_t msg_len,
    const uint8_t *pk,  size_t pk_len)
{
    uint8_t node[32], mhash[32], adrs[32] = {0};
    uint32_t oid, idx, n, h, len;
    const uint8_t *rand;
    psa_algorithm_t hash_alg;

    // xmss parameters
    if (pk_len < 4) return PSA_ERROR_INVALID_ARGUMENT;
    oid = load_bigendian(pk);
    pk += 4; pk_len -= 4;
    oid -= 1; // 1..3 -> 0..2
    if (oid > 2) {
        if (oid - 12 > 8) return PSA_ERROR_INVALID_ARGUMENT;
        oid -= 9; // 13..21 -> 3..11
    }
    n = oid * 11 >> 5; // oid / 3
    h = oid - n * 3;   // oid % 3
    n = 32 - (n & 1) * 8;
    h = xmss_h[h];
    len = n * 2 + 3;
    if (pk_len != n * 2) return PSA_ERROR_INVALID_ARGUMENT;
    hash_alg = oid >= 6 ? PSA_ALG_SHAKE256_256 : PSA_ALG_SHA_256;

    // check signature
    if (sig_len < 36) return PSA_ERROR_INVALID_SIGNATURE;
    idx = load_bigendian(sig);
    sig += 4; sig_len -= 4;
    if (idx >= (1u << h)) return PSA_ERROR_INVALID_SIGNATURE;
    rand = sig;
    sig += n; sig_len -= n;
    if (sig_len != (h + len) * n) return PSA_ERROR_INVALID_SIGNATURE;

    xmss_get_message_hash(mhash, rand, pk, msg, msg_len, idx, n, hash_alg);
    xmss_root_from_sig(node, sig, mhash, pk + n, adrs, idx, n, h, hash_alg);
    if (oberon_ct_compare(node, pk, n)) return PSA_ERROR_INVALID_SIGNATURE;
    return PSA_SUCCESS;
}


/* XMSS^MT signatures */

static psa_status_t oberon_xmssmt_verify(
    const uint8_t *sig, size_t sig_len,
    const uint8_t *msg, size_t msg_len,
    const uint8_t *pk,  size_t pk_len)
{
    uint8_t node[32], mhash[32], adrs[32] = {0};
    uint32_t oid, idx, hd_mask;
    uint32_t i, n, h, d, hd, len;
    uint64_t mtidx;
    const uint8_t *rand;
    psa_algorithm_t hash_alg;

    // xmssmt parameters
    if (pk_len < 4) return PSA_ERROR_INVALID_ARGUMENT;
    oid = load_bigendian(pk);
    pk += 4; pk_len -= 4;
    oid -= 1; // 1..8 -> 0..7
    if (oid > 7) {
        if (oid - 32 > 23) return PSA_ERROR_INVALID_ARGUMENT;
        oid -= 24; // 33..55 -> 8..31
    }
    n = 32 - ((oid >> 3) & 1) * 8;
    d = xmssmt_d[oid & 7];
    hd = xmssmt_q[oid & 7]; // h/d
    h = d * hd;
    len = n * 2 + 3;
    hd_mask = (1u << hd) - 1u;
    if (pk_len != n * 2) return PSA_ERROR_INVALID_ARGUMENT;
    hash_alg = oid >= 16 ? PSA_ALG_SHAKE256_256 : PSA_ALG_SHA_256;

    if (sig_len < 40) return PSA_ERROR_INVALID_SIGNATURE;
    switch (h) {
    case 20:
        mtidx = sig[0] << 16 | sig[1] << 8 | sig[2];
        sig += 3; sig_len -= 3;
        break;
    case 40:
        mtidx = (uint64_t)load_bigendian(sig) << 8 | sig[4];
        sig += 5; sig_len -= 5;
        break;
    default:
        mtidx = (uint64_t)load_bigendian(sig) << 32 | load_bigendian(sig + 4);
        sig += 8; sig_len -= 8;
        break;
    }
    rand = sig;
    sig += n; sig_len -= n;
    if (sig_len != (hd + len) * n * d) return PSA_ERROR_INVALID_SIGNATURE;

    xmss_get_message_hash(mhash, rand, pk, msg, msg_len, mtidx, n, hash_alg);

    // traverse XMSS signatures
    for (i = 0; i < d; i++) {
        idx = (uint32_t)mtidx & hd_mask; // idx_leaf
        mtidx >>= hd; // idx_tree
        adrs[3] = (uint8_t)i; // layer address
        store_bigendian(&adrs[4], (uint32_t)(mtidx >> 32));
        store_bigendian(&adrs[8], (uint32_t)mtidx); // tree address
        xmss_root_from_sig(node, sig, mhash, pk + n, adrs, idx, n, hd, hash_alg);
        memcpy(mhash, node, n);
        sig += (hd + len) * n;
    }
    if (oberon_ct_compare(node, pk, n)) return PSA_ERROR_INVALID_SIGNATURE;
    return PSA_SUCCESS;
}


psa_status_t oberon_import_xmss_key(
    const psa_key_attributes_t *attributes,
    const uint8_t *data, size_t data_length,
    uint8_t *key, size_t key_size, size_t *key_length,
    size_t *key_bits)
{
    uint32_t oid;
    size_t bits;
    (void)attributes;

    if (data_length < 4) return PSA_ERROR_INVALID_ARGUMENT; 
    oid = load_bigendian(data);
    if ((oid >= 1 && oid <= 3) || (oid >= 16 && oid <= 18)) {
        if (data_length != 2 * 32 + 4) return PSA_ERROR_INVALID_ARGUMENT;
        bits = 256;
    } else  if ((oid >= 13 && oid <= 15) || (oid >= 19 && oid <= 21)) {
        if (data_length != 2 * 24 + 4) return PSA_ERROR_INVALID_ARGUMENT;
        bits = 192;
    } else {
        return PSA_ERROR_INVALID_ARGUMENT;
    }
    if (data_length > key_size) return PSA_ERROR_BUFFER_TOO_SMALL;
    memcpy(key, data, data_length);
    *key_length = data_length;
    *key_bits = bits;
    return PSA_SUCCESS;
}

psa_status_t oberon_import_xmssmt_key(
    const psa_key_attributes_t *attributes,
    const uint8_t *data, size_t data_length,
    uint8_t *key, size_t key_size, size_t *key_length,
    size_t *key_bits)
{
    uint32_t oid;
    size_t bits;
    (void)attributes;

    if (data_length < 4) return PSA_ERROR_INVALID_ARGUMENT; 
    oid = load_bigendian(data);
    if ((oid >= 1 && oid <= 8) || (oid >= 0x29 && oid <= 0x30)) {
        if (data_length != 2 * 32 + 4) return PSA_ERROR_INVALID_ARGUMENT;
        bits = 256;
    } else if ((oid >= 0x21 && oid <= 0x28) || (oid >= 0x31 && oid <= 0x38)) {
        if (data_length != 2 * 24 + 4) return PSA_ERROR_INVALID_ARGUMENT;
        bits = 192;
    } else {
        return PSA_ERROR_INVALID_ARGUMENT;
    }
    if (data_length > key_size) return PSA_ERROR_BUFFER_TOO_SMALL;
    memcpy(key, data, data_length);
    *key_length = data_length;
    *key_bits = bits;
    return PSA_SUCCESS;
}

psa_status_t oberon_xmss_verify_message(
    const psa_key_attributes_t *attributes,
    const uint8_t *key, size_t key_length,
    psa_algorithm_t alg,
    const uint8_t *input, size_t input_length,
    const uint8_t *signature, size_t signature_length)
{
    (void)attributes;
    if (alg != PSA_ALG_XMSS) return PSA_ERROR_INVALID_ARGUMENT;
    return oberon_xmss_verify(signature, signature_length, input, input_length, key, key_length);
}

psa_status_t oberon_xmssmt_verify_message(
    const psa_key_attributes_t *attributes,
    const uint8_t *key, size_t key_length,
    psa_algorithm_t alg,
    const uint8_t *input, size_t input_length,
    const uint8_t *signature, size_t signature_length)
{
    (void)attributes;
    if (alg != PSA_ALG_XMSS_MT) return PSA_ERROR_INVALID_ARGUMENT;
    return oberon_xmssmt_verify(signature, signature_length, input, input_length, key, key_length);
}
