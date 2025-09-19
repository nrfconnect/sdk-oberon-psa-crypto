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
#include "oberon_wpa3_sae.h"
#include "oberon_helpers.h"
#include "psa_crypto_driver_wrappers.h"
#ifdef PSA_NEED_OBERON_WPA3_SAE
#include "ocrypto_wpa3_sae_p256.h"

#define P256_KEY_SIZE    32
#define P256_POINT_SIZE  64
#define LOOP_LIMIT       40


static const uint8_t p256_prime[32] = {  // P256 prime
    0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};


static psa_status_t setup_hmac(
    psa_mac_operation_t *mac_op,
    const uint8_t *key, size_t key_len)
{
    psa_key_attributes_t attr = PSA_KEY_ATTRIBUTES_INIT;
    psa_set_key_type(&attr, PSA_KEY_TYPE_HMAC);
    psa_set_key_bits(&attr, PSA_BYTES_TO_BITS(key_len));
    psa_set_key_usage_flags(&attr, PSA_KEY_USAGE_SIGN_MESSAGE);
    memset(mac_op, 0, sizeof *mac_op);
    return psa_driver_wrapper_mac_sign_setup(mac_op, &attr, key, key_len, PSA_ALG_HMAC(PSA_ALG_SHA_256));
}

int sha256_prf_count_len = 2; // test vector error fix !!OM

static psa_status_t sha256_prf_block(
    oberon_wpa3_sae_operation_t *op,
    const uint8_t *key, size_t key_len,
    const uint8_t *label, size_t label_len,
    const uint8_t *context, size_t context_len,
    uint16_t num, uint16_t bit_length,
    uint8_t output[32])
{
    psa_status_t status;
    uint8_t cnt[2], len[2];
    size_t length;

    // block number
    cnt[0] = (uint8_t)num;
    cnt[1] = (uint8_t)(num >> 8);

    // bit length
    len[0] = (uint8_t)bit_length;
    len[1] = (uint8_t)(bit_length >> 8);

    status = setup_hmac(&op->mac_op, key, key_len);
    if (status) goto exit;
    status = psa_driver_wrapper_mac_update(&op->mac_op, cnt, sha256_prf_count_len);
    if (status) goto exit;
    status = psa_driver_wrapper_mac_update(&op->mac_op, label, label_len);
    if (status) goto exit;
    status = psa_driver_wrapper_mac_update(&op->mac_op, context, context_len);
    if (status) goto exit;
    status = psa_driver_wrapper_mac_update(&op->mac_op, len, 2);
    if (status) goto exit;
    status = psa_driver_wrapper_mac_sign_finish(&op->mac_op, output, 32, &length);
    if (status) goto exit;

    return PSA_SUCCESS;

exit:
    psa_driver_wrapper_mac_abort(&op->mac_op);
    return status;
}

static psa_status_t wpa3_sae_pwe(oberon_wpa3_sae_operation_t *op)
{
    psa_status_t status;
    uint8_t seed[32], xy[64];
    size_t length;
    uint8_t count = 1;
    int i, valid, mask, found = 0;

    // hunt and peck
    do {
        valid = 1;
        // seed = H(addr1 | addr2, pw | cnt)
        status = setup_hmac(&op->mac_op, op->max_id, 12);
        if (status) goto exit;
        status = psa_driver_wrapper_mac_update(&op->mac_op, op->password, op->pw_length);
        if (status) goto exit;
        status = psa_driver_wrapper_mac_update(&op->mac_op, &count, 1);
        if (status) goto exit;
        status = psa_driver_wrapper_mac_sign_finish(&op->mac_op, seed, sizeof seed, &length);
        if (status) goto exit;
        // value = KDF-256(seed, label, p256)
        status = sha256_prf_block(op, seed, length,
            (const uint8_t *)"SAE Hunting and Pecking", 23,
            p256_prime, 32, 1, 256, xy);
        if (status) return status;
        // get (value,y) point or reject
        valid &= ocrypto_wpa3_sae_p256_get_pwe_from_x(&xy[32], &xy[0], (int)(seed[31] & 1));
        // save if !found
        mask = found - 1;
        for (i = 0; i < 64; i++) {
            op->pwe[i] = (uint8_t)((op->pwe[i] & ~mask) | (xy[i] & mask));
        }
        found |= valid;
        count++;
        if (count == 255) return PSA_ERROR_INSUFFICIENT_ENTROPY;
    } while (count <= LOOP_LIMIT || !found);

    return PSA_SUCCESS;

exit:
    psa_driver_wrapper_mac_abort(&op->mac_op);
    return status;
}

static psa_status_t wpa3_sae_h2e_pwe(oberon_wpa3_sae_operation_t *op)
{
    psa_status_t status;
    uint8_t val[64];
    size_t length;

    // val = H(0, addr1 | addr2)
    memset(val, 0, op->hash_length);
    status = setup_hmac(&op->mac_op, val, op->hash_length);
    if (status) goto exit;
    status = psa_driver_wrapper_mac_update(&op->mac_op, op->max_id, 12);
    if (status) goto exit;
    status = psa_driver_wrapper_mac_sign_finish(&op->mac_op, val, sizeof val, &length);
    if (status) goto exit;

    // pwe = pt * (val mod (q-1) + 1)
    ocrypto_wpa3_sae_p256_h2e_pwe_from_scalar(op->pwe, op->password, val);

    return PSA_SUCCESS;

exit:
    psa_driver_wrapper_mac_abort(&op->mac_op);
    return status;
}

static psa_status_t oberon_wpa3_sae_confirm(
    oberon_wpa3_sae_operation_t *op,
    const uint8_t commit[98],
    const uint8_t peer_commit[98],
    uint16_t send_confirm,
    uint8_t confirm[34])
{
    psa_status_t status;
    size_t length;

    // add send_confirm
    confirm[0] = (uint8_t)send_confirm;
    confirm[1] = (uint8_t)(send_confirm >> 8);

    // add CN(KCK, send_confirm, scalar, element, peer_scalar, peer_element)
    status = setup_hmac(&op->mac_op, op->kck, 32);
    if (status) goto exit;
    status = psa_driver_wrapper_mac_update(&op->mac_op, confirm, 2);
    if (status) goto exit;
    status = psa_driver_wrapper_mac_update(&op->mac_op, &commit[2], 32);
    if (status) goto exit;
    status = psa_driver_wrapper_mac_update(&op->mac_op, &commit[34], 64);
    if (status) goto exit;
    status = psa_driver_wrapper_mac_update(&op->mac_op, &peer_commit[2], 32);
    if (status) goto exit;
    status = psa_driver_wrapper_mac_update(&op->mac_op, &peer_commit[34], 64);
    if (status) goto exit;
    status = psa_driver_wrapper_mac_sign_finish(&op->mac_op, &confirm[2], 32, &length);
    if (status) goto exit;

    return PSA_SUCCESS;

exit:
    psa_driver_wrapper_mac_abort(&op->mac_op);
    return status;
}

static psa_status_t oberon_wpa3_sae_keys(oberon_wpa3_sae_operation_t *op)
{
    psa_status_t status;
    uint8_t k[32], ctx[32], salt[32];
    psa_key_attributes_t attr = PSA_KEY_ATTRIBUTES_INIT;
    size_t length;
    int res;

    // key already set
    if (op->keys_set) return PSA_SUCCESS;

    // K = ((PWE * peer_scalar) + peer_element) * rand; k = K.x
    res = ocrypto_wpa3_sae_p256_secret_value(
        k, ctx, op->pwe, &op->commit[2], &op->peer_commit[2], &op->peer_commit[34], op->rand);
    if (res) return PSA_ERROR_INVALID_ARGUMENT;

    // keyseed = H(0, k) or H(rej_list, k);
    psa_set_key_type(&attr, PSA_KEY_TYPE_HMAC);
    psa_set_key_bits(&attr, PSA_BYTES_TO_BITS(32));
    psa_set_key_usage_flags(&attr, PSA_KEY_USAGE_SIGN_MESSAGE);
    if (!op->salt_set) {
        memset(salt, 0, op->hash_length);
        status = setup_hmac(&op->mac_op, salt, op->hash_length);
        if (status) goto exit;
    } // else hmac is already set up with salt = rejected group list
    status = psa_driver_wrapper_mac_update(&op->mac_op, k, 32);
    if (status) goto exit;
    status = psa_driver_wrapper_mac_sign_finish(&op->mac_op, k, 32, &length);
    if (status) goto exit;

    // KCK | PMK = KDF-512(keyseed, "SAE KCK and PMK", context)
    status = sha256_prf_block(op, k, 32, (const uint8_t *)"SAE KCK and PMK", 15, ctx, 32, 1, 512, op->kck);
    if (status) return status;
    status = sha256_prf_block(op, k, 32, (const uint8_t *)"SAE KCK and PMK", 15, ctx, 32, 2, 512, op->pmk);
    if (status) return status;
    // SAE-PK: derive KEK here

    // pmkid = first 16 bits of context
    memcpy(op->pmkid, ctx, 16);

    op->keys_set = 1;
    return PSA_SUCCESS;

exit:
    psa_driver_wrapper_mac_abort(&op->mac_op);
    return status;
}


psa_status_t oberon_wpa3_sae_setup(
    oberon_wpa3_sae_operation_t *operation,
    const psa_key_attributes_t *attributes,
    const uint8_t *password, size_t password_length,
    const psa_pake_cipher_suite_t *cipher_suite)
{
    psa_key_type_t type = psa_get_key_type(attributes);
    psa_algorithm_t alg = psa_pake_cs_get_algorithm(cipher_suite);
    psa_algorithm_t hash_alg = PSA_ALG_GET_HASH(alg);
    psa_pake_primitive_t primitive = psa_pake_cs_get_primitive(cipher_suite);
    size_t bits = PSA_PAKE_PRIMITIVE_GET_BITS(primitive);
    size_t pmk_length = 32;

    if (PSA_PAKE_PRIMITIVE_GET_TYPE(primitive) != PSA_PAKE_PRIMITIVE_TYPE_ECC ||
        PSA_PAKE_PRIMITIVE_GET_FAMILY(primitive) != PSA_ECC_FAMILY_SECP_R1) {
        return PSA_ERROR_NOT_SUPPORTED;
    }

    switch (bits) {
    case 256:
        if (hash_alg != PSA_ALG_SHA_256) return PSA_ERROR_INVALID_ARGUMENT;
        break;
    default:
        return PSA_ERROR_NOT_SUPPORTED;
    }

    // store password
    if (password_length > sizeof operation->password) return PSA_ERROR_INSUFFICIENT_MEMORY;
    memcpy(operation->password, password, password_length);
    operation->pw_length = (uint16_t)password_length;

    operation->hash_alg = hash_alg;
    operation->hash_length = (uint8_t)PSA_HASH_LENGTH(hash_alg);
    operation->pmk_length = (uint8_t)pmk_length;
    operation->keys_set = 0;
    operation->salt_set = 0;
    operation->use_h2e = PSA_KEY_TYPE_IS_WPA3_SAE_ECC_PT(type);
    return PSA_SUCCESS;
}

psa_status_t oberon_wpa3_sae_set_user(
    oberon_wpa3_sae_operation_t *operation,
    const uint8_t *user_id, size_t user_id_len)
{
    if (user_id_len != 6) return PSA_ERROR_INVALID_ARGUMENT;
    memcpy(operation->max_id, user_id, 6);
    return PSA_SUCCESS;
}

psa_status_t oberon_wpa3_sae_set_peer(
    oberon_wpa3_sae_operation_t *operation,
    const uint8_t *peer_id, size_t peer_id_len)
{
    if (peer_id_len != 6) return PSA_ERROR_INVALID_ARGUMENT;
    if (memcmp(peer_id, operation->max_id, 6) > 0) {
        memcpy(operation->min_id, operation->max_id, 6);
        memcpy(operation->max_id, peer_id, 6);
    } else {
        memcpy(operation->min_id, peer_id, 6);
    }

    // get PWE
    if (operation->use_h2e) {
        return wpa3_sae_h2e_pwe(operation);
    } else {
        return wpa3_sae_pwe(operation);
    }
}

psa_status_t oberon_wpa3_sae_output(
    oberon_wpa3_sae_operation_t *operation,
    psa_pake_step_t step,
    uint8_t *output, size_t output_size, size_t *output_length)
{
    int res;
    psa_status_t status;
    uint8_t mask[32]; // temporary key

    switch (step) {
    case PSA_PAKE_STEP_COMMIT:
        if (output_size < 98) return PSA_ERROR_BUFFER_TOO_SMALL;
        do {
            status = psa_generate_random(operation->rand, 32);
            if (status) return status;
            status = psa_generate_random(mask, 32);
            if (status) return status;
            // check for valid rand & mask and generate commit data
            res = ocrypto_wpa3_sae_p256_get_commit(operation->commit, operation->rand, mask, operation->pwe);
        } while (res);
        memcpy(output, operation->commit, 98);
        *output_length = 98;
        break;
    case PSA_PAKE_STEP_CONFIRM:
        if (output_size < 34) return PSA_ERROR_BUFFER_TOO_SMALL;
        status = oberon_wpa3_sae_keys(operation);
        if (status) return status;
        status = oberon_wpa3_sae_confirm(operation,
            operation->commit, operation->peer_commit, operation->send_confirm, output);
        if (status) return status;
        *output_length = 34;
        break;
    case PSA_PAKE_STEP_KEYID:
        if (output_size < 16) return PSA_ERROR_BUFFER_TOO_SMALL;
        memcpy(output, operation->pmkid, 16);
        *output_length = 16;
        break;
    default:
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    return PSA_SUCCESS;
}

psa_status_t oberon_wpa3_sae_input(
    oberon_wpa3_sae_operation_t *operation,
    psa_pake_step_t step,
    const uint8_t *input, size_t input_length)
{
    psa_status_t status;
    uint8_t verify[34];
    uint16_t send_confirm;
    int res;

    switch (step) {
    case PSA_PAKE_STEP_COMMIT:
        if (input_length != 98) return PSA_ERROR_INVALID_ARGUMENT;
        res = ocrypto_wpa3_sae_p256_check_commit(input);
        if (res) return PSA_ERROR_INVALID_ARGUMENT;
        memcpy(operation->peer_commit, input, 98);
        break;
    case PSA_PAKE_STEP_SALT:
        // rejected groups list
        status = setup_hmac(&operation->mac_op, input, input_length);
        if (status) return status;
        operation->salt_set = 1;
        break;
    case PSA_PAKE_STEP_CONFIRM:
        if (input_length != 34) return PSA_ERROR_INVALID_ARGUMENT;
        status = oberon_wpa3_sae_keys(operation);
        if (status) return status;
        send_confirm = input[0] | (input[1] << 8);
        status = oberon_wpa3_sae_confirm(operation, operation->peer_commit, operation->commit, send_confirm, verify);
        if (status) return status;
        res = oberon_ct_compare(input, verify, 34);
        if (res) return PSA_ERROR_INVALID_SIGNATURE;
        break;
    case PSA_PAKE_STEP_SEND_CONFIRM:
        if (input_length != 2) return PSA_ERROR_INVALID_ARGUMENT;
        operation->send_confirm = input[0] | (input[1] << 8);
        break;
    default:
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    return PSA_SUCCESS;
}

psa_status_t oberon_wpa3_sae_get_shared_key(
    oberon_wpa3_sae_operation_t *operation,
    uint8_t *output, size_t output_size, size_t *output_length)
{

    if (output_size < operation->pmk_length) return PSA_ERROR_BUFFER_TOO_SMALL;
    memcpy(output, operation->pmk, operation->pmk_length);
    *output_length = operation->pmk_length;
    return PSA_SUCCESS;
}

psa_status_t oberon_wpa3_sae_abort(
    oberon_wpa3_sae_operation_t *operation)
{
    (void)operation;
    return PSA_SUCCESS;
}


#ifdef PSA_NEED_OBERON_KEY_TYPE_WPA3_SAE_PT_SECP_R1_256
static psa_status_t hkdf_sha256_expand(uint8_t u[64], const uint8_t seed[32], const uint8_t *label, size_t label_len)
{
    psa_mac_operation_t mac_op;
    psa_status_t status;
    size_t length;
    uint8_t idx;

    // HKDF-expand
    idx = 1;
    status = setup_hmac(&mac_op, seed, 32);
    if (status) goto exit;
    status = psa_driver_wrapper_mac_update(&mac_op, label, label_len);
    if (status) goto exit;
    status = psa_driver_wrapper_mac_update(&mac_op, &idx, 1);
    if (status) goto exit;
    status = psa_driver_wrapper_mac_sign_finish(&mac_op, u, 32, &length);
    if (status) goto exit;
    idx = 2;
    status = setup_hmac(&mac_op, seed, 32);
    if (status) goto exit;
    status = psa_driver_wrapper_mac_update(&mac_op, u, 32);
    if (status) goto exit;
    status = psa_driver_wrapper_mac_update(&mac_op, label, label_len);
    if (status) goto exit;
    status = psa_driver_wrapper_mac_update(&mac_op, &idx, 1);
    if (status) goto exit;
    status = psa_driver_wrapper_mac_sign_finish(&mac_op, u + 32, 32, &length);
    if (status) goto exit;

    return PSA_SUCCESS;

exit:
    psa_driver_wrapper_mac_abort(&mac_op);
    return status;
}
#endif

psa_status_t oberon_derive_wpa3_sae_pt_key(
    const psa_key_attributes_t *attributes,
    const uint8_t *input, size_t input_length,
    uint8_t *key, size_t key_size, size_t *key_length)
{
    size_t bits = psa_get_key_bits(attributes);
    psa_key_type_t type = psa_get_key_type(attributes);
    uint8_t u1[64], u2[64];

    switch (type) {
#ifdef PSA_NEED_OBERON_KEY_TYPE_WPA3_SAE_PT_SECP_R1_256
    case PSA_KEY_TYPE_WPA3_SAE_ECC_PT(PSA_ECC_FAMILY_SECP_R1):
        switch (bits) {
        case 256: 
            if (input_length != 32) return PSA_ERROR_INVALID_ARGUMENT;
            if (key_size < 64) return PSA_ERROR_BUFFER_TOO_SMALL;

            hkdf_sha256_expand(u1, input, (const uint8_t *)"SAE Hash to Element u1 P1", 25); // expand u1
            hkdf_sha256_expand(u2, input, (const uint8_t *)"SAE Hash to Element u2 P2", 25); // expand u2

            return ocrypto_wpa3_sae_p256_sswu_pt(key, u1, u2);  // get PT
            *key_length = 64;
            return PSA_SUCCESS;
        default:
            return PSA_ERROR_NOT_SUPPORTED;
        }
#endif /* PSA_NEED_OBERON_KEY_TYPE_WPA3_SAE_PT_SECP_R1_256 */

    default:
        (void)input;
        (void)input_length;
        (void)key;
        (void)key_size;
        (void)key_length;
        (void)bits;
        (void)u1;
        (void)u2;
        return PSA_ERROR_NOT_SUPPORTED;
    }
}

psa_status_t oberon_import_wpa3_sae_pt_key(
    const psa_key_attributes_t *attributes,
    const uint8_t *data, size_t data_length,
    uint8_t *key, size_t key_size, size_t *key_length,
    size_t *key_bits)
{
    int res;
    size_t bits = psa_get_key_bits(attributes);
    psa_key_type_t type = psa_get_key_type(attributes);

    switch (type) {
#ifdef PSA_NEED_OBERON_KEY_TYPE_WPA3_SAE_PT
    case PSA_KEY_TYPE_WPA3_SAE_ECC_PT(PSA_ECC_FAMILY_SECP_R1):
        switch (data_length) {
        case 64:
            if (bits != 0 && bits != 256) return PSA_ERROR_INVALID_ARGUMENT;
            res = ocrypto_wpa3_sae_p256_check_pt(data);
            if (res) return PSA_ERROR_INVALID_ARGUMENT; // point not on curve
            break;
        default:
            return PSA_ERROR_NOT_SUPPORTED;
        }
        break;
#endif /* PSA_NEED_OBERON_KEY_TYPE_WPA3_SAE_PT */

    default:
        (void)res;
        (void)bits;
        return PSA_ERROR_NOT_SUPPORTED;
    }

    if (key_size < data_length) return PSA_ERROR_BUFFER_TOO_SMALL;
    memcpy(key, data, data_length);
    *key_length = data_length;
    *key_bits = 256;
    return PSA_SUCCESS;
}
#endif /* PSA_NEED_OBERON_WPA3_SAE */
