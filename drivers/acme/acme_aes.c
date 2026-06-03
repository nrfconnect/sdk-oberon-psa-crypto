//
// Copyright Oberon microsystems AG, Switzerland.
// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
//
// This file implements functions from the Arm PSA Crypto Driver Interface.

/*
 * Please note: this simple implementation is provided for demonstration only. 
 *
 * Use in production is not recommended.
 */ 


#include "string.h"

#include "psa/crypto.h"
#include "acme_aes.h"


/* 128 bit AES */

static const uint8_t sbox_table[256] = {
    0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5,
    0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
    0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0,
    0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0,
    0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC,
    0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
    0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A,
    0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75,
    0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0,
    0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84,
    0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B,
    0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
    0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85,
    0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8,
    0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5,
    0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2,
    0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17,
    0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
    0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88,
    0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB,
    0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C,
    0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79,
    0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9,
    0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
    0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6,
    0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A,
    0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E,
    0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E,
    0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94,
    0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
    0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68,
    0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16,
};

static uint8_t mulx(uint8_t x)
{
    return (uint8_t)((x << 1) ^ ((x >> 7) * 0x11B));
}

static void aes_encrypt_block(uint8_t ct[16], const uint8_t pt[16], const uint8_t xkey[176])
{
    uint8_t a0, a1;
    size_t cnt = 10;
    int i;

    for (i = 0; i < 16; i++) ct[i] = pt[i] ^ *xkey++;
    for (;;) {
        for (i = 0; i < 16; i++) ct[i] = sbox_table[ct[i]];
        a0 = ct[1]; ct[1] = ct[5]; ct[5] = ct[9]; ct[9] = ct[13]; ct[13] = a0;
        a0 = ct[2]; ct[2] = ct[10]; ct[10] = a0; a0 = ct[6]; ct[6] = ct[14]; ct[14] = a0;
        a0 = ct[15]; ct[15] = ct[11]; ct[11] = ct[7]; ct[7] = ct[3]; ct[3] = a0;
        if (--cnt == 0) break;
        for (i = 0; i < 16; i += 4) {
            a1  = ct[i] ^ ct[i + 1] ^ ct[i + 2] ^ ct[i + 3];
            a0  = ct[i];
            ct[i + 0] ^= a1 ^ mulx(ct[i + 0] ^ ct[i + 1]);
            ct[i + 1] ^= a1 ^ mulx(ct[i + 1] ^ ct[i + 2]);
            ct[i + 2] ^= a1 ^ mulx(ct[i + 2] ^ ct[i + 3]);
            ct[i + 3] ^= a1 ^ mulx(ct[i + 3] ^ a0);
        }
        for (i = 0; i < 16; i++) ct[i] = ct[i] ^ *xkey++;
    }
    for (i = 0; i < 16; i++) ct[i] = ct[i] ^ *xkey++;
}

static void aes_key_expansion(uint8_t xkey[176], const uint8_t key[16])
{
    uint8_t rcon = 1, *end = xkey + 176;
    int i;

    for (i = 0; i < 16; i++) *xkey++ = *key++;
    while (xkey != end) {
        for (i = 0; i < 4; i++) xkey[i] = xkey[i - 16] ^ sbox_table[xkey[((i+1)&3)-4]];
        xkey[0] ^= rcon; rcon = mulx(rcon);
        for (i = 4; i < 16; i++) xkey[i] = xkey[i - 16] ^ xkey[i - 4];
        xkey += 16;
    }
}


psa_status_t acme_cipher_encrypt_setup(
    acme_cipher_operation_t *operation,
    const psa_key_attributes_t *attributes,
    const uint8_t *key, size_t key_length,
    psa_algorithm_t alg)
{
    if (psa_get_key_type(attributes) != PSA_KEY_TYPE_AES) return PSA_ERROR_NOT_SUPPORTED;
    if (key_length != 16) {
        if (key_length != 24 && key_length != 32) return PSA_ERROR_INVALID_ARGUMENT;
        return PSA_ERROR_INVALID_ARGUMENT;
    }
    if (alg != PSA_ALG_CTR && alg != PSA_ALG_CCM_STAR_NO_TAG) return PSA_ERROR_NOT_SUPPORTED;
    aes_key_expansion(operation->xkey, key);
    operation->alg = alg;
    return PSA_SUCCESS;
}

psa_status_t acme_cipher_decrypt_setup(
    acme_cipher_operation_t *operation,
    const psa_key_attributes_t *attributes,
    const uint8_t *key, size_t key_length,
    psa_algorithm_t alg)
{
    return acme_cipher_encrypt_setup(operation, attributes, key, key_length, alg);
}

psa_status_t acme_cipher_set_iv(
    acme_cipher_operation_t *operation,
    const uint8_t *iv, size_t iv_length)
{
    switch (operation->alg) {
    case PSA_ALG_CTR:
        if (iv_length != 16) return PSA_ERROR_INVALID_ARGUMENT;
        memcpy(operation->counter, iv, 16);
        break;
    case PSA_ALG_CCM_STAR_NO_TAG:
        if (iv_length != 13) return PSA_ERROR_INVALID_ARGUMENT;
        operation->counter[0] = 1;
        memcpy(&operation->counter[1], iv, 13);
        operation->counter[14] = 0;
        operation->counter[15] = 1;
        break;
    default:
        return PSA_ERROR_NOT_SUPPORTED;
    }
    operation->position = 16;
    return PSA_SUCCESS;
}

psa_status_t acme_cipher_update(
    acme_cipher_operation_t *operation,
    const uint8_t *input, size_t input_length,
    uint8_t *output, size_t output_size, size_t *output_length)
{
    size_t s, pos, len;
    int i;

    if (output_size < input_length) return PSA_ERROR_BUFFER_TOO_SMALL;
    *output_length = input_length;
    pos = operation->position;
    while (input_length) {
        if (pos == 16) {
            // generate a new cipher block
            aes_encrypt_block(operation->cipher, operation->counter, operation->xkey);
            // increment counter
            s = 1;
            for (i = 15; i >= 0; i--) {
                s += (uint32_t)operation->counter[i];
                operation->counter[i] = (uint8_t)s;
                s >>= 8;
            }
            pos = 0;
        }
        len = 16 - pos;
        if (len > input_length) len = input_length;
        for (i = 0; i < (int)len; i++) *output++ = *input++ ^ operation->cipher[pos++];
        input_length -= len;
    }
    operation->position = (uint32_t)pos;
    return PSA_SUCCESS;
}

psa_status_t acme_cipher_finish(
    acme_cipher_operation_t *operation,
    uint8_t *output, size_t output_size, size_t *output_length)
{
    memset(operation, 0, sizeof *operation);
    *output_length = 0;
    (void)output;
    (void)output_size;
    return PSA_SUCCESS;
}

psa_status_t acme_cipher_abort(
    acme_cipher_operation_t *operation)
{
    memset(operation, 0, sizeof *operation);
    return PSA_SUCCESS;
}


psa_status_t acme_cipher_encrypt(
    const psa_key_attributes_t *attributes,
    const uint8_t *key, size_t key_length,
    psa_algorithm_t alg,
    const uint8_t *iv, size_t iv_length,
    const uint8_t *input, size_t input_length,
    uint8_t *output, size_t output_size, size_t *output_length)
{
    acme_cipher_operation_t operation;
    psa_status_t status;
    size_t length;

    status = acme_cipher_encrypt_setup(&operation, attributes, key, key_length, alg);
    if (status) return status;
    status = acme_cipher_set_iv(&operation, iv, iv_length);
    if (status) return status;
    status = acme_cipher_update(&operation, input, input_length, output, output_size, &length);
    if (status) return status;
    status = acme_cipher_finish(&operation, output, output_size, output_length);
    if (status) return status;
    *output_length += length;

    return PSA_SUCCESS;
}

psa_status_t acme_cipher_decrypt(
    const psa_key_attributes_t *attributes,
    const uint8_t *key, size_t key_length,
    psa_algorithm_t alg,
    const uint8_t *input, size_t input_length,
    uint8_t *output, size_t output_size, size_t *output_length)
{
    acme_cipher_operation_t operation;
    psa_status_t status;
    size_t length;
    size_t iv_length = PSA_CIPHER_IV_LENGTH(psa_get_key_type(attributes), alg);

    status = acme_cipher_decrypt_setup(&operation, attributes, key, key_length, alg);
    if (status) return status;
    status = acme_cipher_set_iv(&operation, input, iv_length);
    if (status) return status;
    status = acme_cipher_update(&operation, input + iv_length, input_length - iv_length, output, output_size, &length);
    if (status) return status;
    status = acme_cipher_finish(&operation, output + length, output_size - length, output_length);
    if (status) return status;
    *output_length += length;

    return PSA_SUCCESS;
}
