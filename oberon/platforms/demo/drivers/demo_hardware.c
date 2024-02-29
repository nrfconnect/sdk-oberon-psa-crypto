/*
 * Copyright (c) 2016 - 2024 Nordic Semiconductor ASA
 * Copyright (c) since 2020 Oberon microsystems AG
 *
 * SPDX-License-Identifier: LicenseRef-Nordic-5-Clause
 */

//
// This file implements functions from the Arm PSA Crypto Driver API.

#include "string.h"

#include "psa/crypto.h"
#include "demo_hardware.h"


/* SHA */

static const uint32_t initial256[8] = {
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
};

static const uint32_t initial224[8] = {
    0xc1059ed8, 0x367cd507, 0x3070dd17, 0xf70e5939, 0xffc00b31, 0x68581511, 0x64f98fa7, 0xbefa4fa4
};

static const uint32_t initial1[5] = {
     0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0
};

static const uint32_t const_table[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

static const uint32_t const_tab1[4] = {
    0x5A827999, 0x6ED9EBA1, 0x8F1BBCDC, 0xCA62C1D6
};

#define SHTR(x,c)  ((x) >> (c))
#define ROTR(x,c)  (((x) >> (c)) | ((x) << (32 - (c))))

#define Ch(x,y,z)  ((((z) ^ (y)) & (x)) ^ (z))         // bitwise: x ? y : z
#define Maj(x,y,z) ((((x) | (y)) & (z)) | ((x) & (y))) // bitwise: x+y+z >= 2

#define Sigma0(x)  (ROTR(x,  2) ^ ROTR(x, 13) ^ ROTR(x, 22))
#define Sigma1(x)  (ROTR(x,  6) ^ ROTR(x, 11) ^ ROTR(x, 25))
#define sigma0(x)  (ROTR(x,  7) ^ ROTR(x, 18) ^ SHTR(x,  3))
#define sigma1(x)  (ROTR(x, 17) ^ ROTR(x, 19) ^ SHTR(x, 10))


static uint32_t load_bigendian(const uint8_t x[4])
{
    return (uint32_t)(x[3])
       | (((uint32_t)(x[2])) << 8)
       | (((uint32_t)(x[1])) << 16)
       | (((uint32_t)(x[0])) << 24);
}

static void store_bigendian(uint8_t x[4], uint32_t u)
{
    x[3] = (uint8_t)u; u >>= 8;
    x[2] = (uint8_t)u; u >>= 8;
    x[1] = (uint8_t)u; u >>= 8;
    x[0] = (uint8_t)u;
}

static uint32_t sha256_blocks(demo_hardware_hash_operation_t *operation, const uint8_t *in, size_t in_len)
{
    uint32_t t1, t2, *v = operation->v, *w = operation->w;
    const uint32_t *cptr;
    int i, n;

    while (in_len >= 64) {
        for (i = 0; i < 16; i++) {
            w[i] = load_bigendian(in + i * 4);
        }
        in += 64;
        in_len -= 64;

        memcpy(v, operation->h, 32);

        cptr = const_table;
        n = 4;
        while (1) {
            for (i = 0; i < 16; i++) {
                t1 = v[7] + Sigma1(v[4]) + Ch(v[4], v[5], v[6]) + *cptr++ + w[i];
                v[7] = v[6];
                v[6] = v[5];
                v[5] = v[4];
                v[4] = v[3] + t1;
                t2 = Sigma0(v[0]) + Maj(v[0], v[1], v[2]);
                v[3] = v[2];
                v[2] = v[1];
                v[1] = v[0];
                v[0] = t1 + t2;
            }
            if (--n == 0) break;
            for (i = 0; i < 16; i++) {
                w[i] += sigma1(w[(i - 2) & 15])
                    + w[(i - 7) & 15]
                    + sigma0(w[(i + 1) & 15]);
            }
        }

        for (i = 0; i < 8; i++) {
            operation->h[i] += v[i];
        }
    }
    return (uint32_t)in_len;
}

static uint32_t sha1_blocks(demo_hardware_hash_operation_t *operation, const uint8_t *in, size_t in_len)
{
    uint32_t f, t;
    uint32_t *v = operation->v, *w = operation->w;
    int i, n;

    while (in_len >= 64) {

        memcpy(v, operation->h, 20);

        for (i = 0; i < 16; i++) {
            operation->w[i] = load_bigendian(in);
            in += 4;
        }
        for (; i < 80; i++) {
            w[i] = ROTR(w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16], 31);
        }

        for (n = 0; n < 4; n++) {
            for (i = 0; i < 20; i++) {
                switch (n) {
                    case 0: f = Ch(v[1], v[2], v[3]); break;
                    case 2: f = Maj(v[1], v[2], v[3]); break;
                    default: f = v[1] ^ v[2] ^ v[3]; break;
                }
                t = ROTR(v[0], 27) + f + v[4] + const_tab1[n] + w[n * 20 + i];
                v[4] = v[3];
                v[3] = v[2];
                v[2] = ROTR(v[1], 2);
                v[1] = v[0];
                v[0] = t;
            }
        }

        for (i = 0; i < 5; i++) {
            operation->h[i] += v[i];
        }

        in_len -= 64;
    }
    return (uint32_t)in_len;
}

static uint32_t sha_blocks(demo_hardware_hash_operation_t *operation, const uint8_t *in, size_t in_len, psa_algorithm_t alg)
{
    if (alg == PSA_ALG_SHA_1) {
        return sha1_blocks(operation, in, in_len);
    } else {
        return sha256_blocks(operation, in, in_len);
    }
}


psa_status_t demo_hardware_hash_setup(
    demo_hardware_hash_operation_t *operation,
    psa_algorithm_t alg)
{
    switch (alg) {
    case PSA_ALG_SHA_1:
        memcpy(operation->h, initial1, sizeof initial1);
        break;
    case PSA_ALG_SHA_224:
        memcpy(operation->h, initial224, sizeof initial224);
        break;
    case PSA_ALG_SHA_256:
        memcpy(operation->h, initial256, sizeof initial256);
        break;
    default:
        return PSA_ERROR_NOT_SUPPORTED;
    }

    operation->length = 0;
    operation->in_length = 0;
    operation->alg = alg;
    return PSA_SUCCESS;
}

psa_status_t demo_hardware_hash_clone(
    const demo_hardware_hash_operation_t*source_operation,
    demo_hardware_hash_operation_t*target_operation)
{
    memcpy(target_operation, source_operation, sizeof *target_operation);
    return PSA_SUCCESS;
}

psa_status_t demo_hardware_hash_update(
    demo_hardware_hash_operation_t *operation,
    const uint8_t *input, size_t input_length)
{
    size_t i, len = operation->length;

    if (!operation->alg) return PSA_ERROR_BAD_STATE;

    operation->in_length += input_length;
    if (len) {
        while (len < 64 && input_length > 0) {
            operation->buffer[len++] = *input++;
            input_length--;
        }
        if (len == 64) {
            len = sha_blocks(operation, operation->buffer, 64, operation->alg);
        }
    }
    if (input_length) {
        len = sha_blocks(operation, input, input_length, operation->alg);
        input += input_length - len;
        for (i = 0; i < len; i++) operation->buffer[i] = *input++;
    }

    operation->length = (uint32_t)len;
    return PSA_SUCCESS;
}

psa_status_t demo_hardware_hash_finish(
    demo_hardware_hash_operation_t*operation,
    uint8_t *hash, size_t hash_size, size_t *hash_length)
{
    size_t i, words, len = operation->length;

    switch (operation->alg) {
    case PSA_ALG_SHA_1:   words = 5; break;
    case PSA_ALG_SHA_224: words = 7; break;
    case PSA_ALG_SHA_256: words = 8; break;
    default: return PSA_ERROR_BAD_STATE;
    }

    if (hash_size < words * 4) return PSA_ERROR_BUFFER_TOO_SMALL;
    *hash_length = words * 4;

    operation->buffer[len++] = 0x80;
    if (len > 56) {
        for (i = len; i < 64; i++) operation->buffer[i] = 0;
        len = sha_blocks(operation, operation->buffer, 64, operation->alg);
    }
    for (i = len; i < 59; i++) operation->buffer[i] = 0;
    operation->buffer[59] = (uint8_t)(operation->in_length >> 29);
    operation->buffer[60] = (uint8_t)(operation->in_length >> 21);
    operation->buffer[61] = (uint8_t)(operation->in_length >> 13);
    operation->buffer[62] = (uint8_t)(operation->in_length >> 5);
    operation->buffer[63] = (uint8_t)(operation->in_length << 3);
    sha_blocks(operation, operation->buffer, 64, operation->alg);

    for (i = 0; i < words; i++) {
        store_bigendian(hash, operation->h[i]);
        hash += 4;
    }

    memset(operation, 0, sizeof *operation);
    return PSA_SUCCESS;
}

psa_status_t demo_hardware_hash_abort(
    demo_hardware_hash_operation_t*operation)
{
    memset(operation, 0, sizeof *operation);
    return PSA_SUCCESS;
}

psa_status_t demo_hardware_hash_compute(
    psa_algorithm_t alg,
    const uint8_t *input, size_t input_length,
    uint8_t *hash, size_t hash_size, size_t *hash_length)
{
    demo_hardware_hash_operation_t operation;
    psa_status_t status;

    status = demo_hardware_hash_setup(&operation, alg);
    if (status) return status;
    status = demo_hardware_hash_update(&operation, input, input_length);
    if (status) return status;
    status = demo_hardware_hash_finish(&operation, hash, hash_size, hash_length);
    if (status) return status;

    return PSA_SUCCESS;
}


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


psa_status_t demo_hardware_cipher_encrypt_setup(
    demo_hardware_cipher_operation_t *operation,
    const psa_key_attributes_t *attributes,
    const uint8_t *key, size_t key_length,
    psa_algorithm_t alg)
{
    if (psa_get_key_type(attributes) != PSA_KEY_TYPE_AES || key_length != 16) return PSA_ERROR_NOT_SUPPORTED;
    if (alg != PSA_ALG_CTR && alg != PSA_ALG_CCM_STAR_NO_TAG) return PSA_ERROR_NOT_SUPPORTED;
    aes_key_expansion(operation->xkey, key);
    operation->alg = alg;
    return PSA_SUCCESS;
}

psa_status_t demo_hardware_cipher_decrypt_setup(
    demo_hardware_cipher_operation_t *operation,
    const psa_key_attributes_t *attributes,
    const uint8_t *key, size_t key_length,
    psa_algorithm_t alg)
{
    return demo_hardware_cipher_encrypt_setup(operation, attributes, key, key_length, alg);
}

psa_status_t demo_hardware_cipher_set_iv(
    demo_hardware_cipher_operation_t *operation,
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

psa_status_t demo_hardware_cipher_update(
    demo_hardware_cipher_operation_t *operation,
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

psa_status_t demo_hardware_cipher_finish(
    demo_hardware_cipher_operation_t *operation,
    uint8_t *output, size_t output_size, size_t *output_length)
{
    memset(operation, 0, sizeof *operation);
    *output_length = 0;
    (void)output;
    (void)output_size;
    return PSA_SUCCESS;
}

psa_status_t demo_hardware_cipher_abort(
    demo_hardware_cipher_operation_t *operation)
{
    memset(operation, 0, sizeof *operation);
    return PSA_SUCCESS;
}


psa_status_t demo_hardware_cipher_encrypt(
    const psa_key_attributes_t *attributes,
    const uint8_t *key, size_t key_length,
    psa_algorithm_t alg,
    const uint8_t *iv, size_t iv_length,
    const uint8_t *input, size_t input_length,
    uint8_t *output, size_t output_size, size_t *output_length)
{
    demo_hardware_cipher_operation_t operation;
    psa_status_t status;
    size_t length;

    status = demo_hardware_cipher_encrypt_setup(&operation, attributes, key, key_length, alg);
    if (status) return status;
    status = demo_hardware_cipher_set_iv(&operation, iv, iv_length);
    if (status) return status;
    status = demo_hardware_cipher_update(&operation, input, input_length, output, output_size, &length);
    if (status) return status;
    status = demo_hardware_cipher_finish(&operation, output, output_size, output_length);
    if (status) return status;
    *output_length += length;

    return PSA_SUCCESS;
}

psa_status_t demo_hardware_cipher_decrypt(
    const psa_key_attributes_t *attributes,
    const uint8_t *key, size_t key_length,
    psa_algorithm_t alg,
    const uint8_t *input, size_t input_length,
    uint8_t *output, size_t output_size, size_t *output_length)
{
    demo_hardware_cipher_operation_t operation;
    psa_status_t status;
    size_t length;
    size_t iv_length = PSA_CIPHER_IV_LENGTH(psa_get_key_type(attributes), alg);

    status = demo_hardware_cipher_decrypt_setup(&operation, attributes, key, key_length, alg);
    if (status) return status;
    status = demo_hardware_cipher_set_iv(&operation, input, iv_length);
    if (status) return status;
    status = demo_hardware_cipher_update(&operation, input + iv_length, input_length - iv_length, output, output_size, &length);
    if (status) return status;
    status = demo_hardware_cipher_finish(&operation, output + length, output_size - length, output_length);
    if (status) return status;
    *output_length += length;

    return PSA_SUCCESS;
}
