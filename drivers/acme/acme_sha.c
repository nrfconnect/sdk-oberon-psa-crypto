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
#include "acme_sha.h"


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

static uint32_t sha256_blocks(acme_hash_operation_t *operation, const uint8_t *in, size_t in_len)
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

static uint32_t sha1_blocks(acme_hash_operation_t *operation, const uint8_t *in, size_t in_len)
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

static uint32_t sha_blocks(acme_hash_operation_t *operation, const uint8_t *in, size_t in_len, psa_algorithm_t alg)
{
    if (alg == PSA_ALG_SHA_1) {
        return sha1_blocks(operation, in, in_len);
    } else {
        return sha256_blocks(operation, in, in_len);
    }
}


psa_status_t acme_hash_setup(
    acme_hash_operation_t *operation,
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

psa_status_t acme_hash_clone(
    const acme_hash_operation_t*source_operation,
    acme_hash_operation_t*target_operation)
{
    memcpy(target_operation, source_operation, sizeof *target_operation);
    return PSA_SUCCESS;
}

psa_status_t acme_hash_update(
    acme_hash_operation_t *operation,
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

psa_status_t acme_hash_finish(
    acme_hash_operation_t*operation,
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

psa_status_t acme_hash_abort(
    acme_hash_operation_t*operation)
{
    memset(operation, 0, sizeof *operation);
    return PSA_SUCCESS;
}

psa_status_t acme_hash_compute(
    psa_algorithm_t alg,
    const uint8_t *input, size_t input_length,
    uint8_t *hash, size_t hash_size, size_t *hash_length)
{
    acme_hash_operation_t operation;
    psa_status_t status;

    status = acme_hash_setup(&operation, alg);
    if (status) return status;
    status = acme_hash_update(&operation, input, input_length);
    if (status) return status;
    status = acme_hash_finish(&operation, hash, hash_size, hash_length);
    if (status) return status;

    return PSA_SUCCESS;
}
