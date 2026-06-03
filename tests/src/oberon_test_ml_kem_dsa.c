/*
 *  Copyright Oberon microsystems AG, Switzerland
 *  SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
 *
 *  Licensed under the Apache License, Version 2.0 (the "License"); you may
 *  not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 *  WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */

/*
 * Tests for ML-DSA, ML-KEM.
 */


#include <string.h>

#include "psa/crypto.h"
#include <test/helpers.h>
#include <test/macros.h>
#include "oberon_test_drbg.h"
#if defined(PSA_WANT_ALG_SHAKE128) || defined(PSA_WANT_ALG_SHAKE256)
#include "oberon_test_xof.h"
#endif


#if defined(PSA_WANT_ALG_ML_DSA) || defined(PSA_WANT_ALG_DETERMINISTIC_ML_DSA) || \
    defined(PSA_WANT_ALG_HASH_ML_DSA) || defined(PSA_WANT_ALG_DETERMINISTIC_HASH_ML_DSA)


static const uint8_t seed[32] = {
    0x6D, 0xBB, 0xC4, 0x37, 0x51, 0x36, 0xDF, 0x3B, 0x07, 0xF7, 0xC7, 0x0E, 0x63, 0x9E, 0x22, 0x3E,
    0x17, 0x7E, 0x7F, 0xD5, 0x3B, 0x16, 0x1B, 0x3F, 0x4D, 0x57, 0x79, 0x17, 0x94, 0xF1, 0x26, 0x24};
static const uint8_t seed2[32] = {
    0xF6, 0x96, 0x48, 0x40, 0x48, 0xEC, 0x21, 0xF9, 0x6C, 0xF5, 0x0A, 0x56, 0xD0, 0x75, 0x9C, 0x44,
    0x8F, 0x37, 0x79, 0x75, 0x2F, 0x03, 0x83, 0xD3, 0x74, 0x49, 0x69, 0x06, 0x94, 0xCF, 0x7A, 0x68};
static const uint8_t message[32] = {
    0x20, 0xA7, 0xB7, 0xE1, 0x0F, 0x70, 0x49, 0x6C, 0xC3, 0x82, 0x20, 0xB9, 0x44, 0xDE, 0xF6, 0x99,
    0xBF, 0x14, 0xD1, 0x4E, 0x55, 0xCF, 0x4C, 0x90, 0xA1, 0x2C, 0x1B, 0x33, 0xFC, 0x80, 0xFF, 0xFF};
static const uint8_t ctxStr[16] = "ThisIsTheContext";

// Shake128 hashes
static const uint8_t pk_44[] = {
    0x0c, 0xbe, 0x62, 0x18, 0xa6, 0xf5, 0x2d, 0x7b, 0x5c, 0x1a, 0xfb, 0xb5, 0xfd, 0x37, 0xf7, 0xe9,
    0x7e, 0x0c, 0x86, 0x4f, 0xff, 0x42, 0x8b, 0x96, 0x42, 0x00, 0xf4, 0x02, 0x37, 0xf6, 0x82, 0x37};
static const uint8_t sig_44[] = {
    0x61, 0xe1, 0x00, 0xca, 0xbf, 0xd8, 0x0b, 0x56, 0xa2, 0xc4, 0x6c, 0xe0, 0xe0, 0x31, 0xcc, 0x1c,
    0x71, 0xec, 0xcd, 0x2e, 0x03, 0x13, 0x57, 0xc7, 0xf7, 0x7e, 0x83, 0x61, 0x31, 0x83, 0x19, 0x6d};
static const uint8_t sigD_44[] = {
    0xe6, 0xc8, 0x83, 0x24, 0x68, 0x80, 0xc8, 0xc1, 0x2f, 0xe2, 0x32, 0x6a, 0x1e, 0xe8, 0xbc, 0xb9,
    0xe4, 0xc8, 0xe1, 0xaa, 0x8b, 0x32, 0x41, 0x91, 0xb4, 0x71, 0x8e, 0xeb, 0x79, 0x36, 0xdf, 0x06};
static const uint8_t sigC_44[] = {
    0x6d, 0x01, 0x7e, 0xb3, 0x27, 0x05, 0x6c, 0xea, 0xf7, 0x68, 0xc8, 0xfc, 0x88, 0x45, 0x74, 0xd3,
    0xe1, 0xeb, 0x27, 0x03, 0xa5, 0x5d, 0xa0, 0x6d, 0xbc, 0x9d, 0x6f, 0x58, 0xbb, 0x40, 0xb0, 0xc8};
static const uint8_t sigH_44[] = {
    0xe0, 0x45, 0x9b, 0x65, 0xb4, 0xf2, 0xcd, 0xd4, 0xe0, 0x3d, 0x14, 0xdb, 0x34, 0x16, 0xa7, 0xfe,
    0xa1, 0x48, 0xa6, 0xb5, 0xf4, 0x2c, 0xa9, 0xc6, 0xd3, 0x97, 0xcd, 0xdb, 0xcf, 0xf4, 0x28, 0x8f};
static const uint8_t sigHD_44[] = {
    0x55, 0x26, 0xcc, 0x5e, 0x3f, 0x6c, 0xa1, 0xae, 0x2f, 0x8a, 0x37, 0x37, 0x1c, 0x2d, 0x83, 0x32,
    0x5a, 0x39, 0xa0, 0x46, 0x05, 0xc0, 0xbc, 0x3a, 0x16, 0x4e, 0x13, 0xc7, 0x85, 0x50, 0xbc, 0xb3};
static const uint8_t sigHC_44[] = {
    0xa8, 0xe8, 0x33, 0xc6, 0x53, 0x36, 0x29, 0x5c, 0xfc, 0x04, 0x97, 0xda, 0xb5, 0x1f, 0x9b, 0x53,
    0xf4, 0x03, 0x38, 0x43, 0x30, 0xb7, 0x18, 0x0c, 0x55, 0x72, 0x41, 0x37, 0x22, 0x65, 0x13, 0x8d};
static const uint8_t pk_65[] = {
    0xd0, 0x70, 0xb3, 0x75, 0x3f, 0xac, 0x91, 0x8f, 0x2b, 0x83, 0xf1, 0x20, 0xdb, 0x94, 0xee, 0x76,
    0x59, 0xbc, 0xce, 0xae, 0xf5, 0x44, 0x5a, 0x0f, 0xac, 0xae, 0x48, 0x49, 0x7a, 0x90, 0xf7, 0xac};
static const uint8_t sig_65[] = {
    0xda, 0x99, 0xd3, 0xb8, 0xeb, 0x12, 0x72, 0xf7, 0x60, 0xd6, 0x3a, 0x45, 0xbe, 0x6a, 0xf3, 0x1f,
    0xa6, 0xcb, 0xf7, 0x54, 0x9c, 0xdf, 0xaa, 0x25, 0xe0, 0xcc, 0x38, 0xeb, 0x1c, 0x6f, 0x2d, 0x68};
static const uint8_t sigD_65[] = {
    0x60, 0x01, 0x9d, 0x06, 0x3e, 0xc2, 0xad, 0x70, 0x1e, 0x7d, 0xb3, 0xf9, 0x58, 0xb3, 0xba, 0x0c,
    0xe2, 0x29, 0x7b, 0x3e, 0xf1, 0xe1, 0xb8, 0x04, 0x73, 0x2d, 0xb6, 0x5d, 0x74, 0xeb, 0x57, 0x8a};
static const uint8_t sigC_65[] = {
    0x95, 0xdf, 0x6c, 0xab, 0xd8, 0x01, 0x5f, 0x00, 0xac, 0x22, 0x58, 0x7e, 0xc1, 0x2f, 0x52, 0xf2,
    0xf4, 0xf3, 0x64, 0x0e, 0xd1, 0xc8, 0xa6, 0x40, 0xa7, 0xa0, 0x7d, 0xc3, 0x95, 0x1d, 0x11, 0x11};
static const uint8_t sigH_65[] = {
    0x93, 0xd7, 0x4c, 0x7b, 0x31, 0x30, 0x95, 0x65, 0xe6, 0x9b, 0x8f, 0x9e, 0xf4, 0xff, 0xe2, 0x2f,
    0x37, 0x94, 0xa4, 0x64, 0xbe, 0x82, 0xa6, 0xa8, 0x52, 0xaf, 0x46, 0xca, 0x88, 0x4e, 0x4d, 0xd1};
static const uint8_t sigHD_65[] = {
    0x50, 0x44, 0x6a, 0x1d, 0x14, 0x71, 0x09, 0xbf, 0x26, 0x47, 0x55, 0x96, 0x96, 0x8d, 0x7e, 0x7f,
    0x62, 0xc5, 0xda, 0x0a, 0x25, 0x7e, 0xe2, 0xc5, 0x61, 0x10, 0x2f, 0x6d, 0xca, 0x88, 0x88, 0x27};
static const uint8_t sigHC_65[] = {
    0x7a, 0x0b, 0xf6, 0xd8, 0x4a, 0xd2, 0x72, 0xd9, 0x19, 0x85, 0x0c, 0xa9, 0x54, 0x02, 0x85, 0x1f,
    0xf5, 0x74, 0xb0, 0xe1, 0x4c, 0xd7, 0x7f, 0xe2, 0xd3, 0x87, 0xae, 0xdf, 0x48, 0xcd, 0x46, 0x16};
static const uint8_t pk_87[] = {
    0x08, 0xf8, 0x06, 0x2d, 0x0d, 0xa8, 0x03, 0x4f, 0xfa, 0x1f, 0x22, 0x55, 0x33, 0x6d, 0x66, 0xc0,
    0x2d, 0x4d, 0xb8, 0xaf, 0x8d, 0x66, 0x1b, 0x64, 0xae, 0x31, 0x64, 0x02, 0x26, 0x66, 0x09, 0x14};
static const uint8_t sig_87[] = {
    0x49, 0xd1, 0xe3, 0x5a, 0x5e, 0xc6, 0x08, 0x3e, 0xa5, 0x8e, 0xd4, 0x6e, 0xb1, 0xc8, 0x39, 0x14,
    0xfa, 0x5e, 0x28, 0xe1, 0x95, 0x6a, 0xda, 0x8f, 0x62, 0x89, 0xd3, 0xa8, 0x1d, 0x3b, 0xf3, 0x97};
static const uint8_t sigD_87[] = {
    0x59, 0x67, 0xb4, 0x65, 0x4b, 0x41, 0xb0, 0x8d, 0x99, 0xbe, 0x1c, 0x73, 0xce, 0x5a, 0x32, 0x17,
    0x1b, 0xaa, 0x28, 0x4e, 0x33, 0x3d, 0xb7, 0xe4, 0xfc, 0xd5, 0xc0, 0xe7, 0x0b, 0x9a, 0x17, 0xcf};
static const uint8_t sigC_87[] = {
    0xb0, 0x15, 0xe6, 0xc9, 0xe4, 0x8e, 0xec, 0xbe, 0xcc, 0xc0, 0x4a, 0x43, 0x75, 0x84, 0x45, 0x49,
    0x1b, 0x1d, 0x06, 0x11, 0xec, 0x10, 0xf8, 0xcd, 0x90, 0x7a, 0x00, 0x3c, 0x03, 0xae, 0xf9, 0xc9};
static const uint8_t sigH_87[] = {
    0x7d, 0xa7, 0xcb, 0x22, 0xba, 0xdd, 0x92, 0x03, 0x21, 0x0c, 0xe3, 0xb7, 0xfd, 0x24, 0x3a, 0x8e,
    0x63, 0x42, 0x34, 0xad, 0xa4, 0xe7, 0x8f, 0x7b, 0x1b, 0xd9, 0xa2, 0x4a, 0xbb, 0x5d, 0xe8, 0xb6};
static const uint8_t sigHD_87[] = {
    0xfe, 0xd8, 0x4b, 0xb8, 0x83, 0x0c, 0x63, 0x07, 0x3b, 0x32, 0x54, 0xc1, 0x13, 0x47, 0xe4, 0x4c,
    0x15, 0x2b, 0x66, 0x99, 0x0d, 0xb8, 0x8d, 0x9f, 0xd4, 0x7f, 0x37, 0x6b, 0x53, 0x67, 0x40, 0x90};
static const uint8_t sigHC_87[] = {
    0xc6, 0x61, 0xdf, 0x11, 0x90, 0xea, 0xbf, 0x8f, 0x85, 0xda, 0xdd, 0xfa, 0x5c, 0x90, 0x86, 0xb4,
    0x2a, 0x7f, 0xe9, 0xc4, 0x7e, 0xd5, 0x66, 0x41, 0x7b, 0x26, 0xad, 0x7d, 0x5b, 0x0c, 0xf4, 0x91};

// ct0 rejection test (ML-DSA-44 only)
static const uint8_t ct0_seed[32] = {
    0x53, 0x68, 0x6a, 0x56, 0x3d, 0xc9, 0x3a, 0x01, 0xfd, 0x5a, 0x79, 0xac, 0x83, 0xde, 0x0a, 0x9c, 
    0xbc, 0x3b, 0xb3, 0xfc, 0x90, 0xfb, 0x03, 0xcc, 0x91, 0xb8, 0x13, 0x5e, 0xff, 0xce, 0x6d, 0x94}; 
static const uint8_t ct0_hash[64] = {
    0x6f, 0xe5, 0xa0, 0xa5, 0xeb, 0x58, 0x00, 0xcb, 0x2b, 0xdd, 0x58, 0x12, 0xb2, 0xd8, 0x54, 0xd8, 
    0xd7, 0x4e, 0x3f, 0x1c, 0xd5, 0xb0, 0x5b, 0x69, 0x51, 0x7f, 0x2b, 0xf4, 0x33, 0xf5, 0x53, 0x2b, 
    0xff, 0xba, 0xc7, 0x90, 0x32, 0xa3, 0x5b, 0x47, 0x07, 0x2e, 0xe7, 0x36, 0x91, 0xf2, 0x69, 0x0a, 
    0x47, 0x49, 0x20, 0xea, 0xc1, 0x58, 0xa5, 0x36, 0xb5, 0xb2, 0x31, 0x07, 0xb0, 0xc7, 0xd7, 0x71}; 
static const uint8_t ct0_sig[] = {
    0x97, 0x38, 0x92, 0xc5, 0xa8, 0xce, 0x9e, 0x5c, 0x24, 0x2a, 0xe1, 0xba, 0x0f, 0xb8, 0x20, 0x4d,
    0x98, 0x08, 0x65, 0xb1, 0x61, 0xae, 0xee, 0x94, 0x87, 0x06, 0xe5, 0x0c, 0xc8, 0xa8, 0x2b, 0x8e};

// accumulated tests
static const uint8_t accu_inp_44[] = {0x79, 0x92, 0x5b, 0x99};
static const uint8_t accu_dsa_44[] = {
    0x2f, 0x52, 0xc8, 0x7d, 0x60, 0x74, 0xd9, 0xdc, 0x0a, 0xc0, 0x3e, 0xb5, 0xbb, 0x53, 0x3b, 0xa5,
    0xe9, 0xb0, 0xa7, 0x30, 0x3c, 0x25, 0xe9, 0x4c, 0x62, 0x7d, 0x8f, 0x66, 0xe9, 0x16, 0xf9, 0x28};
static const uint8_t accu_inp_65[] = {0x73, 0xc2, 0x3e, 0xc7};
static const uint8_t accu_dsa_65[] = {
    0x32, 0x8e, 0x36, 0x12, 0xcb, 0xc7, 0xa5, 0x42, 0x21, 0x21, 0xd1, 0x2f, 0xe1, 0x8c, 0xe3, 0x7b,
    0x14, 0x0b, 0xd6, 0xe6, 0x3e, 0x53, 0xf6, 0x38, 0xb7, 0x8e, 0x55, 0x06, 0x00, 0xff, 0xde, 0xba};
static const uint8_t accu_inp_87[] = {0xec, 0xbf, 0x50, 0xe5};
static const uint8_t accu_dsa_87[] = {
    0xf0, 0x6d, 0xbd, 0xe9, 0xed, 0x92, 0x05, 0x8c, 0x60, 0x1f, 0x48, 0x1d, 0x87, 0xe7, 0x50, 0x34,
    0x20, 0xaa, 0x52, 0xe3, 0x2b, 0x3c, 0x4a, 0xb1, 0x1a, 0x15, 0x00, 0xbe, 0xd5, 0xa0, 0xed, 0xcc};

#define ML_DSA44_PK_SIZE 1312
#define ML_DSA65_PK_SIZE 1952
#define ML_DSA87_PK_SIZE 2592
#define ML_DSA44_SIG_SIZE 2420
#define ML_DSA65_SIG_SIZE 3309
#define ML_DSA87_SIG_SIZE 4627

static int test_ml_dsa(int n, int k)
{
    psa_key_attributes_t key_attr = PSA_KEY_ATTRIBUTES_INIT;
    psa_key_derivation_operation_t op = PSA_KEY_DERIVATION_OPERATION_INIT;
    psa_key_id_t key = 0, pkey = 0, dkey = 0;
    psa_algorithm_t alg;
    uint8_t pub[ML_DSA87_PK_SIZE], sig[ML_DSA87_SIG_SIZE], h[32];
    size_t slen, plen, len;
    size_t key_size = (k + 2) * 64; // 128, 196, 256
    size_t pk_size, sig_size;
    int res = 0;

    switch (k) {
    case 0: pk_size = ML_DSA44_PK_SIZE; sig_size = ML_DSA44_SIG_SIZE; break;
    case 1: pk_size = ML_DSA65_PK_SIZE; sig_size = ML_DSA65_SIG_SIZE; break;
    case 2: pk_size = ML_DSA87_PK_SIZE; sig_size = ML_DSA87_SIG_SIZE; break;
    default: return 0;
    }

    switch (n) {
    case 4:
    case 5: alg = PSA_ALG_ML_DSA; break;
    case 6: alg = PSA_ALG_HASH_ML_DSA(PSA_ALG_SHAKE256_256); break;
    case 7: alg = PSA_ALG_HASH_ML_DSA(PSA_ALG_SHAKE128_256); break;
    case 8: alg = PSA_ALG_DETERMINISTIC_HASH_ML_DSA(PSA_ALG_SHAKE256_256); break;
    case 9: alg = PSA_ALG_DETERMINISTIC_HASH_ML_DSA(PSA_ALG_SHAKE128_256); break;
    case 10: alg = PSA_ALG_HASH_ML_DSA(PSA_ALG_SHAKE256_256); break;
    default: alg = PSA_ALG_DETERMINISTIC_ML_DSA;
    }

    TEST_ASSERT(PSA_EXPORT_KEY_OUTPUT_SIZE(PSA_KEY_TYPE_ML_DSA_KEY_PAIR, key_size) == 32);
    TEST_ASSERT(PSA_EXPORT_KEY_OUTPUT_SIZE(PSA_KEY_TYPE_ML_DSA_PUBLIC_KEY, key_size) == pk_size);
    TEST_ASSERT(PSA_SIGN_OUTPUT_SIZE(PSA_KEY_TYPE_ML_DSA_KEY_PAIR, key_size, PSA_ALG_ML_DSA) == sig_size);

    if (n == 1) {
        oberon_test_xof_config(0, 1); // manipulate XOF to provoke more rejections
        psa_set_key_usage_flags(&key_attr, PSA_KEY_USAGE_DERIVE);
        psa_set_key_algorithm(&key_attr, PSA_ALG_HKDF(PSA_ALG_SHA_256));
        psa_set_key_type(&key_attr, PSA_KEY_TYPE_DERIVE);
        psa_set_key_bits(&key_attr, 256);
        TEST_ASSERT(psa_import_key(&key_attr, seed, 32, &dkey) == PSA_SUCCESS);
    }

    if (n == 6) {
        psa_set_key_usage_flags(&key_attr, PSA_KEY_USAGE_SIGN_MESSAGE | PSA_KEY_USAGE_SIGN_HASH | PSA_KEY_USAGE_VERIFY_HASH);
    } else if (n == 3 || n == 5 || n == 10) {
        psa_set_key_usage_flags(&key_attr, PSA_KEY_USAGE_SIGN_MESSAGE | PSA_KEY_USAGE_VERIFY_MESSAGE);
    } else {
        psa_set_key_usage_flags(&key_attr, PSA_KEY_USAGE_SIGN_MESSAGE | PSA_KEY_USAGE_EXPORT);
    }
    psa_set_key_algorithm(&key_attr, alg);
    psa_set_key_type(&key_attr, PSA_KEY_TYPE_ML_DSA_KEY_PAIR);
    psa_set_key_bits(&key_attr, key_size);
    if (n == 1) {
        TEST_ASSERT(psa_key_derivation_setup(&op, PSA_ALG_HKDF(PSA_ALG_SHA_256)) == PSA_SUCCESS);
        TEST_ASSERT(psa_key_derivation_input_key(&op, PSA_KEY_DERIVATION_INPUT_SECRET, dkey) == PSA_SUCCESS);
        TEST_ASSERT(psa_key_derivation_input_bytes(&op, PSA_KEY_DERIVATION_INPUT_INFO, NULL, 0) == PSA_SUCCESS);
        TEST_ASSERT(psa_key_derivation_output_key(&key_attr, &op, &key) == PSA_SUCCESS);
    } else if (n == 2) {
        oberon_test_drbg_setup(seed, 32);
        TEST_ASSERT(psa_generate_key(&key_attr, &key) == PSA_SUCCESS);
        TEST_ASSERT(psa_export_key(key, h, sizeof h, &len) == PSA_SUCCESS);
        ASSERT_COMPARE(h, len, seed, 32);
    } else {
        TEST_ASSERT(psa_import_key(&key_attr, seed, 32, &key) == PSA_SUCCESS);
    }

    TEST_ASSERT(psa_export_public_key(key, pub, pk_size, &plen) == PSA_SUCCESS);
    if (n != 1) {
        psa_hash_compute(PSA_ALG_SHAKE128_256, pub, plen, h, sizeof h, &len);
        switch (k) {
        case 0: ASSERT_COMPARE(h, len, pk_44, sizeof pk_44); break;
        case 1: ASSERT_COMPARE(h, len, pk_65, sizeof pk_65); break;
        case 2: ASSERT_COMPARE(h, len, pk_87, sizeof pk_87); break;
        }
    }

    oberon_test_drbg_setup(seed2, 32);
    if (n == 5 || n == 10) {
        TEST_ASSERT(psa_sign_message_with_context(key, alg, message, sizeof message, ctxStr, sizeof ctxStr,
                                                  sig, sig_size, &slen) == PSA_SUCCESS);
    } else {
        TEST_ASSERT(psa_sign_message(key, alg, message, sizeof message, sig, sig_size, &slen) == PSA_SUCCESS);
    }
    switch (n) {
    case 0:
    case 2:
    case 3:
        psa_hash_compute(PSA_ALG_SHAKE128_256, sig, sig_size, h, sizeof h, &len);
        switch (k) {
        case 0: ASSERT_COMPARE(h, len, sigD_44, sizeof sigD_44); break;
        case 1: ASSERT_COMPARE(h, len, sigD_65, sizeof sigD_65); break;
        case 2: ASSERT_COMPARE(h, len, sigD_87, sizeof sigD_87); break;
        }
        break;
    case 4:
        psa_hash_compute(PSA_ALG_SHAKE128_256, sig, sig_size, h, sizeof h, &len);
        switch (k) {
        case 0: ASSERT_COMPARE(h, len, sig_44, sizeof sig_44); break;
        case 1: ASSERT_COMPARE(h, len, sig_65, sizeof sig_65); break;
        case 2: ASSERT_COMPARE(h, len, sig_87, sizeof sig_87); break;
        }
        break;
    case 5:
        psa_hash_compute(PSA_ALG_SHAKE128_256, sig, sig_size, h, sizeof h, &len);
        switch (k) {
        case 0: ASSERT_COMPARE(h, len, sigC_44, sizeof sigC_44); break;
        case 1: ASSERT_COMPARE(h, len, sigC_65, sizeof sigC_65); break;
        case 2: ASSERT_COMPARE(h, len, sigC_87, sizeof sigC_87); break;
        }
        break;
    case 6:
        psa_hash_compute(PSA_ALG_SHAKE128_256, sig, sig_size, h, sizeof h, &len);
        switch (k) {
        case 0: ASSERT_COMPARE(h, len, sigH_44, sizeof sigH_44); break;
        case 1: ASSERT_COMPARE(h, len, sigH_65, sizeof sigH_65); break;
        case 2: ASSERT_COMPARE(h, len, sigH_87, sizeof sigH_87); break;
        }
        break;
    case 8:
        psa_hash_compute(PSA_ALG_SHAKE128_256, sig, sig_size, h, sizeof h, &len);
        switch (k) {
        case 0: ASSERT_COMPARE(h, len, sigHD_44, sizeof sigHD_44); break;
        case 1: ASSERT_COMPARE(h, len, sigHD_65, sizeof sigHD_65); break;
        case 2: ASSERT_COMPARE(h, len, sigHD_87, sizeof sigHD_87); break;
        }
        break;
    case 10:
        psa_hash_compute(PSA_ALG_SHAKE128_256, sig, sig_size, h, sizeof h, &len);
        switch (k) {
        case 0: ASSERT_COMPARE(h, len, sigHC_44, sizeof sigHC_44); break;
        case 1: ASSERT_COMPARE(h, len, sigHC_65, sizeof sigHC_65); break;
        case 2: ASSERT_COMPARE(h, len, sigHC_87, sizeof sigHC_87); break;
        }
        break;
    }

    if (n == 6) {
        TEST_ASSERT(psa_hash_compute(PSA_ALG_SHAKE256_256, message, sizeof message, h, sizeof h, &len) == PSA_SUCCESS);
        oberon_test_drbg_setup(seed2, 32);
        TEST_ASSERT(psa_sign_hash(key, alg, h, len, sig, sig_size, &slen) == PSA_SUCCESS);
        psa_hash_compute(PSA_ALG_SHAKE128_256, sig, sig_size, h, sizeof h, &len);
        switch (k) {
        case 0: ASSERT_COMPARE(h, len, sigH_44, sizeof sigH_44); break;
        case 1: ASSERT_COMPARE(h, len, sigH_65, sizeof sigH_65); break;
        case 2: ASSERT_COMPARE(h, len, sigH_87, sizeof sigH_87); break;
        }
    }

    // test relaxed key policy for verify
    alg = alg ^ PSA_ALG_ML_DSA_DETERMINISTIC_FLAG; // hedged <-> deterministic

    if (n == 3) {
        TEST_ASSERT(psa_verify_message(key, alg, message, sizeof message, sig, slen) == PSA_SUCCESS);
    } else if (n == 5 || n == 10) {
        TEST_ASSERT(psa_verify_message_with_context(key, alg, message, sizeof message, ctxStr, sizeof ctxStr, sig, slen) == PSA_SUCCESS);
    } else {
        psa_set_key_usage_flags(&key_attr, PSA_KEY_USAGE_VERIFY_MESSAGE);
        psa_set_key_type(&key_attr, PSA_KEY_TYPE_ML_DSA_PUBLIC_KEY);
        TEST_ASSERT(psa_import_key(&key_attr, pub, plen, &pkey) == PSA_SUCCESS);
        TEST_ASSERT(psa_verify_message(pkey, alg, message, sizeof message, sig, slen) == PSA_SUCCESS);
    }

    if (n == 6) {
        psa_set_key_usage_flags(&key_attr, PSA_KEY_USAGE_VERIFY_HASH);
        psa_set_key_type(&key_attr, PSA_KEY_TYPE_ML_DSA_PUBLIC_KEY);
        TEST_ASSERT(psa_import_key(&key_attr, pub, plen, &pkey) == PSA_SUCCESS);
        TEST_ASSERT(psa_hash_compute(PSA_ALG_SHAKE256_256, message, sizeof message, h, sizeof h, &len) == PSA_SUCCESS);
        TEST_ASSERT(psa_verify_hash(pkey, alg, h, len, sig, slen) == PSA_SUCCESS);
        // use secret key
        TEST_ASSERT(psa_verify_hash(key, alg, h, len, sig, slen) == PSA_SUCCESS);
    }

    res = 1;
exit:
    oberon_test_xof_config(0, 0);
    TEST_ASSERT(psa_destroy_key(key) == PSA_SUCCESS);
    TEST_ASSERT(psa_destroy_key(pkey) == PSA_SUCCESS);
    TEST_ASSERT(psa_destroy_key(dkey) == PSA_SUCCESS);

    return res;
}

static int test_ml_dsa_err(int n, int k)
{
    psa_key_attributes_t key_attr = PSA_KEY_ATTRIBUTES_INIT;
    psa_key_id_t key = 0, pkey = 0, dkey = 0;
    uint8_t pub[ML_DSA87_PK_SIZE], sig[ML_DSA87_SIG_SIZE], h[32];
    size_t slen, plen, len;
    size_t key_size = (k + 2) * 64; // 128, 196, 256
    size_t pk_size, sig_size;

    switch (k) {
    case 0: pk_size = ML_DSA44_PK_SIZE; sig_size = ML_DSA44_SIG_SIZE; break;
    case 1: pk_size = ML_DSA65_PK_SIZE; sig_size = ML_DSA65_SIG_SIZE; break;
    case 2: pk_size = ML_DSA87_PK_SIZE; sig_size = ML_DSA87_SIG_SIZE; break;
    default: return 0;
    }

    psa_set_key_bits(&key_attr, key_size);
    psa_set_key_type(&key_attr, PSA_KEY_TYPE_ML_DSA_KEY_PAIR);

    if (n == 1) { // sign_hash with ML_DSA
        psa_set_key_algorithm(&key_attr, PSA_ALG_ML_DSA);
        psa_set_key_usage_flags(&key_attr, PSA_KEY_USAGE_SIGN_HASH);
        TEST_ASSERT(psa_import_key(&key_attr, seed, 32, &key) == PSA_SUCCESS);
        TEST_ASSERT(psa_hash_compute(PSA_ALG_SHAKE256_256, message, sizeof message, h, sizeof h, &len) == PSA_SUCCESS);
        oberon_test_drbg_setup(seed2, 32);
        TEST_ASSERT(psa_sign_hash(key, PSA_ALG_ML_DSA, h, len, sig, sig_size, &slen) == PSA_ERROR_INVALID_ARGUMENT);
        goto abort;
    } else if (n == 3) { // sign_hash with DETERMINISTIC_ML_DSA
        psa_set_key_algorithm(&key_attr, PSA_ALG_DETERMINISTIC_ML_DSA);
        psa_set_key_usage_flags(&key_attr, PSA_KEY_USAGE_SIGN_HASH);
        TEST_ASSERT(psa_import_key(&key_attr, seed, 32, &key) == PSA_SUCCESS);
        TEST_ASSERT(psa_hash_compute(PSA_ALG_SHAKE256_256, message, sizeof message, h, sizeof h, &len) == PSA_SUCCESS);
        oberon_test_drbg_setup(seed2, 32);
        TEST_ASSERT(psa_sign_hash(key, PSA_ALG_DETERMINISTIC_ML_DSA, h, len, sig, sig_size, &slen) == PSA_ERROR_INVALID_ARGUMENT);
        goto abort;
    } else if (n == 5) { // wrong hash algorithm
        psa_set_key_algorithm(&key_attr, PSA_ALG_HASH_ML_DSA(PSA_ALG_MD5));
        psa_set_key_usage_flags(&key_attr, PSA_KEY_USAGE_SIGN_HASH);
        TEST_ASSERT(psa_import_key(&key_attr, seed, 32, &key) == PSA_SUCCESS);
        TEST_ASSERT(psa_hash_compute(PSA_ALG_SHAKE256_256, message, sizeof message, h, sizeof h, &len) == PSA_SUCCESS);
        oberon_test_drbg_setup(seed2, 32);
        TEST_ASSERT(psa_sign_hash(key, PSA_ALG_HASH_ML_DSA(PSA_ALG_MD5), h, len, sig, sig_size, &slen) == PSA_ERROR_NOT_SUPPORTED);
        goto abort;
    } else if (n == 6) { // wrong hash algorithm (deterministic)
        psa_set_key_algorithm(&key_attr, PSA_ALG_DETERMINISTIC_HASH_ML_DSA(PSA_ALG_MD5));
        psa_set_key_usage_flags(&key_attr, PSA_KEY_USAGE_SIGN_HASH);
        TEST_ASSERT(psa_import_key(&key_attr, seed, 32, &key) == PSA_SUCCESS);
        TEST_ASSERT(psa_hash_compute(PSA_ALG_SHAKE256_256, message, sizeof message, h, sizeof h, &len) == PSA_SUCCESS);
        oberon_test_drbg_setup(seed2, 32);
        TEST_ASSERT(psa_sign_hash(key, PSA_ALG_DETERMINISTIC_HASH_ML_DSA(PSA_ALG_MD5), h, len, sig, sig_size, &slen) == PSA_ERROR_NOT_SUPPORTED);
        goto abort;
    } else if (n == 7) { // sign_message with wrong context length
        psa_set_key_algorithm(&key_attr, PSA_ALG_ML_DSA);
        psa_set_key_usage_flags(&key_attr, PSA_KEY_USAGE_SIGN_MESSAGE);
        TEST_ASSERT(psa_import_key(&key_attr, seed, 32, &key) == PSA_SUCCESS);
        oberon_test_drbg_setup(seed2, 32);
        TEST_ASSERT(psa_sign_message_with_context(key, PSA_ALG_ML_DSA, message, sizeof message, ctxStr, 512, sig, sig_size, &slen) == PSA_ERROR_INVALID_ARGUMENT);
        goto abort;
    } else if (n == 8) { // sign_hash with wrong context length
        psa_set_key_algorithm(&key_attr, PSA_ALG_HASH_ML_DSA(PSA_ALG_SHAKE256_256));
        psa_set_key_usage_flags(&key_attr, PSA_KEY_USAGE_SIGN_HASH);
        TEST_ASSERT(psa_import_key(&key_attr, seed, 32, &key) == PSA_SUCCESS);
        TEST_ASSERT(psa_hash_compute(PSA_ALG_SHAKE256_256, message, sizeof message, h, sizeof h, &len) == PSA_SUCCESS);
        oberon_test_drbg_setup(seed2, 32);
        TEST_ASSERT(psa_sign_hash_with_context(key, PSA_ALG_HASH_ML_DSA(PSA_ALG_SHAKE256_256), h, len, ctxStr, 512, sig, sig_size, &slen) == PSA_ERROR_INVALID_ARGUMENT);
        goto abort;
    } else {
        psa_set_key_algorithm(&key_attr, PSA_ALG_ML_DSA);
        psa_set_key_usage_flags(&key_attr, PSA_KEY_USAGE_SIGN_MESSAGE);
        TEST_ASSERT(psa_import_key(&key_attr, seed, 32, &key) == PSA_SUCCESS);
        oberon_test_drbg_setup(seed2, 32);
        TEST_ASSERT(psa_sign_message(key, PSA_ALG_ML_DSA, message, sizeof message, sig, sig_size, &slen) == PSA_SUCCESS);
    }

    TEST_ASSERT(psa_export_public_key(key, pub, pk_size, &plen) == PSA_SUCCESS);

    psa_set_key_type(&key_attr, PSA_KEY_TYPE_ML_DSA_PUBLIC_KEY);

    if (n == 2) { // verify_hash with ML_DSA
        psa_set_key_usage_flags(&key_attr, PSA_KEY_USAGE_VERIFY_HASH);
        TEST_ASSERT(psa_import_key(&key_attr, pub, plen, &pkey) == PSA_SUCCESS);
        TEST_ASSERT(psa_hash_compute(PSA_ALG_SHAKE256_256, message, sizeof message, h, sizeof h, &len) == PSA_SUCCESS);
        TEST_ASSERT(psa_verify_hash(pkey, PSA_ALG_ML_DSA, h, len, sig, slen) == PSA_ERROR_INVALID_ARGUMENT);
        goto abort;
    } else if (n == 4) { // verify_hash with DETERMINISTIC_ML_DSA
        psa_set_key_algorithm(&key_attr, PSA_ALG_DETERMINISTIC_ML_DSA);
        psa_set_key_usage_flags(&key_attr, PSA_KEY_USAGE_VERIFY_HASH);
        TEST_ASSERT(psa_import_key(&key_attr, pub, plen, &pkey) == PSA_SUCCESS);
        TEST_ASSERT(psa_hash_compute(PSA_ALG_SHAKE256_256, message, sizeof message, h, sizeof h, &len) == PSA_SUCCESS);
        TEST_ASSERT(psa_verify_hash(pkey, PSA_ALG_DETERMINISTIC_ML_DSA, h, len, sig, slen) == PSA_ERROR_INVALID_ARGUMENT);
        goto abort;
    } else if (n == 9) { // verify_message with wrong context length
        psa_set_key_usage_flags(&key_attr, PSA_KEY_USAGE_VERIFY_MESSAGE);
        TEST_ASSERT(psa_import_key(&key_attr, pub, plen, &pkey) == PSA_SUCCESS);
        TEST_ASSERT(psa_verify_message_with_context(pkey, PSA_ALG_ML_DSA, message, sizeof message, ctxStr, 512, sig, slen) == PSA_ERROR_INVALID_ARGUMENT);
        goto abort;
    } else if (n == 10) { // verify_hash with wrong context length
        psa_set_key_usage_flags(&key_attr, PSA_KEY_USAGE_VERIFY_HASH);
        TEST_ASSERT(psa_import_key(&key_attr, pub, plen, &pkey) == PSA_SUCCESS);
        TEST_ASSERT(psa_hash_compute(PSA_ALG_SHAKE256_256, message, sizeof message, h, sizeof h, &len) == PSA_SUCCESS);
        TEST_ASSERT(psa_verify_hash_with_context(pkey, PSA_ALG_ML_DSA, h, len, ctxStr, 512, sig, slen) == PSA_ERROR_INVALID_ARGUMENT);
        goto abort;
    } else {
        psa_set_key_usage_flags(&key_attr, PSA_KEY_USAGE_VERIFY_MESSAGE);
        TEST_ASSERT(psa_import_key(&key_attr, pub, plen, &pkey) == PSA_SUCCESS);
        TEST_ASSERT(psa_verify_message(pkey, PSA_ALG_ML_DSA, message, sizeof message, sig, slen) == PSA_SUCCESS);
    }

abort:
    oberon_test_xof_config(0, 0);
    psa_destroy_key(key);
    psa_destroy_key(pkey);
    psa_destroy_key(dkey);
    return 1;
exit:
    oberon_test_xof_config(0, 0);
    psa_destroy_key(key);
    psa_destroy_key(pkey);
    psa_destroy_key(dkey);
    return 0;
}
#endif /* PSA_WANT_ALG_ML_DSA || PSA_WANT_ALG_DETERMINISTIC_ML_DSA || PSA_WANT_ALG_HASH_ML_DSA || PSA_WANT_ALG_DETERMINISTIC_HASH_ML_DSA */

#if defined(PSA_WANT_ALG_DETERMINISTIC_HASH_ML_DSA)
static int test_ct0_rejection() // ML-DSA-44 only
{
    psa_key_attributes_t key_attr = PSA_KEY_ATTRIBUTES_INIT;
    psa_algorithm_t alg = PSA_ALG_DETERMINISTIC_HASH_ML_DSA(PSA_ALG_SHAKE256_512);
    uint8_t hash[32], sig[ML_DSA44_SIG_SIZE];
    psa_key_id_t key = 0;
    size_t len, sig_len;
    int res = 0;

    psa_set_key_usage_flags(&key_attr, PSA_KEY_USAGE_SIGN_HASH | PSA_KEY_USAGE_VERIFY_HASH);
    psa_set_key_algorithm(&key_attr, alg);
    psa_set_key_type(&key_attr, PSA_KEY_TYPE_ML_DSA_KEY_PAIR);
    psa_set_key_bits(&key_attr, 128);
    TEST_ASSERT(psa_import_key(&key_attr, ct0_seed, sizeof ct0_seed, &key) == PSA_SUCCESS);
    TEST_ASSERT(psa_sign_hash(key, alg, ct0_hash, sizeof ct0_hash, sig, sizeof sig, &sig_len) == PSA_SUCCESS);
    TEST_ASSERT(psa_verify_hash(key, alg, ct0_hash, sizeof ct0_hash, sig, sig_len) == PSA_SUCCESS);
    psa_hash_compute(PSA_ALG_SHAKE128_256, sig, sig_len, hash, sizeof hash, &len);
    ASSERT_COMPARE(hash, len, ct0_sig, sizeof ct0_sig);

    res = 1;
exit:
    psa_destroy_key(key);
    return res;
}
#endif /* PSA_WANT_ALG_DETERMINISTIC_HASH_ML_DSA */

#if defined(PSA_WANT_ALG_ML_DSA)
static int test_accumulated_dsa(int k)
{
    psa_xof_operation_t in_op = PSA_XOF_OPERATION_INIT;
    psa_xof_operation_t out_op = PSA_XOF_OPERATION_INIT;
    psa_key_attributes_t key_attr = PSA_KEY_ATTRIBUTES_INIT;
    uint8_t pk[ML_DSA87_PK_SIZE], sig[ML_DSA87_SIG_SIZE];
    uint8_t msg[32], ct[10], rnd[32];
    psa_key_id_t key = 0;
    size_t pk_len, sig_len;
    int i, res = 0;

    psa_set_key_usage_flags(&key_attr, PSA_KEY_USAGE_SIGN_MESSAGE | PSA_KEY_USAGE_VERIFY_MESSAGE);
    psa_set_key_algorithm(&key_attr, PSA_ALG_ML_DSA);
    psa_set_key_type(&key_attr, PSA_KEY_TYPE_ML_DSA_KEY_PAIR);
    psa_set_key_bits(&key_attr, (k + 2) * 64);

    TEST_ASSERT(psa_xof_setup(&in_op, PSA_ALG_SHAKE128) == PSA_SUCCESS);
    switch (k) {
    case 0: TEST_ASSERT(psa_xof_update(&in_op, accu_inp_44, 4) == PSA_SUCCESS); break;
    case 1: TEST_ASSERT(psa_xof_update(&in_op, accu_inp_65, 4) == PSA_SUCCESS); break;
    case 2: TEST_ASSERT(psa_xof_update(&in_op, accu_inp_87, 4) == PSA_SUCCESS); break;
    }
    TEST_ASSERT(psa_xof_setup(&out_op, PSA_ALG_SHAKE128) == PSA_SUCCESS);
    for (i = 0; i < 100; i++) {
        TEST_ASSERT(psa_xof_output(&in_op, rnd, 32) == PSA_SUCCESS);
        TEST_ASSERT(psa_import_key(&key_attr, rnd, 32, &key) == PSA_SUCCESS);
        TEST_ASSERT(psa_export_public_key(key, pk, sizeof pk, &pk_len) == PSA_SUCCESS);
        TEST_ASSERT(psa_xof_update(&out_op, pk, pk_len) == PSA_SUCCESS);
        TEST_ASSERT(psa_xof_output(&in_op, msg, 32) == PSA_SUCCESS);
        TEST_ASSERT(psa_xof_output(&in_op, ct, 10) == PSA_SUCCESS);
        TEST_ASSERT(psa_xof_output(&in_op, rnd, 32) == PSA_SUCCESS);
        oberon_test_drbg_setup(rnd, 32);
        TEST_ASSERT(psa_sign_message_with_context(key, PSA_ALG_ML_DSA, msg, 32, ct, 10, sig, sizeof sig, &sig_len) == PSA_SUCCESS);
        TEST_ASSERT(psa_xof_update(&out_op, sig, sig_len) == PSA_SUCCESS);
        TEST_ASSERT(psa_verify_message_with_context(key, PSA_ALG_ML_DSA, msg, 32, ct, 10, sig, sig_len) == PSA_SUCCESS);
        psa_destroy_key(key);
    }
    TEST_ASSERT(psa_xof_output(&out_op, rnd, 32) == PSA_SUCCESS);
    switch (k) {
    case 0: ASSERT_COMPARE(rnd, 32, accu_dsa_44, sizeof accu_dsa_44); break;
    case 1: ASSERT_COMPARE(rnd, 32, accu_dsa_65, sizeof accu_dsa_65); break;
    case 2: ASSERT_COMPARE(rnd, 32, accu_dsa_87, sizeof accu_dsa_87); break;
    }

    res = 1;
exit:
    TEST_ASSERT(psa_xof_abort(&in_op) == PSA_SUCCESS);
    TEST_ASSERT(psa_xof_abort(&out_op) == PSA_SUCCESS);
    psa_destroy_key(key);
    return res;
}
#endif /* PSA_WANT_ALG_ML_DSA */


static const uint8_t data[16] = {0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15};

int test_wrong_context()
{
    psa_key_attributes_t key_attr = PSA_KEY_ATTRIBUTES_INIT;
    psa_key_id_t key = 0;
    uint8_t h[64], sig[65];
    size_t hlen, slen;
    psa_algorithm_t alg;

    // illegal context
    alg = PSA_ALG_ECDSA(PSA_ALG_SHA_256);
    psa_set_key_type(&key_attr, PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_SECP_R1));
    psa_set_key_bits(&key_attr, 256);
    psa_set_key_algorithm(&key_attr, alg);
    psa_set_key_usage_flags(&key_attr, PSA_KEY_USAGE_SIGN_MESSAGE | PSA_KEY_USAGE_VERIFY_MESSAGE | PSA_KEY_USAGE_SIGN_HASH | PSA_KEY_USAGE_VERIFY_HASH);
#if defined(PSA_WANT_ALG_ECDSA) && defined(PSA_WANT_ALG_SHA_256)
    TEST_ASSERT(psa_generate_key(&key_attr, &key) == PSA_SUCCESS);
    TEST_ASSERT(psa_sign_message_with_context(key, alg, data, sizeof data, data, 4, sig, sizeof sig, &slen) == PSA_ERROR_INVALID_ARGUMENT);
    TEST_ASSERT(psa_sign_message_with_context(key, alg, data, sizeof data, data, 0, sig, sizeof sig, &slen) == PSA_SUCCESS);
    TEST_ASSERT(psa_verify_message_with_context(key, alg, data, sizeof data, data, 4, sig, slen) == PSA_ERROR_INVALID_ARGUMENT);
    TEST_ASSERT(psa_verify_message_with_context(key, alg, data, sizeof data, data, 0, sig, slen) == PSA_SUCCESS);
    TEST_ASSERT(psa_hash_compute(PSA_ALG_SHA_256, data, sizeof data, h, sizeof h, &hlen) == PSA_SUCCESS);
    TEST_ASSERT(psa_sign_hash_with_context(key, alg, h, hlen, data, 4, sig, sizeof sig, &slen) == PSA_ERROR_INVALID_ARGUMENT);
    TEST_ASSERT(psa_sign_hash_with_context(key, alg, h, hlen, data, 0, sig, sizeof sig, &slen) == PSA_SUCCESS);
    TEST_ASSERT(psa_verify_hash_with_context(key, alg, h, hlen, data, 4, sig, slen) == PSA_ERROR_INVALID_ARGUMENT);
    TEST_ASSERT(psa_verify_hash_with_context(key, alg, h, hlen, data, 0, sig, slen) == PSA_SUCCESS);
#endif
    psa_destroy_key(key);

    // not implemented context
    alg = PSA_ALG_ED25519PH;
    psa_set_key_type(&key_attr, PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_TWISTED_EDWARDS));
    psa_set_key_bits(&key_attr, 255);
    psa_set_key_algorithm(&key_attr, alg);
#if defined(PSA_WANT_ALG_ED25519PH) && defined(PSA_WANT_ALG_SHA_512)
    TEST_ASSERT(psa_generate_key(&key_attr, &key) == PSA_SUCCESS);
    TEST_ASSERT(psa_sign_message_with_context(key, alg, data, sizeof data, data, 4, sig, sizeof sig, &slen) == PSA_ERROR_NOT_SUPPORTED);
    TEST_ASSERT(psa_sign_message_with_context(key, alg, data, sizeof data, data, 0, sig, sizeof sig, &slen) == PSA_SUCCESS);
    TEST_ASSERT(psa_verify_message_with_context(key, alg, data, sizeof data, data, 4, sig, slen) == PSA_ERROR_NOT_SUPPORTED);
    TEST_ASSERT(psa_verify_message_with_context(key, alg, data, sizeof data, data, 0, sig, slen) == PSA_SUCCESS);
    TEST_ASSERT(psa_hash_compute(PSA_ALG_SHA_512, data, sizeof data, h, sizeof h, &hlen) == PSA_SUCCESS);
    TEST_ASSERT(psa_sign_hash_with_context(key, alg, h, hlen, data, 4, sig, sizeof sig, &slen) == PSA_ERROR_NOT_SUPPORTED);
    TEST_ASSERT(psa_sign_hash_with_context(key, alg, h, hlen, data, 0, sig, sizeof sig, &slen) == PSA_SUCCESS);
    TEST_ASSERT(psa_verify_hash_with_context(key, alg, h, hlen, data, 4, sig, slen) == PSA_ERROR_NOT_SUPPORTED);
    TEST_ASSERT(psa_verify_hash_with_context(key, alg, h, hlen, data, 0, sig, slen) == PSA_SUCCESS);
#endif
    psa_destroy_key(key);

    return 1;
exit:
    psa_destroy_key(key);
    (void)h;
    (void)sig;
    (void)hlen;
    (void)slen;
    return 0;
}

#ifdef PSA_WANT_ALG_ML_KEM

static const uint8_t kem_rnd[64] = {
    0x6D, 0xBB, 0xC4, 0x37, 0x51, 0x36, 0xDF, 0x3B, 0x07, 0xF7, 0xC7, 0x0E, 0x63, 0x9E, 0x22, 0x3E,
    0x17, 0x7E, 0x7F, 0xD5, 0x3B, 0x16, 0x1B, 0x3F, 0x4D, 0x57, 0x79, 0x17, 0x94, 0xF1, 0x26, 0x24,
    0xF6, 0x96, 0x48, 0x40, 0x48, 0xEC, 0x21, 0xF9, 0x6C, 0xF5, 0x0A, 0x56, 0xD0, 0x75, 0x9C, 0x44,
    0x8F, 0x37, 0x79, 0x75, 0x2F, 0x03, 0x83, 0xD3, 0x74, 0x49, 0x69, 0x06, 0x94, 0xCF, 0x7A, 0x68};
static const uint8_t kem_msg[] = {
    0x20, 0xA7, 0xB7, 0xE1, 0x0F, 0x70, 0x49, 0x6C, 0xC3, 0x82, 0x20, 0xB9, 0x44, 0xDE, 0xF6, 0x99,
    0xBF, 0x14, 0xD1, 0x4E, 0x55, 0xCF, 0x4C, 0x90, 0xA1, 0x2C, 0x1B, 0x33, 0xFC, 0x80, 0xFF, 0xFF};

static const uint8_t pk_512[] = {
    0x7e, 0xe3, 0xdb, 0x7f, 0xc8, 0x21, 0x91, 0x7d, 0x98, 0xbc, 0x5d, 0x53, 0xc0, 0x1f, 0xe7, 0xbd,
    0x92, 0xc2, 0xb9, 0xd6, 0x77, 0x52, 0xeb, 0x62, 0xc5, 0xac, 0x40, 0xf1, 0xd1, 0x85, 0xb8, 0x2c};
static const uint8_t ct_512[] = {
    0x54, 0x2d, 0x53, 0xb6, 0x4a, 0xec, 0x25, 0xc6, 0xc1, 0xaa, 0xd9, 0xae, 0x41, 0xf8, 0xbf, 0x62,
    0x20, 0x34, 0xaf, 0x61, 0x73, 0x36, 0x31, 0x76, 0xd0, 0x88, 0x05, 0xdf, 0x6c, 0x8f, 0x24, 0x72};
static const uint8_t ss_512[] = {
    0x2b, 0x5c, 0x52, 0xee, 0x72, 0x94, 0x63, 0x31, 0x98, 0x3b, 0xa0, 0x50, 0xbe, 0x0f, 0x43, 0x50,
    0x55, 0xc0, 0x54, 0x79, 0x01, 0xe0, 0x35, 0x59, 0xb3, 0x56, 0x51, 0x78, 0x89, 0xea, 0x27, 0xc5};
static const uint8_t es_512[] = {
    0x93, 0x7f, 0xa9, 0xe2, 0x54, 0xea, 0x46, 0x81, 0x2a, 0x05, 0x82, 0x53, 0x41, 0xaf, 0x57, 0xdf,
    0x9b, 0xef, 0xae, 0xe2, 0x6c, 0x61, 0x69, 0xf8, 0x21, 0x41, 0x6d, 0xb3, 0xde, 0xbf, 0xfe, 0xb9};
static const uint8_t pk_768[] = {
    0xfd, 0xec, 0x3f, 0x7c, 0x6b, 0x0b, 0x82, 0xdb, 0x46, 0x4c, 0x8b, 0x2b, 0x2b, 0xc6, 0x4c, 0xd5,
    0x84, 0xdf, 0xe3, 0x2f, 0x5a, 0x0f, 0xd3, 0x18, 0x04, 0xa9, 0x71, 0xfa, 0xc1, 0xac, 0xd1, 0xe6};
static const uint8_t ct_768[] = {
    0x93, 0x18, 0x87, 0xba, 0x32, 0x29, 0xe5, 0x3d, 0xad, 0xcd, 0x86, 0xd0, 0x6c, 0x54, 0x3b, 0xfc,
    0x78, 0x8d, 0x25, 0x78, 0x3c, 0xb2, 0x18, 0x86, 0x1f, 0x92, 0x31, 0x21, 0x7e, 0x51, 0x96, 0xcb};
static const uint8_t ss_768[] = {
    0xb4, 0x08, 0xd5, 0xd1, 0x15, 0x71, 0x3f, 0x0a, 0x93, 0x04, 0x7d, 0xbb, 0xea, 0x83, 0x2e, 0x43,
    0x40, 0x78, 0x76, 0x86, 0xd5, 0x9a, 0x9a, 0x2d, 0x10, 0x6b, 0xd6, 0x62, 0xba, 0x0a, 0xa0, 0x35};
static const uint8_t es_768[] = {
    0x4b, 0xca, 0x15, 0x72, 0x3c, 0x66, 0xb7, 0x2f, 0xe5, 0x9c, 0x6a, 0xdc, 0x05, 0x3e, 0xfd, 0xea,
    0xd0, 0x0a, 0x5c, 0x7b, 0x9b, 0xe4, 0x90, 0x08, 0x32, 0xf6, 0x8e, 0xcd, 0xce, 0xf6, 0x70, 0xac};
static const uint8_t pk_1024[] = {
    0x41, 0x7d, 0x08, 0x4c, 0xe9, 0xaf, 0xb0, 0x7a, 0x06, 0x48, 0x8b, 0x4c, 0xe4, 0x44, 0x17, 0x7d,
    0x45, 0x20, 0xd5, 0xdb, 0xdc, 0xd1, 0x54, 0x1a, 0x63, 0xba, 0xf6, 0xe2, 0xb2, 0x88, 0x75, 0x2a};
static const uint8_t ct_1024[] = {
    0x77, 0xb4, 0xda, 0x4a, 0x79, 0x30, 0xcc, 0x7d, 0x14, 0x3b, 0x9e, 0xeb, 0xe1, 0x8e, 0x3b, 0x72,
    0x77, 0x7f, 0xb0, 0x08, 0xe2, 0x17, 0x9a, 0x11, 0xca, 0xb2, 0xd3, 0x85, 0xbd, 0x06, 0xc2, 0x3d};
static const uint8_t ss_1024[] = {
    0x23, 0xf2, 0x11, 0xb8, 0x4a, 0x6e, 0xe2, 0x0c, 0x8c, 0x29, 0xf6, 0xe5, 0x31, 0x4c, 0x91, 0xb4,
    0x14, 0xe9, 0x40, 0x51, 0x3d, 0x38, 0x0a, 0xdd, 0x17, 0xbd, 0x72, 0x4a, 0xb3, 0xa1, 0x3a, 0x52};
static const uint8_t es_1024[] = {
    0xe4, 0x87, 0x37, 0x17, 0x3e, 0xb6, 0xd3, 0x03, 0x0a, 0xd0, 0x22, 0xd4, 0xf9, 0x84, 0x86, 0xd9,
    0xed, 0xe2, 0xa5, 0x4f, 0x82, 0xf0, 0x93, 0xaa, 0x51, 0x9c, 0x75, 0x2a, 0x85, 0x6c, 0xb3, 0x87};
// accumulated tests
static const uint8_t accu_kem_512[] = {
    0x82, 0xd4, 0x85, 0x71, 0xc8, 0xf0, 0xaa, 0xe9, 0xe9, 0xba, 0xed, 0x11, 0xbf, 0xe7, 0x84, 0xd4,
    0x93, 0xe4, 0xeb, 0x95, 0x6f, 0xa5, 0x50, 0xb8, 0x5e, 0x78, 0xdb, 0x74, 0xc6, 0xe9, 0xc5, 0xbf};
static const uint8_t accu_kem_768[] = {
    0xa6, 0x07, 0x53, 0x55, 0x0b, 0x34, 0x3a, 0x71, 0x8a, 0xc7, 0x03, 0x30, 0xbc, 0x99, 0x1b, 0x1d,
    0x8a, 0xa6, 0x12, 0x0f, 0x45, 0xfa, 0x73, 0xa5, 0xa2, 0x40, 0xdf, 0xbf, 0x94, 0x28, 0xe6, 0x3f};
static const uint8_t accu_kem_1024[] = {
    0x09, 0xed, 0xcb, 0x5f, 0x1b, 0xc3, 0x16, 0x03, 0x31, 0x5c, 0x51, 0x19, 0xde, 0x52, 0x0c, 0x69,
    0xd3, 0x10, 0x53, 0x59, 0x75, 0xed, 0x4d, 0x57, 0xd3, 0x77, 0x49, 0xb1, 0x2b, 0x80, 0x98, 0x23};

#define ML_KEM512_PK_SIZE  800
#define ML_KEM768_PK_SIZE  1184
#define ML_KEM1024_PK_SIZE 1568
#define ML_KEM512_CT_SIZE  768
#define ML_KEM768_CT_SIZE  1088
#define ML_KEM1024_CT_SIZE 1568

static int test_ml_kem(int n, int k)
{
    psa_key_attributes_t key_attr = PSA_KEY_ATTRIBUTES_INIT;
    psa_key_derivation_operation_t op = PSA_KEY_DERIVATION_OPERATION_INIT;
    psa_key_id_t key = 0, pkey = 0, skey = 0, dkey = 0;
    uint8_t pub[ML_KEM1024_PK_SIZE], ct[ML_KEM1024_CT_SIZE];
    uint8_t h[64], secret1[32], secret2[32];
    size_t clen, plen, slen, len;
    size_t key_size = (k + 2) * 256; // 512, 768, 1024
    size_t pk_size, ct_size;
    int res = 0;

    switch (k) {
    case 0: pk_size = ML_KEM512_PK_SIZE;  ct_size = ML_KEM512_CT_SIZE;  break;
    case 1: pk_size = ML_KEM768_PK_SIZE;  ct_size = ML_KEM768_CT_SIZE;  break;
    case 2: pk_size = ML_KEM1024_PK_SIZE; ct_size = ML_KEM1024_CT_SIZE; break;
    default: goto exit;
    }

    TEST_ASSERT(PSA_EXPORT_KEY_OUTPUT_SIZE(PSA_KEY_TYPE_ML_KEM_KEY_PAIR, key_size) == 64);
    TEST_ASSERT(PSA_EXPORT_KEY_OUTPUT_SIZE(PSA_KEY_TYPE_ML_KEM_PUBLIC_KEY, key_size) == pk_size);
    TEST_ASSERT(PSA_KEY_ENCAPSULATE_CIPHERTEXT_SIZE(PSA_KEY_TYPE_ML_KEM_KEY_PAIR, key_size) == ct_size);

    if (n == 3) {
        oberon_test_xof_config(0, 1); // manipulate XOF to provoke more rejections
        psa_set_key_usage_flags(&key_attr, PSA_KEY_USAGE_DERIVE);
        psa_set_key_algorithm(&key_attr, PSA_ALG_HKDF(PSA_ALG_SHA_256));
        psa_set_key_type(&key_attr, PSA_KEY_TYPE_DERIVE);
        psa_set_key_bits(&key_attr, 256);
        TEST_ASSERT(psa_import_key(&key_attr, kem_rnd, 32, &dkey) == PSA_SUCCESS);
    }

    if (n == 2) {
        psa_set_key_usage_flags(&key_attr, PSA_KEY_USAGE_ENCRYPT | PSA_KEY_USAGE_DECRYPT);
    } else {
        psa_set_key_usage_flags(&key_attr, PSA_KEY_USAGE_DECRYPT | PSA_KEY_USAGE_EXPORT);
    }
    psa_set_key_algorithm(&key_attr, PSA_ALG_ML_KEM);
    psa_set_key_type(&key_attr, PSA_KEY_TYPE_ML_KEM_KEY_PAIR);
    psa_set_key_bits(&key_attr, key_size);
    if (n == 3) {
        TEST_ASSERT(psa_key_derivation_setup(&op, PSA_ALG_HKDF(PSA_ALG_SHA_256)) == PSA_SUCCESS);
        TEST_ASSERT(psa_key_derivation_input_key(&op, PSA_KEY_DERIVATION_INPUT_SECRET, dkey) == PSA_SUCCESS);
        TEST_ASSERT(psa_key_derivation_input_bytes(&op, PSA_KEY_DERIVATION_INPUT_INFO, NULL, 0) == PSA_SUCCESS);
        TEST_ASSERT(psa_key_derivation_output_key(&key_attr, &op, &key) == PSA_SUCCESS);
    } else if (n == 1) {
        oberon_test_drbg_setup(kem_rnd, 64);
        TEST_ASSERT(psa_generate_key(&key_attr, &key) == PSA_SUCCESS);
        TEST_ASSERT(psa_export_key(key, h, sizeof h, &len) == PSA_SUCCESS);
        ASSERT_COMPARE(h, len, kem_rnd, 64);
    } else {
        TEST_ASSERT(psa_import_key(&key_attr, kem_rnd, 64, &key) == PSA_SUCCESS);
    }

    TEST_ASSERT(psa_export_public_key(key, pub, pk_size, &plen) == PSA_SUCCESS);
    if (n != 3) {
        psa_hash_compute(PSA_ALG_SHAKE128_256, pub, plen, h, sizeof h, &len);
        switch (k) {
        case 0: ASSERT_COMPARE(h, len, pk_512, 32); break;
        case 1: ASSERT_COMPARE(h, len, pk_768, 32); break;
        case 2: ASSERT_COMPARE(h, len, pk_1024, 32); break;
        }
    }

    psa_set_key_usage_flags(&key_attr, PSA_KEY_USAGE_ENCRYPT);
    psa_set_key_type(&key_attr, PSA_KEY_TYPE_ML_KEM_PUBLIC_KEY);
    TEST_ASSERT(psa_import_key(&key_attr, pub, plen, &pkey) == PSA_SUCCESS);

    psa_set_key_usage_flags(&key_attr, PSA_KEY_USAGE_ENCRYPT | PSA_KEY_USAGE_EXPORT);
    psa_set_key_algorithm(&key_attr, PSA_ALG_CCM);
    psa_set_key_type(&key_attr, PSA_KEY_TYPE_AES);
    psa_set_key_bits(&key_attr, 0);
    oberon_test_drbg_setup(kem_msg, sizeof kem_msg);
    if (n == 2) {
        TEST_ASSERT(psa_encapsulate(key, PSA_ALG_ML_KEM, &key_attr, &skey, ct, ct_size, &clen) == PSA_SUCCESS);
    } else {
        TEST_ASSERT(psa_encapsulate(pkey, PSA_ALG_ML_KEM, &key_attr, &skey, ct, ct_size, &clen) == PSA_SUCCESS);
    }
    TEST_ASSERT(psa_export_key(skey, secret1, sizeof secret1, &slen) == PSA_SUCCESS);
    TEST_ASSERT(slen == 32);
    if (n != 3) {
        switch (k) {
        case 0: ASSERT_COMPARE(secret1, 32, ss_512, 32); break;
        case 1: ASSERT_COMPARE(secret1, 32, ss_768, 32); break;
        case 2: ASSERT_COMPARE(secret1, 32, ss_1024, 32); break;
        }
        psa_hash_compute(PSA_ALG_SHAKE128_256, ct, clen, h, sizeof h, &len);
        switch (k) {
        case 0: ASSERT_COMPARE(h, len, ct_512, 32); break;
        case 1: ASSERT_COMPARE(h, len, ct_768, 32); break;
        case 2: ASSERT_COMPARE(h, len, ct_1024, 32); break;
        }
    }

    TEST_ASSERT(psa_destroy_key(skey) == PSA_SUCCESS);
    psa_set_key_bits(&key_attr, 256);
    TEST_ASSERT(psa_decapsulate(key, PSA_ALG_ML_KEM, ct, clen, &key_attr, &skey) == PSA_SUCCESS);
    TEST_ASSERT(psa_export_key(skey, secret2, sizeof secret2, &slen) == PSA_SUCCESS);
    TEST_ASSERT(slen == 32);
    switch (k) {
    case 0: ASSERT_COMPARE(secret1, 32, secret2, 32); break;
    case 1: ASSERT_COMPARE(secret1, 32, secret2, 32); break;
    case 2: ASSERT_COMPARE(secret1, 32, secret2, 32); break;
    }
    
    if (n != 3) {
        ct[0]++; // wrong cyphertext
        TEST_ASSERT(psa_destroy_key(skey) == PSA_SUCCESS);
        TEST_ASSERT(psa_decapsulate(key, PSA_ALG_ML_KEM, ct, clen, &key_attr, &skey) == PSA_SUCCESS);
        TEST_ASSERT(psa_export_key(skey, secret2, sizeof secret2, &slen) == PSA_SUCCESS);
        TEST_ASSERT(slen == 32);
        switch (k) {
        case 0: ASSERT_COMPARE(secret2, 32, es_512, 32); break;
        case 1: ASSERT_COMPARE(secret2, 32, es_768, 32); break;
        case 2: ASSERT_COMPARE(secret2, 32, es_1024, 32); break;
        }
    }

    res = 1;
exit:
    oberon_test_xof_config(0, 0);
    TEST_ASSERT(psa_destroy_key(key) == PSA_SUCCESS);
    TEST_ASSERT(psa_destroy_key(pkey) == PSA_SUCCESS);
    TEST_ASSERT(psa_destroy_key(skey) == PSA_SUCCESS);
    TEST_ASSERT(psa_destroy_key(dkey) == PSA_SUCCESS);

    return res;
}

static int test_ml_kem_err(int n, int k)
{
    psa_key_attributes_t key_attr = PSA_KEY_ATTRIBUTES_INIT;
    psa_key_attributes_t attr = PSA_KEY_ATTRIBUTES_INIT;
    psa_key_id_t key = 0, pkey = 0, skey = 0, dkey = 0;
    uint8_t pub[ML_KEM1024_PK_SIZE], ct[ML_KEM1024_CT_SIZE];
    size_t clen, plen;
    size_t key_size = (k + 2) * 256; // 512, 768, 1024
    size_t pk_size, ct_size;

    switch (k) {
    case 0: pk_size = ML_KEM512_PK_SIZE;  ct_size = ML_KEM512_CT_SIZE;  break;
    case 1: pk_size = ML_KEM768_PK_SIZE;  ct_size = ML_KEM768_CT_SIZE;  break;
    case 2: pk_size = ML_KEM1024_PK_SIZE; ct_size = ML_KEM1024_CT_SIZE; break;
    default: goto exit;
    }

    if (n == 1) {
        psa_set_key_usage_flags(&key_attr, PSA_KEY_USAGE_DECRYPT);
    } else if (n == 9) {
        psa_set_key_usage_flags(&key_attr, PSA_KEY_USAGE_ENCRYPT);
    } else {
        psa_set_key_usage_flags(&key_attr, PSA_KEY_USAGE_ENCRYPT | PSA_KEY_USAGE_DECRYPT);
    }
    if (n == 2 || n == 4) {
        psa_set_key_algorithm(&key_attr, PSA_ALG_ML_DSA);
    } else {
        psa_set_key_algorithm(&key_attr, PSA_ALG_ML_KEM);
    }
    psa_set_key_type(&key_attr, PSA_KEY_TYPE_ML_KEM_KEY_PAIR);
    psa_set_key_bits(&key_attr, key_size);
    TEST_ASSERT(psa_import_key(&key_attr, kem_rnd, 64, &key) == PSA_SUCCESS);

    TEST_ASSERT(psa_export_public_key(key, pub, pk_size, &plen) == PSA_SUCCESS);

    if (n == 3) {
        psa_set_key_usage_flags(&key_attr, PSA_KEY_USAGE_DECRYPT);
    } else {
        psa_set_key_usage_flags(&key_attr, PSA_KEY_USAGE_ENCRYPT);
    }
    psa_set_key_type(&key_attr, PSA_KEY_TYPE_ML_KEM_PUBLIC_KEY);
    TEST_ASSERT(psa_import_key(&key_attr, pub, plen, &pkey) == PSA_SUCCESS);

    psa_set_key_usage_flags(&key_attr, PSA_KEY_USAGE_ENCRYPT | PSA_KEY_USAGE_EXPORT);
    if (n == 6) {
        psa_set_key_algorithm(&key_attr, PSA_ALG_RSA_PKCS1V15_CRYPT);
        psa_set_key_type(&key_attr, PSA_KEY_TYPE_RSA_KEY_PAIR);
    } else {
        psa_set_key_algorithm(&key_attr, PSA_ALG_CCM);
        psa_set_key_type(&key_attr, PSA_KEY_TYPE_AES);
    }
    if (n == 7) {
        psa_set_key_bits(&key_attr, 7);
    } else {
        psa_set_key_bits(&key_attr, 0);
    }
    oberon_test_drbg_setup(kem_msg, sizeof kem_msg);
    if (n == 1) { // key does not permit encrypt
        TEST_ASSERT(psa_encapsulate(key, PSA_ALG_ML_KEM, &key_attr, &skey, ct, ct_size, &clen) == PSA_ERROR_NOT_PERMITTED);
        goto abort;
    } else if (n == 2) { // not permitted algorithm 
        TEST_ASSERT(psa_encapsulate(key, PSA_ALG_ML_KEM, &key_attr, &skey, ct, ct_size, &clen) == PSA_ERROR_NOT_PERMITTED);
        goto abort;
    } else if (n == 3) { // key does not permit encrypt 
        TEST_ASSERT(psa_encapsulate(pkey, PSA_ALG_ML_KEM, &key_attr, &skey, ct, ct_size, &clen) == PSA_ERROR_NOT_PERMITTED);
        goto abort;
    } else if (n == 4) { // not permitted algorithm 
        TEST_ASSERT(psa_encapsulate(pkey, PSA_ALG_ML_KEM, &key_attr, &skey, ct, ct_size, &clen) == PSA_ERROR_NOT_PERMITTED);
        goto abort;
    } else if (n == 5) { // wrong algorithm 
        TEST_ASSERT(psa_encapsulate(pkey, PSA_ALG_ML_DSA, &key_attr, &skey, ct, ct_size, &clen) == PSA_ERROR_INVALID_ARGUMENT);
        goto abort;
    } else if (n == 6) { // wrong output key type 
        TEST_ASSERT(psa_encapsulate(pkey, PSA_ALG_ML_KEM, &key_attr, &skey, ct, ct_size, &clen) == PSA_ERROR_INVALID_ARGUMENT);
        goto abort;
    } else if (n == 7) { // wrong output key size 
        TEST_ASSERT(psa_encapsulate(pkey, PSA_ALG_ML_KEM, &key_attr, &skey, ct, ct_size, &clen) == PSA_ERROR_INVALID_ARGUMENT);
        goto abort;
    } else if (n == 8) { // buffer too small 
        TEST_ASSERT(psa_encapsulate(pkey, PSA_ALG_ML_KEM, &key_attr, &skey, ct, ct_size - 1, &clen) == PSA_ERROR_BUFFER_TOO_SMALL);
        goto abort;
    } else {
        TEST_ASSERT(psa_encapsulate(pkey, PSA_ALG_ML_KEM, &key_attr, &skey, ct, ct_size, &clen) == PSA_SUCCESS);
    }
    TEST_ASSERT(psa_destroy_key(skey) == PSA_SUCCESS);

    if (n == 9) { // key does not permit decrypt
        TEST_ASSERT(psa_decapsulate(key, PSA_ALG_ML_KEM, ct, clen, &key_attr, &skey) == PSA_ERROR_NOT_PERMITTED);
        goto abort;
    } else if (n == 10) { // not permitted algorithm 
        psa_set_key_usage_flags(&attr, PSA_KEY_USAGE_ENCRYPT | PSA_KEY_USAGE_DECRYPT);
        psa_set_key_algorithm(&attr, PSA_ALG_ML_DSA);
        psa_set_key_type(&attr, PSA_KEY_TYPE_ML_KEM_KEY_PAIR);
        psa_set_key_bits(&attr, key_size);
        TEST_ASSERT(psa_import_key(&attr, kem_rnd, 64, &key) == PSA_SUCCESS);
        TEST_ASSERT(psa_decapsulate(key, PSA_ALG_ML_KEM, ct, clen, &key_attr, &skey) == PSA_ERROR_NOT_PERMITTED);
        goto abort;
    } else if (n == 11) { // wrong algorithm 
        TEST_ASSERT(psa_decapsulate(key, PSA_ALG_ML_DSA, ct, clen, &key_attr, &skey) == PSA_ERROR_INVALID_ARGUMENT);
        goto abort;
    } else if (n == 12) { // wrong output key type 
        psa_set_key_algorithm(&key_attr, PSA_ALG_RSA_PKCS1V15_CRYPT);
        psa_set_key_type(&key_attr, PSA_KEY_TYPE_RSA_KEY_PAIR);
        TEST_ASSERT(psa_decapsulate(key, PSA_ALG_ML_KEM, ct, clen, &key_attr, &skey) == PSA_ERROR_INVALID_ARGUMENT);
        goto abort;
    } else if (n == 13) { // wrong output key size 
        psa_set_key_bits(&key_attr, 7);
        TEST_ASSERT(psa_decapsulate(key, PSA_ALG_ML_KEM, ct, clen, &key_attr, &skey) == PSA_ERROR_INVALID_ARGUMENT);
        goto abort;
    } else if (n == 14) { // wrong ciphertext size 
        TEST_ASSERT(psa_decapsulate(key, PSA_ALG_ML_KEM, ct, clen - 1, &key_attr, &skey) == PSA_ERROR_INVALID_ARGUMENT);
        goto abort;
    } else {
        TEST_ASSERT(psa_decapsulate(key, PSA_ALG_ML_KEM, ct, clen, &key_attr, &skey) == PSA_SUCCESS);
    }

abort:
    oberon_test_xof_config(0, 0);
    psa_destroy_key(key);
    psa_destroy_key(pkey);
    psa_destroy_key(skey);
    psa_destroy_key(dkey);
    return 1;
exit:
    oberon_test_xof_config(0, 0);
    psa_destroy_key(key);
    psa_destroy_key(pkey);
    psa_destroy_key(skey);
    psa_destroy_key(dkey);
    return 0;
}

static int test_accumulated_kem(int k)
{
    psa_xof_operation_t in_op = PSA_XOF_OPERATION_INIT;
    psa_xof_operation_t out_op = PSA_XOF_OPERATION_INIT;
    psa_key_attributes_t key_attr = PSA_KEY_ATTRIBUTES_INIT;
    psa_key_attributes_t ss_attr = PSA_KEY_ATTRIBUTES_INIT;
    uint8_t pk[ML_KEM1024_PK_SIZE], ct[ML_KEM1024_CT_SIZE];
    uint8_t rnd[64], ss[32], ss2[32];
    psa_key_id_t key = 0, skey = 0;
    size_t pk_len, ct_len, ss_len, ss2_len;
    int i, res = 0;

    psa_set_key_usage_flags(&key_attr, PSA_KEY_USAGE_ENCRYPT | PSA_KEY_USAGE_DECRYPT);
    psa_set_key_algorithm(&key_attr, PSA_ALG_ML_KEM);
    psa_set_key_type(&key_attr, PSA_KEY_TYPE_ML_KEM_KEY_PAIR);
    psa_set_key_bits(&key_attr, (k + 2) * 256);
    psa_set_key_usage_flags(&ss_attr, PSA_KEY_USAGE_ENCRYPT | PSA_KEY_USAGE_EXPORT);
    psa_set_key_algorithm(&ss_attr, PSA_ALG_CCM);
    psa_set_key_type(&ss_attr, PSA_KEY_TYPE_AES);
    psa_set_key_bits(&ss_attr, 0);

    TEST_ASSERT(psa_xof_setup(&in_op, PSA_ALG_SHAKE128) == PSA_SUCCESS);
    TEST_ASSERT(psa_xof_setup(&out_op, PSA_ALG_SHAKE128) == PSA_SUCCESS);
    for (i = 0; i < 100; i++) {
        TEST_ASSERT(psa_xof_output(&in_op, rnd, 64) == PSA_SUCCESS);
        TEST_ASSERT(psa_import_key(&key_attr, rnd, 64, &key) == PSA_SUCCESS);
        TEST_ASSERT(psa_export_public_key(key, pk, sizeof pk, &pk_len) == PSA_SUCCESS);
        TEST_ASSERT(psa_xof_update(&out_op, pk, pk_len) == PSA_SUCCESS);
        TEST_ASSERT(psa_xof_output(&in_op, rnd, 32) == PSA_SUCCESS);
        oberon_test_drbg_setup(rnd, 32);
        TEST_ASSERT(psa_encapsulate(key, PSA_ALG_ML_KEM, &ss_attr, &skey, ct, sizeof ct, &ct_len) == PSA_SUCCESS);
        TEST_ASSERT(psa_xof_update(&out_op, ct, ct_len) == PSA_SUCCESS);
        TEST_ASSERT(psa_export_key(skey, ss, sizeof ss, &ss_len) == PSA_SUCCESS);
        TEST_ASSERT(psa_xof_update(&out_op, ss, ss_len) == PSA_SUCCESS);
        psa_destroy_key(skey);
        TEST_ASSERT(psa_decapsulate(key, PSA_ALG_ML_KEM, ct, ct_len, &ss_attr, &skey) == PSA_SUCCESS);
        TEST_ASSERT(psa_export_key(skey, ss2, sizeof ss2, &ss2_len) == PSA_SUCCESS);
        ASSERT_COMPARE(ss2, ss2_len, ss, ss_len);
        psa_destroy_key(skey);
        ct[0]++; // wrong ciphertext
        TEST_ASSERT(psa_decapsulate(key, PSA_ALG_ML_KEM, ct, ct_len, &ss_attr, &skey) == PSA_SUCCESS);
        TEST_ASSERT(psa_export_key(skey, ss2, sizeof ss2, &ss2_len) == PSA_SUCCESS);
        TEST_ASSERT(psa_xof_update(&out_op, ss2, ss2_len) == PSA_SUCCESS);
        psa_destroy_key(key);
        psa_destroy_key(skey);
    }
    TEST_ASSERT(psa_xof_output(&out_op, rnd, 32) == PSA_SUCCESS);
    switch (k) {
    case 0: ASSERT_COMPARE(rnd, 32, accu_kem_512, sizeof accu_kem_512); break;
    case 1: ASSERT_COMPARE(rnd, 32, accu_kem_768, sizeof accu_kem_768); break;
    case 2: ASSERT_COMPARE(rnd, 32, accu_kem_1024, sizeof accu_kem_1024); break;
    }

    res = 1;
exit:
    TEST_ASSERT(psa_xof_abort(&in_op) == PSA_SUCCESS);
    TEST_ASSERT(psa_xof_abort(&out_op) == PSA_SUCCESS);
    psa_destroy_key(key);
    psa_destroy_key(skey);
    return res;
}
#endif /* PSA_WANT_ALG_ML_KEM */


int main(void)
{
    int i, k;

    TEST_ASSERT(psa_crypto_init() == PSA_SUCCESS);

#if defined(PSA_WANT_ALG_ML_DSA) || defined(PSA_WANT_ALG_DETERMINISTIC_ML_DSA)
    for (k = 0; k < 3; k++) {
        for (i = 0; i <= 5; i++) {
            TEST_ASSERT(test_ml_dsa(i, k));
        }
        for (i = 0; i <= 10; i++) {
            TEST_ASSERT(test_ml_dsa_err(i, k));
        }
    }
#endif

#if defined(PSA_WANT_ALG_HASH_ML_DSA) || defined(PSA_WANT_ALG_DETERMINISTIC_HASH_ML_DSA)
    for (k = 0; k < 3; k++) {
        for (i = 6; i <= 10; i++) {
            TEST_ASSERT(test_ml_dsa(i, k));
        }
    }
#endif

#if defined(PSA_WANT_ALG_DETERMINISTIC_HASH_ML_DSA)
    TEST_ASSERT(test_ct0_rejection());
#endif

#if defined(PSA_WANT_ALG_ML_DSA)
    for (k = 0; k < 3; k++) {
        TEST_ASSERT(test_accumulated_dsa(k));
    }
#endif

#ifdef PSA_WANT_ALG_ML_KEM
    for (k = 0; k < 3; k++) {
        for (i = 0; i <= 3; i++) {
            TEST_ASSERT(test_ml_kem(i, k));
        }
        for (i = 0; i <= 14; i++) {
            TEST_ASSERT(test_ml_kem_err(i, k));
        }
        TEST_ASSERT(test_accumulated_kem(k));
    }
#endif

    TEST_ASSERT(test_wrong_context());

return 0;
exit:
    (void)i;
    (void)k;
    return 1;
}
