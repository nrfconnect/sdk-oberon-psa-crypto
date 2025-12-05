/*
 *  Copyright Oberon microsystems AG, Switzerland
 *  SPDX-License-Identifier: Apache-2.0
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
 * These tests use the oberon_test_drbg to inject specific random bytes.
 */


#include <string.h>

#include "psa/crypto.h"
#include <test/helpers.h>
#include <test/macros.h>
#include "oberon_test_drbg.h"


#if defined(PSA_WANT_ALG_ML_DSA) || defined(PSA_WANT_ALG_DETERMINISTIC_ML_DSA) || \
    defined(PSA_WANT_ALG_HASH_ML_DSA) || defined(PSA_WANT_ALG_DETERMINISTIC_HASH_ML_DSA)

// Test vectors from KAT/MLDSA

static const uint8_t seed[32] = {
    0xF6, 0x96, 0x48, 0x40, 0x48, 0xEC, 0x21, 0xF9, 0x6C, 0xF5, 0x0A, 0x56, 0xD0, 0x75, 0x9C, 0x44,
    0x8F, 0x37, 0x79, 0x75, 0x2F, 0x03, 0x83, 0xD3, 0x74, 0x49, 0x69, 0x06, 0x94, 0xCF, 0x7A, 0x68};
static const uint8_t rnd[32] = {
    0xdf, 0xa7, 0x32, 0x9c, 0xd1, 0xc3, 0xf4, 0xd8, 0xff, 0x75, 0xbd, 0xe1, 0x9e, 0xba, 0x5d, 0xc8,
    0x42, 0x22, 0x9e, 0xf5, 0xcb, 0x12, 0xc6, 0x76, 0xea, 0x6f, 0xcc, 0x7c, 0x08, 0xe9, 0xec, 0xab};
static const uint8_t msg[] = {
    0x6D, 0xBB, 0xC4, 0x37, 0x51, 0x36, 0xDF, 0x3B, 0x07, 0xF7, 0xC7, 0x0E, 0x63, 0x9E, 0x22, 0x3E};
static const uint8_t ctx[16] = "ThisIsTheContext";


static const uint8_t pk_44[] = {
    0x18, 0x28, 0x82, 0x49, 0xb9, 0x0b, 0xcb, 0xd4, 0x8d, 0x47, 0x3d, 0x2a, 0x50, 0x7c, 0xc3, 0xc1,
    0xe9, 0x5e, 0x04, 0x0f, 0x63, 0x9a, 0xc3, 0x33, 0x3a, 0x8e, 0xd1, 0x89, 0x1d, 0xe1, 0x45, 0x52};
static const uint8_t sig_44[] = {
    0x1e, 0xb3, 0xe7, 0xa9, 0xaf, 0xc0, 0x64, 0xed, 0x33, 0xb0, 0xb2, 0x7b, 0x42, 0x25, 0x9f, 0x82,
    0x8a, 0x16, 0x8e, 0x7e, 0xd2, 0xa1, 0xc2, 0xfd, 0x66, 0xb3, 0x72, 0xee, 0x38, 0x57, 0x5c, 0xf7};
static const uint8_t sigD_44[] = {
    0xed, 0xe9, 0xfa, 0xf0, 0x5e, 0xd9, 0x6d, 0xbe, 0xcd, 0xf8, 0xeb, 0xc3, 0x31, 0xd9, 0x38, 0xf2,
    0xd5, 0x63, 0x48, 0x19, 0x7a, 0x07, 0xc6, 0x2d, 0x68, 0x55, 0x54, 0xb3, 0x09, 0xdd, 0x92, 0x97};
static const uint8_t sigH_44[] = {
    0xb8, 0x88, 0x08, 0xaf, 0x94, 0x6b, 0x5a, 0x16, 0x41, 0xa9, 0xdf, 0x60, 0x62, 0xc3, 0xb2, 0x6b,
    0x35, 0x39, 0xd7, 0xe4, 0x0f, 0x80, 0xae, 0x64, 0x20, 0x26, 0xe6, 0xe8, 0x0f, 0x2d, 0xe5, 0x76};
static const uint8_t sigHD_44[] = {
    0x3a, 0xf0, 0x48, 0xb9, 0x03, 0x1c, 0x53, 0x11, 0xef, 0x91, 0x11, 0xa7, 0x10, 0xd0, 0xa2, 0x24,
    0x7b, 0xdb, 0x19, 0x54, 0x90, 0xa2, 0x1a, 0xf1, 0x45, 0x69, 0x9b, 0x92, 0x3f, 0xe5, 0x37, 0xb7};
static const uint8_t sigC_44[] = {
    0x8d, 0x77, 0x6f, 0xec, 0x4d, 0xc8, 0x7d, 0xf5, 0x02, 0xeb, 0x62, 0x35, 0x89, 0x63, 0xca, 0xf8,
    0x3a, 0x6e, 0xa3, 0xf6, 0x84, 0xdc, 0x5b, 0x8f, 0x61, 0x9b, 0x5d, 0x0f, 0xa9, 0x84, 0xae, 0x7d};
static const uint8_t sigHC_44[] = {
    0x4a, 0x02, 0x66, 0x73, 0xf8, 0xbd, 0x6d, 0x72, 0x42, 0x81, 0xad, 0x34, 0x92, 0xe0, 0x37, 0xad,
    0x61, 0x14, 0x2e, 0x45, 0x60, 0x1d, 0xc4, 0x74, 0x19, 0x03, 0x0a, 0x56, 0xd2, 0x96, 0xbd, 0x98};
static const uint8_t pk_65[] = {
    0xab, 0x0f, 0x27, 0xcf, 0xe4, 0xf8, 0x4d, 0x2a, 0x9f, 0xa7, 0x4d, 0x48, 0x46, 0x74, 0x39, 0xdf,
    0x9e, 0x5d, 0xd8, 0x40, 0x1f, 0x87, 0x15, 0xf8, 0x2e, 0xd7, 0x0e, 0x43, 0xa3, 0x71, 0x40, 0x0a};
static const uint8_t sig_65[] = {
    0xdb, 0xd0, 0x56, 0x2f, 0xd0, 0x88, 0xd4, 0xdd, 0x38, 0x21, 0x09, 0xbb, 0x7c, 0xbe, 0xc2, 0xd0,
    0x88, 0xe0, 0x99, 0x94, 0xaf, 0x58, 0x26, 0xbe, 0x86, 0x57, 0xc6, 0x7d, 0xfc, 0x88, 0xcd, 0x54};
static const uint8_t sigD_65[] = {
    0x28, 0x7b, 0x33, 0xfc, 0xc1, 0x19, 0x7c, 0x7c, 0x2b, 0xa8, 0x0d, 0x95, 0x03, 0x37, 0x3d, 0xc6,
    0x2f, 0x1e, 0x55, 0x8c, 0x3c, 0x89, 0xf6, 0x3f, 0x41, 0x58, 0x52, 0x08, 0x6b, 0xdf, 0xa1, 0x41};
static const uint8_t sigH_65[] = {
    0x8e, 0xa0, 0x62, 0x79, 0xa9, 0xcc, 0x75, 0xa8, 0x6f, 0xa8, 0x6c, 0x5c, 0x4e, 0x09, 0xa5, 0x0e,
    0xa0, 0x1c, 0xef, 0x92, 0xa5, 0x69, 0xc0, 0xd5, 0x60, 0x0e, 0x55, 0x31, 0x15, 0x1c, 0x48, 0x80};
static const uint8_t sigHD_65[] = {
    0x6f, 0xf4, 0xe8, 0x66, 0x70, 0x50, 0x16, 0x5f, 0x99, 0xe6, 0x1a, 0x2b, 0x12, 0x08, 0x75, 0x17,
    0x1a, 0x42, 0x11, 0x5f, 0x49, 0xa2, 0x87, 0x99, 0x0a, 0x95, 0x8f, 0x7e, 0xea, 0x38, 0xad, 0x4d};
static const uint8_t sigC_65[] = {
    0x89, 0x7c, 0x7a, 0x29, 0xaa, 0x56, 0x32, 0x19, 0x72, 0x08, 0x66, 0x54, 0x55, 0x88, 0x03, 0xad,
    0xa4, 0xd4, 0x16, 0xc5, 0x82, 0xf4, 0x8b, 0x6f, 0xf0, 0xda, 0x6f, 0x87, 0x47, 0xde, 0x5e, 0x9b};
static const uint8_t sigHC_65[] = {
    0x26, 0x14, 0xd4, 0x56, 0xe9, 0xad, 0xa2, 0xb3, 0x20, 0xf4, 0xf3, 0x2e, 0x00, 0x98, 0xd4, 0xe7,
    0x5c, 0x0b, 0x77, 0x7e, 0x75, 0x66, 0x26, 0x5a, 0xb9, 0xb7, 0xec, 0x69, 0x69, 0xcf, 0x08, 0x68};
static const uint8_t pk_87[] = {
    0xb5, 0x09, 0xc4, 0xeb, 0xd6, 0xb5, 0xfa, 0x67, 0x00, 0x9c, 0x73, 0xcc, 0x7c, 0xeb, 0xe5, 0x5a,
    0x3f, 0x38, 0x48, 0x6a, 0x24, 0xac, 0xfb, 0xf9, 0xd9, 0x1d, 0xd0, 0x4f, 0x63, 0xe6, 0x60, 0xb5};
static const uint8_t sig_87[] = {
    0xd0, 0x90, 0x9b, 0xaf, 0xd2, 0xc5, 0xb1, 0x6a, 0x2e, 0x01, 0x89, 0x49, 0xf6, 0xaa, 0x5c, 0x26,
    0x8a, 0x9e, 0x22, 0x8a, 0x4f, 0x6b, 0x65, 0x56, 0x67, 0x2f, 0x11, 0x2d, 0x77, 0xa4, 0x38, 0x62};
static const uint8_t sigD_87[] = {
    0x79, 0xd2, 0x9f, 0x62, 0xed, 0x72, 0x8a, 0x20, 0x22, 0xbe, 0x46, 0x5f, 0x57, 0x17, 0xc6, 0x9e,
    0xa1, 0xbf, 0xa4, 0x17, 0x5e, 0xa3, 0x9c, 0xb3, 0x0e, 0x3f, 0x79, 0x4a, 0x8c, 0xb2, 0x33, 0xcb};
static const uint8_t sigH_87[] = {
    0x4e, 0xf0, 0x7b, 0x9b, 0x56, 0xe7, 0x72, 0x5d, 0x47, 0x07, 0x36, 0x2b, 0x1c, 0x64, 0x26, 0x27,
    0xf9, 0xda, 0xdc, 0xa2, 0x0b, 0xc2, 0xc6, 0x33, 0xf8, 0x08, 0xf5, 0x00, 0xad, 0xfd, 0x8b, 0x7c};
static const uint8_t sigHD_87[] = {
    0xee, 0x7b, 0x04, 0xf1, 0x32, 0xb7, 0x83, 0xe6, 0xaa, 0xcf, 0x50, 0xb3, 0xf5, 0x9c, 0xf3, 0xcc,
    0x14, 0x55, 0x4e, 0x7c, 0xe6, 0x70, 0x8a, 0x43, 0x4c, 0xd1, 0xe1, 0x64, 0x8d, 0x64, 0xb4, 0x30};
static const uint8_t sigC_87[] = {
    0x4b, 0x9d, 0xe9, 0xf5, 0x6a, 0xef, 0xaa, 0x0a, 0x88, 0xd4, 0xba, 0x47, 0x7e, 0x4a, 0x98, 0x1d,
    0x42, 0xca, 0x1d, 0x0b, 0xb9, 0xc8, 0xc2, 0x9f, 0x2a, 0xdf, 0x64, 0x56, 0x9f, 0x1c, 0x4f, 0x98};
static const uint8_t sigHC_87[] = {
    0x44, 0x57, 0xef, 0x89, 0x05, 0x29, 0x75, 0xbf, 0x89, 0x4e, 0x4c, 0x5e, 0x8b, 0xd6, 0xc2, 0xf7,
    0xee, 0x2d, 0x89, 0xdd, 0x70, 0x35, 0x74, 0x30, 0x83, 0x52, 0x05, 0xfc, 0xea, 0x35, 0x49, 0x09};

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
    case 6: alg = PSA_ALG_HASH_ML_DSA(PSA_ALG_SHA_256); break;
    case 7: alg = PSA_ALG_HASH_ML_DSA(PSA_ALG_SHAKE128_256); break;
    case 8: alg = PSA_ALG_DETERMINISTIC_HASH_ML_DSA(PSA_ALG_SHA_256); break;
    case 9: alg = PSA_ALG_DETERMINISTIC_HASH_ML_DSA(PSA_ALG_SHAKE128_256); break;
    case 10: alg = PSA_ALG_HASH_ML_DSA(PSA_ALG_SHA_256); break;
    default: alg = PSA_ALG_DETERMINISTIC_ML_DSA;
    }

    TEST_ASSERT(PSA_EXPORT_KEY_OUTPUT_SIZE(PSA_KEY_TYPE_ML_DSA_KEY_PAIR, key_size) == 32);
    TEST_ASSERT(PSA_EXPORT_KEY_OUTPUT_SIZE(PSA_KEY_TYPE_ML_DSA_PUBLIC_KEY, key_size) == pk_size);
    TEST_ASSERT(PSA_SIGN_OUTPUT_SIZE(PSA_KEY_TYPE_ML_DSA_KEY_PAIR, key_size, PSA_ALG_ML_DSA) == sig_size);

    if (n == 1) {
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
        psa_hash_compute(PSA_ALG_SHA_256, pub, plen, h, sizeof h, &len);
        switch (k) {
        case 0: ASSERT_COMPARE(h, len, pk_44, sizeof pk_44); break;
        case 1: ASSERT_COMPARE(h, len, pk_65, sizeof pk_65); break;
        case 2: ASSERT_COMPARE(h, len, pk_87, sizeof pk_87); break;
        }
    }

    oberon_test_drbg_setup(rnd, 32);
    if (n == 5 || n == 10) {
        TEST_ASSERT(psa_sign_message_with_context(key, alg, msg, sizeof msg, ctx, sizeof ctx,
                                                  sig, sig_size, &slen) == PSA_SUCCESS);
    } else {
        TEST_ASSERT(psa_sign_message(key, alg, msg, sizeof msg, sig, sig_size, &slen) == PSA_SUCCESS);
    }
    switch (n) {
    case 0:
    case 2:
    case 3:
        psa_hash_compute(PSA_ALG_SHA_256, sig, sig_size, h, sizeof h, &len);
        switch (k) {
        case 0: ASSERT_COMPARE(h, len, sigD_44, sizeof sigD_44); break;
        case 1: ASSERT_COMPARE(h, len, sigD_65, sizeof sigD_65); break;
        case 2: ASSERT_COMPARE(h, len, sigD_87, sizeof sigD_87); break;
        }
        break;
    case 4:
        psa_hash_compute(PSA_ALG_SHA_256, sig, sig_size, h, sizeof h, &len);
        switch (k) {
        case 0: ASSERT_COMPARE(h, len, sig_44, sizeof sig_44); break;
        case 1: ASSERT_COMPARE(h, len, sig_65, sizeof sig_65); break;
        case 2: ASSERT_COMPARE(h, len, sig_87, sizeof sig_87); break;
        }
        break;
    case 5:
        psa_hash_compute(PSA_ALG_SHA_256, sig, sig_size, h, sizeof h, &len);
        switch (k) {
        case 0: ASSERT_COMPARE(h, len, sigC_44, sizeof sigC_44); break;
        case 1: ASSERT_COMPARE(h, len, sigC_65, sizeof sigC_65); break;
        case 2: ASSERT_COMPARE(h, len, sigC_87, sizeof sigC_87); break;
        }
        break;
    case 6:
        psa_hash_compute(PSA_ALG_SHA_256, sig, sig_size, h, sizeof h, &len);
        switch (k) {
        case 0: ASSERT_COMPARE(h, len, sigH_44, sizeof sigH_44); break;
        case 1: ASSERT_COMPARE(h, len, sigH_65, sizeof sigH_65); break;
        case 2: ASSERT_COMPARE(h, len, sigH_87, sizeof sigH_87); break;
        }
        break;
    case 8:
        psa_hash_compute(PSA_ALG_SHA_256, sig, sig_size, h, sizeof h, &len);
        switch (k) {
        case 0: ASSERT_COMPARE(h, len, sigHD_44, sizeof sigHD_44); break;
        case 1: ASSERT_COMPARE(h, len, sigHD_65, sizeof sigHD_65); break;
        case 2: ASSERT_COMPARE(h, len, sigHD_87, sizeof sigHD_87); break;
        }
        break;
    case 10:
        psa_hash_compute(PSA_ALG_SHA_256, sig, sig_size, h, sizeof h, &len);
        switch (k) {
        case 0: ASSERT_COMPARE(h, len, sigHC_44, sizeof sigHC_44); break;
        case 1: ASSERT_COMPARE(h, len, sigHC_65, sizeof sigHC_65); break;
        case 2: ASSERT_COMPARE(h, len, sigHC_87, sizeof sigHC_87); break;
        }
        break;
    }

    if (n == 6) {
        TEST_ASSERT(psa_hash_compute(PSA_ALG_SHA_256, msg, sizeof msg, h, sizeof h, &len) == PSA_SUCCESS);
        oberon_test_drbg_setup(rnd, 32);
        TEST_ASSERT(psa_sign_hash(key, alg, h, len, sig, sig_size, &slen) == PSA_SUCCESS);
        psa_hash_compute(PSA_ALG_SHA_256, sig, sig_size, h, sizeof h, &len);
        switch (k) {
        case 0: ASSERT_COMPARE(h, len, sigH_44, sizeof sigH_44); break;
        case 1: ASSERT_COMPARE(h, len, sigH_65, sizeof sigH_65); break;
        case 2: ASSERT_COMPARE(h, len, sigH_87, sizeof sigH_87); break;
        }
    }

    // test relaxed key policy for verify
    alg = alg ^ PSA_ALG_ML_DSA_DETERMINISTIC_FLAG; // hedged <-> deterministic

    if (n == 3) {
        TEST_ASSERT(psa_verify_message(key, alg, msg, sizeof msg, sig, slen) == PSA_SUCCESS);
    } else if (n == 5 || n == 10) {
        TEST_ASSERT(psa_verify_message_with_context(key, alg, msg, sizeof msg, ctx, sizeof ctx, sig, slen) == PSA_SUCCESS);
    } else {
        psa_set_key_usage_flags(&key_attr, PSA_KEY_USAGE_VERIFY_MESSAGE);
        psa_set_key_type(&key_attr, PSA_KEY_TYPE_ML_DSA_PUBLIC_KEY);
        TEST_ASSERT(psa_import_key(&key_attr, pub, plen, &pkey) == PSA_SUCCESS);
        TEST_ASSERT(psa_verify_message(pkey, alg, msg, sizeof msg, sig, slen) == PSA_SUCCESS);
    }

    if (n == 6) {
        psa_set_key_usage_flags(&key_attr, PSA_KEY_USAGE_VERIFY_HASH);
        psa_set_key_type(&key_attr, PSA_KEY_TYPE_ML_DSA_PUBLIC_KEY);
        TEST_ASSERT(psa_import_key(&key_attr, pub, plen, &pkey) == PSA_SUCCESS);
        TEST_ASSERT(psa_hash_compute(PSA_ALG_SHA_256, msg, sizeof msg, h, sizeof h, &len) == PSA_SUCCESS);
        TEST_ASSERT(psa_verify_hash(pkey, alg, h, len, sig, slen) == PSA_SUCCESS);
        // use secret key
        TEST_ASSERT(psa_verify_hash(key, alg, h, len, sig, slen) == PSA_SUCCESS);
    }

    res = 1;
exit:
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
        TEST_ASSERT(psa_hash_compute(PSA_ALG_SHA_256, msg, sizeof msg, h, sizeof h, &len) == PSA_SUCCESS);
        oberon_test_drbg_setup(rnd, 32);
        TEST_ASSERT(psa_sign_hash(key, PSA_ALG_ML_DSA, h, len, sig, sig_size, &slen) == PSA_ERROR_INVALID_ARGUMENT);
        goto abort;
    } else if (n == 3) { // sign_hash with DETERMINISTIC_ML_DSA
        psa_set_key_algorithm(&key_attr, PSA_ALG_DETERMINISTIC_ML_DSA);
        psa_set_key_usage_flags(&key_attr, PSA_KEY_USAGE_SIGN_HASH);
        TEST_ASSERT(psa_import_key(&key_attr, seed, 32, &key) == PSA_SUCCESS);
        TEST_ASSERT(psa_hash_compute(PSA_ALG_SHA_256, msg, sizeof msg, h, sizeof h, &len) == PSA_SUCCESS);
        oberon_test_drbg_setup(rnd, 32);
        TEST_ASSERT(psa_sign_hash(key, PSA_ALG_DETERMINISTIC_ML_DSA, h, len, sig, sig_size, &slen) == PSA_ERROR_INVALID_ARGUMENT);
        goto abort;
    } else if (n == 5) { // wrong hash algorithm
        psa_set_key_algorithm(&key_attr, PSA_ALG_HASH_ML_DSA(PSA_ALG_MD5));
        psa_set_key_usage_flags(&key_attr, PSA_KEY_USAGE_SIGN_HASH);
        TEST_ASSERT(psa_import_key(&key_attr, seed, 32, &key) == PSA_SUCCESS);
        TEST_ASSERT(psa_hash_compute(PSA_ALG_SHA_256, msg, sizeof msg, h, sizeof h, &len) == PSA_SUCCESS);
        oberon_test_drbg_setup(rnd, 32);
        TEST_ASSERT(psa_sign_hash(key, PSA_ALG_HASH_ML_DSA(PSA_ALG_MD5), h, len, sig, sig_size, &slen) == PSA_ERROR_NOT_SUPPORTED);
        goto abort;
    } else if (n == 6) { // wrong hash algorithm (deterministic)
        psa_set_key_algorithm(&key_attr, PSA_ALG_DETERMINISTIC_HASH_ML_DSA(PSA_ALG_MD5));
        psa_set_key_usage_flags(&key_attr, PSA_KEY_USAGE_SIGN_HASH);
        TEST_ASSERT(psa_import_key(&key_attr, seed, 32, &key) == PSA_SUCCESS);
        TEST_ASSERT(psa_hash_compute(PSA_ALG_SHA_256, msg, sizeof msg, h, sizeof h, &len) == PSA_SUCCESS);
        oberon_test_drbg_setup(rnd, 32);
        TEST_ASSERT(psa_sign_hash(key, PSA_ALG_DETERMINISTIC_HASH_ML_DSA(PSA_ALG_MD5), h, len, sig, sig_size, &slen) == PSA_ERROR_NOT_SUPPORTED);
        goto abort;
    } else if (n == 7) { // sign_message with wrong context length
        psa_set_key_algorithm(&key_attr, PSA_ALG_ML_DSA);
        psa_set_key_usage_flags(&key_attr, PSA_KEY_USAGE_SIGN_MESSAGE);
        TEST_ASSERT(psa_import_key(&key_attr, seed, 32, &key) == PSA_SUCCESS);
        oberon_test_drbg_setup(rnd, 32);
        TEST_ASSERT(psa_sign_message_with_context(key, PSA_ALG_ML_DSA, msg, sizeof msg, ctx, 512, sig, sig_size, &slen) == PSA_ERROR_INVALID_ARGUMENT);
        goto abort;
    } else if (n == 8) { // sign_hash with wrong context length
        psa_set_key_algorithm(&key_attr, PSA_ALG_HASH_ML_DSA(PSA_ALG_SHA_256));
        psa_set_key_usage_flags(&key_attr, PSA_KEY_USAGE_SIGN_HASH);
        TEST_ASSERT(psa_import_key(&key_attr, seed, 32, &key) == PSA_SUCCESS);
        TEST_ASSERT(psa_hash_compute(PSA_ALG_SHA_256, msg, sizeof msg, h, sizeof h, &len) == PSA_SUCCESS);
        oberon_test_drbg_setup(rnd, 32);
        TEST_ASSERT(psa_sign_hash_with_context(key, PSA_ALG_HASH_ML_DSA(PSA_ALG_SHA_256), h, len, ctx, 512, sig, sig_size, &slen) == PSA_ERROR_INVALID_ARGUMENT);
        goto abort;
    } else {
        psa_set_key_algorithm(&key_attr, PSA_ALG_ML_DSA);
        psa_set_key_usage_flags(&key_attr, PSA_KEY_USAGE_SIGN_MESSAGE);
        TEST_ASSERT(psa_import_key(&key_attr, seed, 32, &key) == PSA_SUCCESS);
        oberon_test_drbg_setup(rnd, 32);
        TEST_ASSERT(psa_sign_message(key, PSA_ALG_ML_DSA, msg, sizeof msg, sig, sig_size, &slen) == PSA_SUCCESS);
    }

    TEST_ASSERT(psa_export_public_key(key, pub, pk_size, &plen) == PSA_SUCCESS);

    psa_set_key_type(&key_attr, PSA_KEY_TYPE_ML_DSA_PUBLIC_KEY);

    if (n == 2) { // verify_hash with ML_DSA
        psa_set_key_usage_flags(&key_attr, PSA_KEY_USAGE_VERIFY_HASH);
        TEST_ASSERT(psa_import_key(&key_attr, pub, plen, &pkey) == PSA_SUCCESS);
        TEST_ASSERT(psa_hash_compute(PSA_ALG_SHA_256, msg, sizeof msg, h, sizeof h, &len) == PSA_SUCCESS);
        TEST_ASSERT(psa_verify_hash(pkey, PSA_ALG_ML_DSA, h, len, sig, slen) == PSA_ERROR_INVALID_ARGUMENT);
        goto abort;
    } else if (n == 4) { // verify_hash with DETERMINISTIC_ML_DSA
        psa_set_key_algorithm(&key_attr, PSA_ALG_DETERMINISTIC_ML_DSA);
        psa_set_key_usage_flags(&key_attr, PSA_KEY_USAGE_VERIFY_HASH);
        TEST_ASSERT(psa_import_key(&key_attr, pub, plen, &pkey) == PSA_SUCCESS);
        TEST_ASSERT(psa_hash_compute(PSA_ALG_SHA_256, msg, sizeof msg, h, sizeof h, &len) == PSA_SUCCESS);
        TEST_ASSERT(psa_verify_hash(pkey, PSA_ALG_DETERMINISTIC_ML_DSA, h, len, sig, slen) == PSA_ERROR_INVALID_ARGUMENT);
        goto abort;
    } else if (n == 9) { // verify_message with wrong context length
        psa_set_key_usage_flags(&key_attr, PSA_KEY_USAGE_VERIFY_MESSAGE);
        TEST_ASSERT(psa_import_key(&key_attr, pub, plen, &pkey) == PSA_SUCCESS);
        TEST_ASSERT(psa_verify_message_with_context(pkey, PSA_ALG_ML_DSA, msg, sizeof msg, ctx, 512, sig, slen) == PSA_ERROR_INVALID_ARGUMENT);
        goto abort;
    } else if (n == 10) { // verify_hash with wrong context length
        psa_set_key_usage_flags(&key_attr, PSA_KEY_USAGE_VERIFY_HASH);
        TEST_ASSERT(psa_import_key(&key_attr, pub, plen, &pkey) == PSA_SUCCESS);
        TEST_ASSERT(psa_hash_compute(PSA_ALG_SHA_256, msg, sizeof msg, h, sizeof h, &len) == PSA_SUCCESS);
        TEST_ASSERT(psa_verify_hash_with_context(pkey, PSA_ALG_ML_DSA, h, len, ctx, 512, sig, slen) == PSA_ERROR_INVALID_ARGUMENT);
        goto abort;
    } else {
        psa_set_key_usage_flags(&key_attr, PSA_KEY_USAGE_VERIFY_MESSAGE);
        TEST_ASSERT(psa_import_key(&key_attr, pub, plen, &pkey) == PSA_SUCCESS);
        TEST_ASSERT(psa_verify_message(pkey, PSA_ALG_ML_DSA, msg, sizeof msg, sig, slen) == PSA_SUCCESS);
    }

abort:
    psa_destroy_key(key);
    psa_destroy_key(pkey);
    psa_destroy_key(dkey);
    return 1;
exit:
    psa_destroy_key(key);
    psa_destroy_key(pkey);
    psa_destroy_key(dkey);
    return 0;
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
    0x52, 0xDC, 0x02, 0xB7, 0x03, 0xFA, 0x93, 0xEC, 0xA2, 0xC3, 0x97, 0xB5, 0x0E, 0x21, 0xAF, 0x7D,
    0x57, 0x06, 0x6D, 0x51, 0x37, 0xEC, 0xF2, 0x7A, 0x30, 0x3D, 0x7B, 0x96, 0x03, 0x80, 0xE3, 0xB2};
static const uint8_t ct_512[] = {
    0x92, 0xE6, 0xBF, 0xF6, 0x43, 0xA5, 0x18, 0x18, 0x1A, 0x8C, 0x61, 0x8D, 0x34, 0x0C, 0x0C, 0x13,
    0x8F, 0x99, 0xEB, 0xA6, 0x60, 0x6C, 0xD1, 0x86, 0x19, 0x15, 0xEC, 0x11, 0x6C, 0x8B, 0xCF, 0x5E};
static const uint8_t ss_512[] = {
    0x2B, 0x5C, 0x52, 0xEE, 0x72, 0x94, 0x63, 0x31, 0x98, 0x3B, 0xA0, 0x50, 0xBE, 0x0F, 0x43, 0x50,
    0x55, 0xC0, 0x54, 0x79, 0x01, 0xE0, 0x35, 0x59, 0xB3, 0x56, 0x51, 0x78, 0x89, 0xEA, 0x27, 0xC5};
static const uint8_t pk_768[] = {
    0x4B, 0xEC, 0x47, 0x30, 0xF2, 0x62, 0x73, 0xC6, 0x31, 0x9E, 0xF7, 0x38, 0x7D, 0xD4, 0x75, 0x83,
    0x15, 0x24, 0x0A, 0x93, 0x94, 0xCD, 0x89, 0x26, 0x4B, 0x14, 0x8B, 0x91, 0x13, 0x06, 0x0B, 0x61};
static const uint8_t ct_768[] = {
    0x41, 0x91, 0xF5, 0x59, 0x6E, 0xBE, 0x7F, 0xF1, 0x44, 0x61, 0x85, 0x4E, 0x6C, 0x28, 0x85, 0x76,
    0x3C, 0x43, 0x9B, 0x88, 0x11, 0x66, 0xE4, 0x33, 0x7C, 0xA5, 0x08, 0x4E, 0xE6, 0xCF, 0x2C, 0x6E};
static const uint8_t ss_768[] = {
    0xB4, 0x08, 0xD5, 0xD1, 0x15, 0x71, 0x3F, 0x0A, 0x93, 0x04, 0x7D, 0xBB, 0xEA, 0x83, 0x2E, 0x43,
    0x40, 0x78, 0x76, 0x86, 0xD5, 0x9A, 0x9A, 0x2D, 0x10, 0x6B, 0xD6, 0x62, 0xBA, 0x0A, 0xA0, 0x35};
static const uint8_t pk_1024[] = {
    0xB6, 0xDF, 0xF8, 0x8F, 0x25, 0xFE, 0xF3, 0xB0, 0xBB, 0xEE, 0x12, 0xF9, 0xC5, 0xFE, 0x81, 0x74,
    0xC6, 0xDF, 0x6F, 0x30, 0x0E, 0x0D, 0x97, 0x54, 0x19, 0xCE, 0xF6, 0x92, 0x75, 0x9D, 0x69, 0x06};
static const uint8_t ct_1024[] = {
    0x13, 0x08, 0xCC, 0x78, 0x03, 0xED, 0xE2, 0x54, 0xC1, 0x70, 0x4F, 0x62, 0xEC, 0x82, 0x93, 0x0D,
    0x34, 0x39, 0x4B, 0x27, 0x98, 0x3D, 0x8F, 0x0B, 0x5C, 0x33, 0xD6, 0x8D, 0x17, 0x36, 0x48, 0xB4};
static const uint8_t ss_1024[] = {
    0x23, 0xF2, 0x11, 0xB8, 0x4A, 0x6E, 0xE2, 0x0C, 0x8C, 0x29, 0xF6, 0xE5, 0x31, 0x4C, 0x91, 0xB4,
    0x14, 0xE9, 0x40, 0x51, 0x3D, 0x38, 0x0A, 0xDD, 0x17, 0xBD, 0x72, 0x4A, 0xB3, 0xA1, 0x3A, 0x52};

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
        psa_hash_compute(PSA_ALG_SHA_256, pub, plen, h, sizeof h, &len);
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
        psa_hash_compute(PSA_ALG_SHA_256, ct, clen, h, sizeof h, &len);
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

    res = 1;
exit:
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
    psa_destroy_key(key);
    psa_destroy_key(pkey);
    psa_destroy_key(skey);
    psa_destroy_key(dkey);
    return 1;
exit:
    psa_destroy_key(key);
    psa_destroy_key(pkey);
    psa_destroy_key(skey);
    psa_destroy_key(dkey);
    return 0;
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

#ifdef PSA_WANT_ALG_ML_KEM
    for (k = 0; k < 3; k++) {
        for (i = 0; i <= 3; i++) {
            TEST_ASSERT(test_ml_kem(i, k));
        }
        for (i = 0; i <= 14; i++) {
            TEST_ASSERT(test_ml_kem_err(i, k));
        }
    }
#endif

    TEST_ASSERT(test_wrong_context());

return 0;
exit:
    (void)i;
    (void)k;
    return 1;
}
