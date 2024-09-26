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

#include <string.h>

#include "psa/crypto.h"
#include <test/helpers.h>
#include <test/macros.h>


#define ILLEGAL_ID 777


#ifdef PSA_WANT_ALG_AES_KW
// AES-KW test vectors from RFC3394

static const uint8_t kek128[] = {
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F};
static const uint8_t key128[] = {
    0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF};
static const uint8_t ct128[] = {
    0x1F, 0xA6, 0x8B, 0x0A, 0x81, 0x12, 0xB4, 0x47, 0xAE, 0xF3, 0x4B, 0xD8, 0xFB, 0x5A, 0x7B, 0x82,
    0x9D, 0x3E, 0x86, 0x23, 0x71, 0xD2, 0xCF, 0xE5};

static const uint8_t kek256[] = {
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F};
static const uint8_t key256[] = {
    0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF,
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F};
static const uint8_t ct256[] = {
    0x28, 0xC9, 0xF4, 0x04, 0xC4, 0xB8, 0x10, 0xF4, 0xCB, 0xCC, 0xB3, 0x5C, 0xFB, 0x87, 0xF8, 0x26,
    0x3F, 0x57, 0x86, 0xE2, 0xD8, 0x0E, 0xD3, 0x26, 0xCB, 0xC7, 0xF0, 0xE7, 0x1A, 0x99, 0xF4, 0x3B,
    0xFB, 0x98, 0x8B, 0x9B, 0x7A, 0x02, 0xDD, 0x21};
#endif // PSA_WANT_ALG_AES_KW

#ifdef PSA_WANT_ALG_AES_KWP
// AES-KWP test vectors from RFC5649

static const uint8_t kek192[] = {
    0x58, 0x40, 0xdf, 0x6e, 0x29, 0xb0, 0x2a, 0xf1, 0xab, 0x49, 0x3b, 0x70, 0x5b, 0xf1, 0x6e, 0xa1,
    0xae, 0x83, 0x38, 0xf4, 0xdc, 0xc1, 0x76, 0xa8};
static const uint8_t key1[] = {
    0xc3, 0x7b, 0x7e, 0x64, 0x92, 0x58, 0x43, 0x40, 0xbe, 0xd1, 0x22, 0x07, 0x80, 0x89, 0x41, 0x15,
    0x50, 0x68, 0xf7, 0x38};
static const uint8_t ct1[] = {
    0x13, 0x8b, 0xde, 0xaa, 0x9b, 0x8f, 0xa7, 0xfc, 0x61, 0xf9, 0x77, 0x42, 0xe7, 0x22, 0x48, 0xee,
    0x5a, 0xe6, 0xae, 0x53, 0x60, 0xd1, 0xae, 0x6a, 0x5f, 0x54, 0xf3, 0x73, 0xfa, 0x54, 0x3b, 0x6a};
static const uint8_t key2[] = {
    0x46, 0x6f, 0x72, 0x50, 0x61, 0x73, 0x69};
static const uint8_t ct2[] = {
    0xaf, 0xbe, 0xb0, 0xf0, 0x7d, 0xfb, 0xf5, 0x41, 0x92, 0x00, 0xf2, 0xcc, 0xb5, 0x0b, 0xb2, 0x4f};
// wrong ct
static const uint8_t ct1e1[] = { // wrong IV
    0x28, 0x1e, 0x4e, 0x08, 0xc3, 0xf1, 0x02, 0x20, 0x61, 0x16, 0x61, 0x2b, 0xc3, 0x49, 0x6e, 0x86,
    0x78, 0x95, 0xf6, 0x5b, 0xe1, 0xc3, 0xfc, 0xe8, 0xca, 0xed, 0x8b, 0xf4, 0x84, 0x51, 0x63, 0x4d};
static const uint8_t ct1e2[] = { // wrong padding (not zero)
    0x35, 0x53, 0xd6, 0x88, 0xf7, 0x08, 0xe3, 0x5b, 0xb3, 0x7e, 0xff, 0x1c, 0x10, 0xe1, 0x5d, 0x81,
    0x36, 0x2f, 0x59, 0x90, 0x1b, 0x76, 0x77, 0xae, 0xbd, 0x69, 0xe2, 0x81, 0x1b, 0x5f, 0xe4, 0x61};
static const uint8_t ct1e3[] = { // wrong padding (pt length too low)
    0xfc, 0xe8, 0xf9, 0x72, 0x0d, 0x65, 0x9b, 0xa7, 0x54, 0xd7, 0xdc, 0x84, 0x7e, 0x5a, 0xa4, 0x4b,
    0xca, 0x1d, 0x24, 0x9c, 0xf8, 0x24, 0x9a, 0x64, 0xf8, 0x3e, 0x55, 0xa0, 0xfc, 0x59, 0x92, 0x95};
static const uint8_t ct1e4[] = { // wrong padding (pt length too high)
    0xff, 0xe3, 0x12, 0x0e, 0xef, 0xb6, 0xe3, 0x14, 0xc4, 0xa4, 0xdb, 0x1e, 0xac, 0x98, 0x6f, 0x3a,
    0x2d, 0x96, 0x0a, 0xe2, 0x3f, 0x18, 0xee, 0x04, 0xec, 0x47, 0xfe, 0x2e, 0x1c, 0x2d, 0x26, 0xe9};
#endif // PSA_WANT_ALG_AES_KWP


#ifdef PSA_WANT_ALG_AES_KW
int test_aes_kw()
{
    uint8_t ct[40], pt[32];
    psa_key_id_t key = 0, kek = 0;
    psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;
    size_t length;

    psa_set_key_usage_flags(&attributes, PSA_KEY_USAGE_WRAP | PSA_KEY_USAGE_UNWRAP);
    psa_set_key_algorithm(&attributes, PSA_ALG_AES_KW);
    psa_set_key_type(&attributes, PSA_KEY_TYPE_AES);
    TEST_ASSERT(psa_import_key(&attributes, kek128, sizeof kek128, &kek) == PSA_SUCCESS);

    psa_set_key_usage_flags(&attributes, PSA_KEY_USAGE_EXPORT);
    psa_set_key_algorithm(&attributes, PSA_ALG_AES_KW);
    psa_set_key_type(&attributes, PSA_KEY_TYPE_AES);
    TEST_ASSERT(psa_import_key(&attributes, key128, sizeof key128, &key) == PSA_SUCCESS);

    TEST_ASSERT(psa_wrap_key(key, kek, PSA_ALG_AES_KW, PSA_KEY_FORMAT_DEFAULT, ct, sizeof ct, &length) == PSA_SUCCESS);
    ASSERT_COMPARE(ct, length, ct128, sizeof ct128);
    TEST_ASSERT(psa_destroy_key(key) == PSA_SUCCESS); key = 0;

    psa_set_key_usage_flags(&attributes, PSA_KEY_USAGE_EXPORT);
    psa_set_key_algorithm(&attributes, PSA_ALG_CTR);
    psa_set_key_type(&attributes, PSA_KEY_TYPE_AES);
    TEST_ASSERT(psa_unwrap_key(&attributes, kek, PSA_ALG_AES_KW, PSA_KEY_FORMAT_DEFAULT, ct, length, &key) == PSA_SUCCESS);
    TEST_ASSERT(psa_export_key(key, pt, sizeof pt, &length) == PSA_SUCCESS);
    ASSERT_COMPARE(pt, length, key128, sizeof key128);
    TEST_ASSERT(psa_destroy_key(key) == PSA_SUCCESS); key = 0;
    TEST_ASSERT(psa_destroy_key(kek) == PSA_SUCCESS); kek = 0;

    psa_set_key_usage_flags(&attributes, PSA_KEY_USAGE_WRAP | PSA_KEY_USAGE_UNWRAP);
    psa_set_key_algorithm(&attributes, PSA_ALG_AES_KW);
    psa_set_key_type(&attributes, PSA_KEY_TYPE_AES);
    TEST_ASSERT(psa_import_key(&attributes, kek256, sizeof kek256, &kek) == PSA_SUCCESS);

    psa_set_key_usage_flags(&attributes, PSA_KEY_USAGE_EXPORT);
    psa_set_key_algorithm(&attributes, PSA_ALG_AES_KW);
    psa_set_key_type(&attributes, PSA_KEY_TYPE_AES);
    TEST_ASSERT(psa_import_key(&attributes, key256, sizeof key256, &key) == PSA_SUCCESS);

    TEST_ASSERT(psa_wrap_key(key, kek, PSA_ALG_AES_KW, PSA_KEY_FORMAT_DEFAULT, ct, sizeof ct, &length) == PSA_SUCCESS);
    ASSERT_COMPARE(ct, length, ct256, sizeof ct256);
    TEST_ASSERT(psa_destroy_key(key) == PSA_SUCCESS); key = 0;

    psa_set_key_usage_flags(&attributes, PSA_KEY_USAGE_EXPORT);
    psa_set_key_algorithm(&attributes, PSA_ALG_CTR);
    psa_set_key_type(&attributes, PSA_KEY_TYPE_AES);
    TEST_ASSERT(psa_unwrap_key(&attributes, kek, PSA_ALG_AES_KW, PSA_KEY_FORMAT_DEFAULT, ct, length, &key) == PSA_SUCCESS);
    TEST_ASSERT(psa_export_key(key, pt, sizeof pt, &length) == PSA_SUCCESS);
    ASSERT_COMPARE(pt, length, key256, sizeof key256);
    TEST_ASSERT(psa_destroy_key(key) == PSA_SUCCESS); key = 0;
    TEST_ASSERT(psa_destroy_key(kek) == PSA_SUCCESS); kek = 0;

    return 1;
exit:
    psa_destroy_key(key);
    psa_destroy_key(kek);
    return 0;
}

int test_aes_kw_err(int n)
{
    uint8_t ct[40];
    psa_key_id_t key = 0, kek = 0;
    psa_key_attributes_t key_attr = PSA_KEY_ATTRIBUTES_INIT;
    psa_key_attributes_t kek_attr = PSA_KEY_ATTRIBUTES_INIT;
    size_t length;
    psa_status_t expected = PSA_SUCCESS;
    psa_algorithm_t alg;
    psa_key_data_format_t format = PSA_KEY_FORMAT_DEFAULT;
    size_t key_size, buf_size;

    if (n == 1) { // wrong kek usage
        psa_set_key_usage_flags(&kek_attr, PSA_KEY_USAGE_ENCRYPT);
        expected = PSA_ERROR_NOT_PERMITTED;
    } else if (n == 2) { // wrong kek usage
        psa_set_key_usage_flags(&kek_attr, PSA_KEY_USAGE_UNWRAP);
        expected = PSA_ERROR_NOT_PERMITTED;
    } else {
        psa_set_key_usage_flags(&kek_attr, PSA_KEY_USAGE_WRAP);
    }
    if (n == 3) { // wrong kek algorithm
        psa_set_key_algorithm(&kek_attr, PSA_ALG_CTR);
        expected = PSA_ERROR_NOT_PERMITTED;
    } else {
        psa_set_key_algorithm(&kek_attr, PSA_ALG_AES_KW);
    }
    if (n == 4) { // wrong kek type
        psa_set_key_type(&kek_attr, PSA_KEY_TYPE_PASSWORD);
        expected = PSA_ERROR_INVALID_ARGUMENT;
    } else {
        psa_set_key_type(&kek_attr, PSA_KEY_TYPE_AES);
    }

    if (n == 5) { // wrong key usage
        psa_set_key_usage_flags(&key_attr, PSA_KEY_USAGE_WRAP);
        expected = PSA_ERROR_NOT_PERMITTED;
    } else {
        psa_set_key_usage_flags(&key_attr, PSA_KEY_USAGE_EXPORT);
    }
    if (n == 6) { // wrong key algorithm
        psa_set_key_algorithm(&key_attr, PSA_ALG_CTR);
        expected = PSA_ERROR_NOT_PERMITTED;
    } else {
        psa_set_key_algorithm(&key_attr, PSA_ALG_AES_KW);
    }
    psa_set_key_type(&key_attr, PSA_KEY_TYPE_RAW_DATA);
    key_size = sizeof key256;
    if (n == 7) { // key size too small
        key_size = 8;
        expected = PSA_ERROR_INVALID_ARGUMENT;
    }
    if (n == 8) { // key size not a multiple of 8
        key_size -= 4;
        expected = PSA_ERROR_INVALID_ARGUMENT;
    }

    alg = PSA_ALG_AES_KW;
    if (n == 9) { // no key wrap algorithm
        alg = PSA_ALG_CTR;
        psa_set_key_algorithm(&key_attr, alg);
        psa_set_key_algorithm(&kek_attr, alg);
        expected = PSA_ERROR_INVALID_ARGUMENT;
    }
    if (n == 10) { // undefined key wrap algorithm
        alg = (psa_algorithm_t) 0x0B400F00;
        psa_set_key_algorithm(&key_attr, alg);
        psa_set_key_algorithm(&kek_attr, alg);
        expected = PSA_ERROR_NOT_SUPPORTED;
    }
    if (n == 11) { // unsupported format
        format = (psa_key_data_format_t) 77;
        expected = PSA_ERROR_NOT_SUPPORTED;
    }
    buf_size = sizeof ct;
    if (n == 12) { // buffer too small
        buf_size = sizeof ct256 - 1;
        expected = PSA_ERROR_BUFFER_TOO_SMALL;
    }

    TEST_ASSERT(psa_import_key(&kek_attr, kek256, sizeof kek256, &kek) == PSA_SUCCESS);
    if (n == 13) {
        TEST_ASSERT(psa_destroy_key(kek) == PSA_SUCCESS); kek = 0;
        kek = ILLEGAL_ID;
        expected = PSA_ERROR_INVALID_HANDLE;
    }

    TEST_ASSERT(psa_import_key(&key_attr, key256, key_size, &key) == PSA_SUCCESS);
    if (n == 14) {
        TEST_ASSERT(psa_destroy_key(key) == PSA_SUCCESS); key = 0;
        key = ILLEGAL_ID;
        expected = PSA_ERROR_INVALID_HANDLE;
    }

    TEST_ASSERT(psa_wrap_key(key, kek, alg, format, ct, buf_size, &length) == expected);
    if (expected != PSA_SUCCESS) goto abort;

    TEST_ASSERT(psa_destroy_key(key) == PSA_SUCCESS); key = 0;
    TEST_ASSERT(psa_destroy_key(kek) == PSA_SUCCESS); kek = 0;

    if (n == 15) { // wrong kek usage
        psa_set_key_usage_flags(&kek_attr, PSA_KEY_USAGE_DECRYPT);
        expected = PSA_ERROR_NOT_PERMITTED;
    } else if (n == 16) { // wrong kek usage
        psa_set_key_usage_flags(&kek_attr, PSA_KEY_USAGE_WRAP);
        expected = PSA_ERROR_NOT_PERMITTED;
    } else {
        psa_set_key_usage_flags(&kek_attr, PSA_KEY_USAGE_UNWRAP);
    }
    if (n == 17) { // wrong kek algorithm
        psa_set_key_algorithm(&kek_attr, PSA_ALG_CTR);
        expected = PSA_ERROR_NOT_PERMITTED;
    } else {
        psa_set_key_algorithm(&kek_attr, PSA_ALG_AES_KW);
    }
    if (n == 18) { // wrong kek type
        psa_set_key_type(&kek_attr, PSA_KEY_TYPE_PASSWORD);
        expected = PSA_ERROR_INVALID_ARGUMENT;
    } else {
        psa_set_key_type(&kek_attr, PSA_KEY_TYPE_AES);
    }

    psa_set_key_usage_flags(&key_attr, PSA_KEY_USAGE_EXPORT);
    psa_set_key_algorithm(&key_attr, PSA_ALG_CTR);
    psa_set_key_type(&key_attr, PSA_KEY_TYPE_RAW_DATA);

    alg = PSA_ALG_AES_KW;
    if (n == 19) { // no key wrap algorithm
        alg = PSA_ALG_CTR;
        psa_set_key_algorithm(&kek_attr, alg);
        expected = PSA_ERROR_INVALID_ARGUMENT;
    }
    if (n == 20) { // undefined key wrap algorithm
        alg = (psa_algorithm_t) 0x0B400F00;
        psa_set_key_algorithm(&kek_attr, alg);
        expected = PSA_ERROR_NOT_SUPPORTED;
    }
    if (n == 21) { // unsupported format
        format = (psa_key_data_format_t) 77;
        expected = PSA_ERROR_NOT_SUPPORTED;
    }

    if (n == 22) { // wrapped data to small
        length = 16;
        expected = PSA_ERROR_INVALID_ARGUMENT;
    }
    if (n == 23) { // wrapped data size not a multiple of 8
        length -= 4;
        expected = PSA_ERROR_INVALID_ARGUMENT;
    }

    if (n == 24) { // wrong data
        ct[0]++;
        expected = PSA_ERROR_INVALID_SIGNATURE;
    }

    TEST_ASSERT(psa_import_key(&kek_attr, kek256, sizeof kek256, &kek) == PSA_SUCCESS);
    if (n == 25) {
        TEST_ASSERT(psa_destroy_key(kek) == PSA_SUCCESS); kek = 0;
        kek = ILLEGAL_ID;
        expected = PSA_ERROR_INVALID_HANDLE;
    }

    TEST_ASSERT(psa_unwrap_key(&key_attr, kek, alg, format, ct, length, &key) == expected);

abort:
    if (key != ILLEGAL_ID) TEST_ASSERT(psa_destroy_key(key) == PSA_SUCCESS);
    if (kek != ILLEGAL_ID) TEST_ASSERT(psa_destroy_key(kek) == PSA_SUCCESS);
    return 1;
exit:
    psa_destroy_key(key);
    psa_destroy_key(kek);
    return 0;
}
#endif // PSA_WANT_ALG_AES_KW


#ifdef PSA_WANT_ALG_AES_KWP
int test_aes_kwp()
{
    uint8_t ct[40], pt[32];
    psa_key_id_t key = 0, kek = 0;
    psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;
    size_t length;

    psa_set_key_usage_flags(&attributes, PSA_KEY_USAGE_WRAP | PSA_KEY_USAGE_UNWRAP);
    psa_set_key_algorithm(&attributes, PSA_ALG_AES_KWP);
    psa_set_key_type(&attributes, PSA_KEY_TYPE_AES);
    TEST_ASSERT(psa_import_key(&attributes, kek192, sizeof kek192, &kek) == PSA_SUCCESS);

    psa_set_key_usage_flags(&attributes, PSA_KEY_USAGE_EXPORT);
    psa_set_key_algorithm(&attributes, PSA_ALG_AES_KWP);
    psa_set_key_type(&attributes, PSA_KEY_TYPE_RAW_DATA);
    TEST_ASSERT(psa_import_key(&attributes, key1, sizeof key1, &key) == PSA_SUCCESS);

    TEST_ASSERT(psa_wrap_key(key, kek, PSA_ALG_AES_KWP, PSA_KEY_FORMAT_DEFAULT, ct, sizeof ct, &length) == PSA_SUCCESS);
    ASSERT_COMPARE(ct, length, ct1, sizeof ct1);
    TEST_ASSERT(psa_destroy_key(key) == PSA_SUCCESS); key = 0;

    psa_set_key_usage_flags(&attributes, PSA_KEY_USAGE_EXPORT);
    psa_set_key_algorithm(&attributes, PSA_ALG_CTR);
    psa_set_key_type(&attributes, PSA_KEY_TYPE_RAW_DATA);
    TEST_ASSERT(psa_unwrap_key(&attributes, kek, PSA_ALG_AES_KWP, PSA_KEY_FORMAT_DEFAULT, ct, length, &key) == PSA_SUCCESS);
    TEST_ASSERT(psa_export_key(key, pt, sizeof pt, &length) == PSA_SUCCESS);
    ASSERT_COMPARE(pt, length, key1, sizeof key1);
    TEST_ASSERT(psa_destroy_key(key) == PSA_SUCCESS); key = 0;

    psa_set_key_usage_flags(&attributes, PSA_KEY_USAGE_EXPORT);
    psa_set_key_algorithm(&attributes, PSA_ALG_AES_KWP);
    psa_set_key_type(&attributes, PSA_KEY_TYPE_RAW_DATA);
    TEST_ASSERT(psa_import_key(&attributes, key2, sizeof key2, &key) == PSA_SUCCESS);

    TEST_ASSERT(psa_wrap_key(key, kek, PSA_ALG_AES_KWP, PSA_KEY_FORMAT_DEFAULT, ct, sizeof ct, &length) == PSA_SUCCESS);
    ASSERT_COMPARE(ct, length, ct2, sizeof ct2);
    TEST_ASSERT(psa_destroy_key(key) == PSA_SUCCESS); key = 0;

    psa_set_key_usage_flags(&attributes, PSA_KEY_USAGE_EXPORT);
    psa_set_key_algorithm(&attributes, PSA_ALG_CTR);
    psa_set_key_type(&attributes, PSA_KEY_TYPE_RAW_DATA);
    TEST_ASSERT(psa_unwrap_key(&attributes, kek, PSA_ALG_AES_KWP, PSA_KEY_FORMAT_DEFAULT, ct, length, &key) == PSA_SUCCESS);
    TEST_ASSERT(psa_export_key(key, pt, sizeof pt, &length) == PSA_SUCCESS);
    ASSERT_COMPARE(pt, length, key2, sizeof key2);
    TEST_ASSERT(psa_destroy_key(key) == PSA_SUCCESS); key = 0;
    TEST_ASSERT(psa_destroy_key(kek) == PSA_SUCCESS); kek = 0;

    return 1;
exit:
    psa_destroy_key(key);
    psa_destroy_key(kek);
    return 0;
}

int test_aes_kwp_err(int n)
{
    uint8_t ct[40];
    psa_key_id_t key = 0, kek = 0;
    psa_key_attributes_t key_attr = PSA_KEY_ATTRIBUTES_INIT;
    psa_key_attributes_t kek_attr = PSA_KEY_ATTRIBUTES_INIT;
    size_t length;
    psa_status_t expected = PSA_SUCCESS;
    psa_algorithm_t alg;
    psa_key_data_format_t format = PSA_KEY_FORMAT_DEFAULT;
    size_t buf_size;
    const uint8_t *ctp = ct;

    if (n == 1) { // wrong kek usage
        psa_set_key_usage_flags(&kek_attr, PSA_KEY_USAGE_ENCRYPT);
        expected = PSA_ERROR_NOT_PERMITTED;
    } else if (n == 2) { // wrong kek usage
        psa_set_key_usage_flags(&kek_attr, PSA_KEY_USAGE_UNWRAP);
        expected = PSA_ERROR_NOT_PERMITTED;
    } else {
        psa_set_key_usage_flags(&kek_attr, PSA_KEY_USAGE_WRAP);
    }
    if (n == 3) { // wrong kek algorithm
        psa_set_key_algorithm(&kek_attr, PSA_ALG_CTR);
        expected = PSA_ERROR_NOT_PERMITTED;
    } else {
        psa_set_key_algorithm(&kek_attr, PSA_ALG_AES_KWP);
    }
    if (n == 4) { // wrong kek type
        psa_set_key_type(&kek_attr, PSA_KEY_TYPE_PASSWORD);
        expected = PSA_ERROR_INVALID_ARGUMENT;
    } else {
        psa_set_key_type(&kek_attr, PSA_KEY_TYPE_AES);
    }

    if (n == 5) { // wrong key usage
        psa_set_key_usage_flags(&key_attr, PSA_KEY_USAGE_WRAP);
        expected = PSA_ERROR_NOT_PERMITTED;
    } else {
        psa_set_key_usage_flags(&key_attr, PSA_KEY_USAGE_EXPORT);
    }
    if (n == 6) { // wrong key algorithm
        psa_set_key_algorithm(&key_attr, PSA_ALG_CTR);
        expected = PSA_ERROR_NOT_PERMITTED;
    } else {
        psa_set_key_algorithm(&key_attr, PSA_ALG_AES_KWP);
    }
    psa_set_key_type(&key_attr, PSA_KEY_TYPE_RAW_DATA);

    alg = PSA_ALG_AES_KWP;
    if (n == 7) { // no key wrap algorithm
        alg = PSA_ALG_CTR;
        psa_set_key_algorithm(&key_attr, alg);
        psa_set_key_algorithm(&kek_attr, alg);
        expected = PSA_ERROR_INVALID_ARGUMENT;
    }
    if (n == 8) { // undefined key wrap algorithm
        alg = (psa_algorithm_t) 0x0B400F00;
        psa_set_key_algorithm(&key_attr, alg);
        psa_set_key_algorithm(&kek_attr, alg);
        expected = PSA_ERROR_NOT_SUPPORTED;
    }
    if (n == 9) { // unsupported format
        format = (psa_key_data_format_t) 77;
        expected = PSA_ERROR_NOT_SUPPORTED;
    }
    buf_size = sizeof ct;
    if (n == 10) { // buffer too small
        buf_size = sizeof ct256 - 1;
        expected = PSA_ERROR_BUFFER_TOO_SMALL;
    }

    TEST_ASSERT(psa_import_key(&kek_attr, kek256, sizeof kek256, &kek) == PSA_SUCCESS);
    if (n == 11) {
        TEST_ASSERT(psa_destroy_key(kek) == PSA_SUCCESS); kek = 0;
        kek = ILLEGAL_ID;
        expected = PSA_ERROR_INVALID_HANDLE;
    }

    TEST_ASSERT(psa_import_key(&key_attr, key256, sizeof key256, &key) == PSA_SUCCESS);
    if (n == 12) {
        TEST_ASSERT(psa_destroy_key(key) == PSA_SUCCESS); key = 0;
        key = ILLEGAL_ID;
        expected = PSA_ERROR_INVALID_HANDLE;
    }

    TEST_ASSERT(psa_wrap_key(key, kek, alg, format, ct, buf_size, &length) == expected);
    if (expected != PSA_SUCCESS) goto abort;

    TEST_ASSERT(psa_destroy_key(key) == PSA_SUCCESS); key = 0;
    TEST_ASSERT(psa_destroy_key(kek) == PSA_SUCCESS); kek = 0;

    if (n == 13) { // wrong kek usage
        psa_set_key_usage_flags(&kek_attr, PSA_KEY_USAGE_DECRYPT);
        expected = PSA_ERROR_NOT_PERMITTED;
    } else if (n == 14) { // wrong kek usage
        psa_set_key_usage_flags(&kek_attr, PSA_KEY_USAGE_WRAP);
        expected = PSA_ERROR_NOT_PERMITTED;
    } else {
        psa_set_key_usage_flags(&kek_attr, PSA_KEY_USAGE_UNWRAP);
    }
    if (n == 15) { // wrong kek algorithm
        psa_set_key_algorithm(&kek_attr, PSA_ALG_CTR);
        expected = PSA_ERROR_NOT_PERMITTED;
    } else {
        psa_set_key_algorithm(&kek_attr, PSA_ALG_AES_KWP);
    }
    if (n == 16) { // wrong kek type
        psa_set_key_type(&kek_attr, PSA_KEY_TYPE_PASSWORD);
        expected = PSA_ERROR_INVALID_ARGUMENT;
    } else {
        psa_set_key_type(&kek_attr, PSA_KEY_TYPE_AES);
    }

    psa_set_key_usage_flags(&key_attr, PSA_KEY_USAGE_EXPORT);
    psa_set_key_algorithm(&key_attr, PSA_ALG_CTR);
    psa_set_key_type(&key_attr, PSA_KEY_TYPE_RAW_DATA);

    alg = PSA_ALG_AES_KWP;
    if (n == 17) { // no key wrap algorithm
        alg = PSA_ALG_CTR;
        psa_set_key_algorithm(&kek_attr, alg);
        expected = PSA_ERROR_INVALID_ARGUMENT;
    }
    if (n == 18) { // undefined key wrap algorithm
        alg = (psa_algorithm_t) 0x0B400F00;
        psa_set_key_algorithm(&kek_attr, alg);
        expected = PSA_ERROR_NOT_SUPPORTED;
    }
    if (n == 19) { // unsupported format
        format = (psa_key_data_format_t) 77;
        expected = PSA_ERROR_NOT_SUPPORTED;
    }

    if (n == 20) { // wrapped data to small
        length = 8;
        expected = PSA_ERROR_INVALID_ARGUMENT;
    }
    if (n == 21) { // wrapped data size not a multiple of 8
        length -= 4;
        expected = PSA_ERROR_INVALID_ARGUMENT;
    }

    if (n == 22) { // wrong data
        ct[0]++;
        expected = PSA_ERROR_INVALID_SIGNATURE;
    }
    if (n == 23) { // wrong IV
        ctp = ct1e1;
        expected = PSA_ERROR_INVALID_SIGNATURE;
    }
    if (n == 24) { // wrong padding (not zero)
        ctp = ct1e2;
        expected = PSA_ERROR_INVALID_SIGNATURE;
    }
    if (n == 25) { // wrong padding (pt length too low)
        ctp = ct1e3;
        expected = PSA_ERROR_INVALID_SIGNATURE;
    }
    if (n == 26) { // wrong padding (pt length too high)
        ctp = ct1e4;
        expected = PSA_ERROR_INVALID_SIGNATURE;
    }

    TEST_ASSERT(psa_import_key(&kek_attr, kek256, sizeof kek256, &kek) == PSA_SUCCESS);
    if (n == 27) {
        TEST_ASSERT(psa_destroy_key(kek) == PSA_SUCCESS); kek = 0;
        kek = ILLEGAL_ID;
        expected = PSA_ERROR_INVALID_HANDLE;
    }

    TEST_ASSERT(psa_unwrap_key(&key_attr, kek, alg, format, ctp, length, &key) == expected);

abort:
    if (key != ILLEGAL_ID) TEST_ASSERT(psa_destroy_key(key) == PSA_SUCCESS);
    if (kek != ILLEGAL_ID) TEST_ASSERT(psa_destroy_key(kek) == PSA_SUCCESS);
    return 1;
exit:
    psa_destroy_key(key);
    psa_destroy_key(kek);
    return 0;
}
#endif // PSA_WANT_ALG_AES_KWP


int main(void)
{
    int i;

    TEST_ASSERT(psa_crypto_init() == PSA_SUCCESS);

#ifdef PSA_WANT_ALG_AES_KW
    TEST_ASSERT(test_aes_kw());
    for (i = 1; i <= 25; i++) {
        TEST_ASSERT(test_aes_kw_err(i));
    }
#endif

#ifdef PSA_WANT_ALG_AES_KWP
    TEST_ASSERT(test_aes_kwp());
    for (i = 1; i <= 27; i++) {
        TEST_ASSERT(test_aes_kwp_err(i));
    }
#endif

    return 0;
exit:
    (void)i;
    return 1;
}
