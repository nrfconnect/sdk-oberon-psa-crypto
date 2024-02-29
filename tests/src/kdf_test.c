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

#include "psa/crypto.h"
#include <test/helpers.h>
#include <test/macros.h>
#include <string.h>

#if defined(PSA_WANT_ALG_PBKDF2_HMAC)
static const uint8_t PBKDF2_SHA1_K1[] = {
    0x0c, 0x60, 0xc8, 0x0f, 0x96, 0x1f, 0x0e, 0x71, 0xf3, 0xa9, 0xb5, 0x24, 0xaf, 0x60, 0x12, 0x06,
    0x2f, 0xe0, 0x37, 0xa6};
static const uint8_t PBKDF2_SHA1_K2[] = {
    0xea, 0x6c, 0x01, 0x4d, 0xc7, 0x2d, 0x6f, 0x8c, 0xcd, 0x1e, 0xd9, 0x2a, 0xce, 0x1d, 0x41, 0xf0,
    0xd8, 0xde, 0x89, 0x57};
static const uint8_t PBKDF2_SHA1_K4k[] = {
    0x4b, 0x00, 0x79, 0x01, 0xb7, 0x65, 0x48, 0x9a, 0xbe, 0xad, 0x49, 0xd9, 0x26, 0xf7, 0x21, 0xd0,
    0x65, 0xa4, 0x29, 0xc1};
static const uint8_t PBKDF2_SHA256_K1[] = {
    0x12, 0x0f, 0xb6, 0xcf, 0xfc, 0xf8, 0xb3, 0x2c, 0x43, 0xe7, 0x22, 0x52, 0x56, 0xc4, 0xf8, 0x37,
    0xa8, 0x65, 0x48, 0xc9, 0x2c, 0xcc, 0x35, 0x48, 0x08, 0x05, 0x98, 0x7c, 0xb7, 0x0b, 0xe1, 0x7b};
static const uint8_t PBKDF2_SHA256_K2[] = {
    0xae, 0x4d, 0x0c, 0x95, 0xaf, 0x6b, 0x46, 0xd3, 0x2d, 0x0a, 0xdf, 0xf9, 0x28, 0xf0, 0x6d, 0xd0,
    0x2a, 0x30, 0x3f, 0x8e, 0xf3, 0xc2, 0x51, 0xdf, 0xd6, 0xe2, 0xd8, 0x5a, 0x95, 0x47, 0x4c, 0x43};
static const uint8_t PBKDF2_SHA256_K4k[] = {
    0xc5, 0xe4, 0x78, 0xd5, 0x92, 0x88, 0xc8, 0x41, 0xaa, 0x53, 0x0d, 0xb6, 0x84, 0x5c, 0x4c, 0x8d,
    0x96, 0x28, 0x93, 0xa0, 0x01, 0xce, 0x4e, 0x11, 0xa4, 0x96, 0x38, 0x73, 0xaa, 0x98, 0x13, 0x4a};

#endif
#if defined(PSA_WANT_ALG_PBKDF2_HMAC) || defined(PSA_WANT_ALG_PBKDF2_AES_CMAC_PRF_128)
static const uint8_t PBKDF2_CMAC_SALT1[] = "Thread";
static const uint8_t PBKDF2_CMAC_SALT2[] = "\000\001\002\003\004\005\006\007";
static const uint8_t PBKDF2_CMAC_SALT3[] = "Test Network";
#endif
#if defined(PSA_WANT_ALG_PBKDF2_AES_CMAC_PRF_128)
static const uint8_t PBKDF2_CMAC_SALT[] = "Thread" "\000\001\002\003\004\005\006\007" "Test Network";
static const uint8_t PBKDF2_CMAC_K16k[] = {
    0xc3, 0xf5, 0x93, 0x68, 0x44, 0x5a, 0x1b, 0x61, 0x06, 0xbe, 0x42, 0x0a, 0x70, 0x6d, 0x4c, 0xc9};
#endif

#if defined(PSA_WANT_ALG_PBKDF2_HMAC) || defined(PSA_WANT_ALG_PBKDF2_AES_CMAC_PRF_128)
static int test_pbkdf2(psa_algorithm_t alg, uint32_t it,
    const uint8_t *pw, size_t pw_len,
    const uint8_t *salt, size_t salt_len,
    const uint8_t *ref, size_t ref_len)
{
    psa_key_derivation_operation_t op = PSA_KEY_DERIVATION_OPERATION_INIT;
    uint8_t data[64];
    psa_key_attributes_t pw_attr = PSA_KEY_ATTRIBUTES_INIT;
    psa_key_id_t pw_key = 0;
    psa_key_attributes_t salt_attr = PSA_KEY_ATTRIBUTES_INIT;
    psa_key_id_t salt_key = 0;
    psa_key_attributes_t out_attr = PSA_KEY_ATTRIBUTES_INIT;
    psa_key_id_t out_key = 0;
    size_t size;
    int res = 0;

    psa_set_key_usage_flags(&pw_attr, PSA_KEY_USAGE_DERIVE);
    psa_set_key_algorithm(&pw_attr, alg);
    psa_set_key_type(&pw_attr, PSA_KEY_TYPE_PASSWORD);  // or PSA_KEY_TYPE_DERIVE
    TEST_ASSERT(psa_import_key(&pw_attr, pw, pw_len, &pw_key) == PSA_SUCCESS);

    psa_set_key_usage_flags(&salt_attr, PSA_KEY_USAGE_DERIVE);
    psa_set_key_algorithm(&salt_attr, alg);
    psa_set_key_type(&salt_attr, PSA_KEY_TYPE_PEPPER);  // or PSA_KEY_TYPE_RAW_DATA
    TEST_ASSERT(psa_import_key(&salt_attr, salt, salt_len, &salt_key) == PSA_SUCCESS);

    psa_set_key_usage_flags(&out_attr, PSA_KEY_USAGE_EXPORT);
    psa_set_key_algorithm(&out_attr, alg);
    psa_set_key_type(&out_attr, PSA_KEY_TYPE_PASSWORD_HASH);
    psa_set_key_bits(&out_attr, PSA_BYTES_TO_BITS(ref_len));

    TEST_ASSERT(psa_key_derivation_setup(&op, alg) == PSA_SUCCESS);
    TEST_ASSERT(psa_key_derivation_input_integer(&op, PSA_KEY_DERIVATION_INPUT_COST, it) == PSA_SUCCESS);
    TEST_ASSERT(psa_key_derivation_input_bytes(&op, PSA_KEY_DERIVATION_INPUT_SALT, salt, salt_len) == PSA_SUCCESS);
    TEST_ASSERT(psa_key_derivation_input_bytes(&op, PSA_KEY_DERIVATION_INPUT_PASSWORD, pw, pw_len) == PSA_SUCCESS);
    TEST_ASSERT(psa_key_derivation_output_bytes(&op, data, ref_len) == PSA_SUCCESS);
    ASSERT_COMPARE(data, ref_len, ref, ref_len);
    TEST_ASSERT(psa_key_derivation_abort(&op) == PSA_SUCCESS);

    TEST_ASSERT(psa_key_derivation_setup(&op, alg) == PSA_SUCCESS);
    TEST_ASSERT(psa_key_derivation_input_integer(&op, PSA_KEY_DERIVATION_INPUT_COST, it) == PSA_SUCCESS);
    TEST_ASSERT(psa_key_derivation_input_bytes(&op, PSA_KEY_DERIVATION_INPUT_SALT, salt, salt_len) == PSA_SUCCESS);
    TEST_ASSERT(psa_key_derivation_input_key(&op, PSA_KEY_DERIVATION_INPUT_PASSWORD, pw_key) == PSA_SUCCESS);
    TEST_ASSERT(psa_key_derivation_output_bytes(&op, data, ref_len) == PSA_SUCCESS);
    ASSERT_COMPARE(data, ref_len, ref, ref_len);
    TEST_ASSERT(psa_key_derivation_abort(&op) == PSA_SUCCESS);

    TEST_ASSERT(psa_key_derivation_setup(&op, alg) == PSA_SUCCESS);
    TEST_ASSERT(psa_key_derivation_input_integer(&op, PSA_KEY_DERIVATION_INPUT_COST, it) == PSA_SUCCESS);
    TEST_ASSERT(psa_key_derivation_input_bytes(&op, PSA_KEY_DERIVATION_INPUT_SALT, (const uint8_t *) "salt", 4) == PSA_SUCCESS);
    TEST_ASSERT(psa_key_derivation_input_bytes(&op, PSA_KEY_DERIVATION_INPUT_PASSWORD, pw, pw_len) == PSA_SUCCESS);
    TEST_ASSERT(psa_key_derivation_output_key(&out_attr, &op, &out_key) == PSA_ERROR_NOT_PERMITTED); // bytes -> key is not allowed
    TEST_ASSERT(psa_key_derivation_abort(&op) == PSA_SUCCESS);

    TEST_ASSERT(psa_key_derivation_setup(&op, alg) == PSA_SUCCESS);
    TEST_ASSERT(psa_key_derivation_input_integer(&op, PSA_KEY_DERIVATION_INPUT_COST, it) == PSA_SUCCESS);
    TEST_ASSERT(psa_key_derivation_input_bytes(&op, PSA_KEY_DERIVATION_INPUT_SALT, salt, salt_len) == PSA_SUCCESS);
    TEST_ASSERT(psa_key_derivation_input_key(&op, PSA_KEY_DERIVATION_INPUT_PASSWORD, pw_key) == PSA_SUCCESS);
    TEST_ASSERT(psa_key_derivation_output_key(&out_attr, &op, &out_key) == PSA_SUCCESS);
    TEST_ASSERT(psa_export_key(out_key, data, sizeof data, &size) == PSA_SUCCESS);
    ASSERT_COMPARE(data, size, ref, ref_len);
    TEST_ASSERT(psa_key_derivation_abort(&op) == PSA_SUCCESS);
    TEST_ASSERT(psa_destroy_key(out_key) == PSA_SUCCESS);

    TEST_ASSERT(psa_key_derivation_setup(&op, alg) == PSA_SUCCESS);
    TEST_ASSERT(psa_key_derivation_input_integer(&op, PSA_KEY_DERIVATION_INPUT_COST, it) == PSA_SUCCESS);
    TEST_ASSERT(psa_key_derivation_input_key(&op, PSA_KEY_DERIVATION_INPUT_SALT, salt_key) == PSA_SUCCESS);
    TEST_ASSERT(psa_key_derivation_input_key(&op, PSA_KEY_DERIVATION_INPUT_PASSWORD, pw_key) == PSA_SUCCESS);
    TEST_ASSERT(psa_key_derivation_output_key(&out_attr, &op, &out_key) == PSA_SUCCESS);
    TEST_ASSERT(psa_export_key(out_key, data, sizeof data, &size) == PSA_SUCCESS);
    ASSERT_COMPARE(data, size, ref, ref_len);
    TEST_ASSERT(psa_key_derivation_abort(&op) == PSA_SUCCESS);
    TEST_ASSERT(psa_destroy_key(out_key) == PSA_SUCCESS);

    if (salt_len == 26) { // test incremental salt
        TEST_ASSERT(psa_key_derivation_setup(&op, alg) == PSA_SUCCESS);
        TEST_ASSERT(psa_key_derivation_input_integer(&op, PSA_KEY_DERIVATION_INPUT_COST, it) == PSA_SUCCESS);
        TEST_ASSERT(psa_key_derivation_input_bytes(&op, PSA_KEY_DERIVATION_INPUT_SALT, PBKDF2_CMAC_SALT1, 6) == PSA_SUCCESS);
        TEST_ASSERT(psa_key_derivation_input_bytes(&op, PSA_KEY_DERIVATION_INPUT_SALT, PBKDF2_CMAC_SALT2, 8) == PSA_SUCCESS);
        TEST_ASSERT(psa_key_derivation_input_bytes(&op, PSA_KEY_DERIVATION_INPUT_SALT, PBKDF2_CMAC_SALT3, 12) == PSA_SUCCESS);
        TEST_ASSERT(psa_key_derivation_input_bytes(&op, PSA_KEY_DERIVATION_INPUT_PASSWORD, pw, pw_len) == PSA_SUCCESS);
        TEST_ASSERT(psa_key_derivation_output_bytes(&op, data, ref_len) == PSA_SUCCESS);
        ASSERT_COMPARE(data, ref_len, ref, ref_len);
        TEST_ASSERT(psa_key_derivation_abort(&op) == PSA_SUCCESS);
    }

    res = 1;
exit:
    TEST_ASSERT(psa_destroy_key(pw_key) == PSA_SUCCESS);
    TEST_ASSERT(psa_destroy_key(salt_key) == PSA_SUCCESS);

    return res;
}
#endif // defined(PSA_WANT_ALG_PBKDF2_HMAC) || defined(PSA_WANT_ALG_PBKDF2_AES_CMAC_PRF_128)


#ifdef PSA_WANT_ALG_SP800_108_COUNTER_HMAC
uint8_t SP800_108_HMAC_Key[32] = {1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,31,32};
static const uint8_t SP800_108_HMAC_K1[] = {
    0xf8, 0xb7, 0x24, 0x82, 0x0d, 0xf0, 0xef, 0xea, 0x81, 0xc2, 0x52, 0xb6, 0x7a, 0x88, 0x60, 0xb6,
    0x44, 0xd3, 0xc3, 0x7b, 0x9f, 0xce, 0x78, 0x24, 0x58, 0x21, 0x4f, 0x14, 0xc6, 0x61, 0xc0, 0x0a};
static const uint8_t SP800_108_HMAC_K2[] = {
    0x1e, 0xe4, 0x54, 0x9b, 0x54, 0x9c, 0x79, 0x9b, 0x2e, 0x9c, 0x6e, 0x40, 0x81, 0xc3, 0x02, 0x8c,
    0x03, 0xeb, 0x73, 0x08, 0x45, 0xb1, 0x79, 0xf1, 0xc9, 0xce, 0x13, 0xe0, 0xc9, 0x6b, 0x53, 0xf7};
static const uint8_t SP800_108_HMAC_K3[] = {
    0x3d, 0x04, 0xc0, 0x28, 0x61, 0x89, 0xc8, 0xbd, 0x18, 0x3d, 0x43, 0x4d, 0xe3, 0xc3, 0x17, 0xc0,
    0xae, 0x8c, 0xa5, 0x1c, 0xf6, 0xf7, 0x7c, 0x8b, 0xac, 0xec, 0xd0, 0x70, 0xf6, 0x15, 0x29, 0xfe};
static const uint8_t SP800_108_HMAC_K4[] = {
    0x86, 0xf3, 0xaa, 0x9a, 0x5a, 0x76, 0x02, 0x71, 0x3f, 0x37, 0x99, 0x6c, 0x28, 0x8b, 0xc2, 0x7b,
    0xa1, 0x97, 0xd5, 0xa7, 0x89, 0x57, 0xdd, 0xc9, 0x64, 0x04, 0x43, 0x69, 0x2f, 0xb0, 0x41, 0x34};

// Vectors from mbedtls/examples/crypto/SP800-108_counter_KDF/README.md
static const uint8_t SP800_108_HMAC_Key1[] = {
    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0d, 0x0f,
    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0d, 0x0f};
static const uint8_t SP800_108_HMAC_Label1[] = {
    0x50, 0x53, 0x41, 0x5f, 0x41, 0x4c, 0x47, 0x5f, 0x53, 0x50, 0x38, 0x30, 0x30, 0x5f, 0x31, 0x30,
    0x38, 0x5f, 0x43, 0x4f, 0x55, 0x4e, 0x54, 0x45, 0x52, 0x20, 0x53, 0x61, 0x6d, 0x70, 0x6c, 0x65};
static const uint8_t SP800_108_HMAC_Context1[] = {
    0x53, 0x61, 0x6d, 0x70, 0x6c, 0x65, 0x20, 0x6b, 0x65, 0x79, 0x20, 0x63, 0x72, 0x65, 0x61, 0x74,
    0x69, 0x6f, 0x6e, 0x20, 0x76, 0x69, 0x61, 0x20, 0x53, 0x50, 0x20, 0x38, 0x30, 0x30, 0x2d, 0x31,
    0x30, 0x38, 0x72, 0x31, 0x20, 0x43, 0x6f, 0x75, 0x6e, 0x74, 0x65, 0x72, 0x20, 0x6d, 0x6f, 0x64,
    0x65};
static const uint8_t SP800_108_HMAC_Output1[] = {
    0x81, 0x58, 0xcd, 0x6a, 0xe7, 0x50, 0x69, 0x0c, 0x20, 0x54, 0xbe, 0x10, 0x66, 0xd2, 0xd8, 0xf3,
    0x4a, 0xb0, 0x14, 0xd0, 0x7f, 0x81, 0x4c, 0xbc, 0x7d, 0x3e, 0x3d, 0xca, 0x78, 0xa9, 0x3f, 0x5d,
    0x66, 0x29, 0xb1, 0x14, 0xb4, 0x2a, 0x04, 0x64, 0xa4, 0x89};

static const uint8_t SP800_108_HMAC_Key2[] = {
    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0d, 0x0f,
    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0d, 0x0f};
static const uint8_t SP800_108_HMAC_Label2[] = {
    0x50, 0x53, 0x41, 0x5f, 0x41, 0x4c, 0x47, 0x5f, 0x53, 0x50, 0x38, 0x30, 0x30, 0x5f, 0x31, 0x30,
    0x38, 0x5f, 0x43, 0x4f, 0x55, 0x4e, 0x54, 0x45, 0x52, 0x20, 0x53, 0x61, 0x6d, 0x70, 0x6c, 0x65};
static const uint8_t SP800_108_HMAC_Output2[] = {
    0x2f, 0xe0, 0x5b, 0xd4, 0x22, 0x00, 0x4f, 0xa1, 0x9a, 0x48, 0xcd, 0x8c, 0x9b, 0xd2, 0xca, 0x8d,
    0x39, 0x87, 0xea, 0x6c, 0x5a, 0xbc, 0xd5, 0x54, 0x3a, 0xed, 0xeb, 0x04, 0xe2, 0xb7, 0x00, 0x0c,
    0xb6, 0xeb, 0x18, 0xc3, 0x3a, 0x3d, 0x89, 0x67, 0xa7, 0xd6};
#endif

#ifdef PSA_WANT_ALG_SP800_108_COUNTER_CMAC
uint8_t SP800_108_CMAC_Key[32] = {1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,31,32};
static const uint8_t SP800_108_CMAC_K1[] = {
    0x43, 0x88, 0xc2, 0xb6, 0xfb, 0xa7, 0xd5, 0x98, 0x62, 0xb4, 0xd8, 0x83, 0xbb, 0x55, 0xae, 0xa3,
    0x8f, 0x36, 0x28, 0x9f, 0x76, 0x72, 0x7c, 0x9d, 0xdf, 0xce, 0x6c, 0xca, 0xff, 0x6d, 0x20, 0xf0};
static const uint8_t SP800_108_CMAC_K2[] = {
    0x5b, 0x59, 0x24, 0xfb, 0x1e, 0x25, 0xe0, 0x1f, 0x40, 0x87, 0x76, 0x28, 0xa7, 0x32, 0xd5, 0x0c,
    0x2b, 0x3a, 0xb7, 0x96, 0x23, 0x32, 0xbf, 0x37, 0xc7, 0x4e, 0x52, 0x77, 0x40, 0x04, 0x4b, 0x9a};
static const uint8_t SP800_108_CMAC_K3[] = {
    0xb6, 0x23, 0x2f, 0x4d, 0x07, 0xdd, 0xde, 0x57, 0x2d, 0x5c, 0x6c, 0x47, 0x19, 0x67, 0x1f, 0x2a,
    0x17, 0xea, 0xb9, 0x6c, 0x65, 0x45, 0x13, 0xe0, 0x85, 0xd2, 0x8d, 0x0c, 0x64, 0x06, 0x06, 0x44};
static const uint8_t SP800_108_CMAC_K4[] = {
    0x7f, 0xff, 0x10, 0x9e, 0xe2, 0xb9, 0x08, 0x17, 0xbc, 0xfa, 0x9c, 0x28, 0x07, 0x94, 0x45, 0x8e,
    0xae, 0x43, 0xc0, 0x2a, 0x3f, 0x4d, 0xd9, 0x9d, 0x5c, 0x66, 0x70, 0x90, 0x7f, 0xf6, 0x66, 0x50};

// Vectors from mbedtls/examples/crypto/SP800-108_counter_KDF/README.md
static const uint8_t SP800_108_CMAC_Key1[] = {
    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0d, 0x0f};
static const uint8_t SP800_108_CMAC_Label1[] = {
    0x50, 0x53, 0x41, 0x5f, 0x41, 0x4c, 0x47, 0x5f, 0x53, 0x50, 0x38, 0x30, 0x30, 0x5f, 0x31, 0x30,
    0x38, 0x5f, 0x43, 0x4f, 0x55, 0x4e, 0x54, 0x45, 0x52, 0x20, 0x53, 0x61, 0x6d, 0x70, 0x6c, 0x65};
static const uint8_t SP800_108_CMAC_Context1[] = {
    0x53, 0x61, 0x6d, 0x70, 0x6c, 0x65, 0x20, 0x6b, 0x65, 0x79, 0x20, 0x63, 0x72, 0x65, 0x61, 0x74,
    0x69, 0x6f, 0x6e, 0x20, 0x76, 0x69, 0x61, 0x20, 0x53, 0x50, 0x20, 0x38, 0x30, 0x30, 0x2d, 0x31,
    0x30, 0x38, 0x72, 0x31, 0x20, 0x43, 0x6f, 0x75, 0x6e, 0x74, 0x65, 0x72, 0x20, 0x6d, 0x6f, 0x64,
    0x65};
static const uint8_t SP800_108_CMAC_Output1[] = {
    0x3c, 0x50, 0xb5, 0x5a, 0x13, 0xb9, 0x49, 0xad, 0x25, 0xb4, 0xb4, 0x0f, 0xc3, 0x7f, 0x55, 0x38,
    0x36, 0xb5, 0x9f, 0xa0, 0xd0, 0x74, 0xb7, 0x3c, 0x83, 0x17, 0x6d, 0x4c, 0x10, 0x5f, 0xc2, 0x17,
    0x83, 0x8e, 0xc4, 0xa1, 0xb0, 0x7b, 0x8a, 0xbe, 0xa8, 0xf1};

static const uint8_t SP800_108_CMAC_Key2[] = {
    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0d, 0x0f};
static const uint8_t SP800_108_CMAC_Label2[] = {
    0x50, 0x53, 0x41, 0x5f, 0x41, 0x4c, 0x47, 0x5f, 0x53, 0x50, 0x38, 0x30, 0x30, 0x5f, 0x31, 0x30,
    0x38, 0x5f, 0x43, 0x4f, 0x55, 0x4e, 0x54, 0x45, 0x52, 0x20, 0x53, 0x61, 0x6d, 0x70, 0x6c, 0x65};
static const uint8_t SP800_108_CMAC_Output2[] = {
    0xe1, 0xec, 0xfc, 0000, 0x1e, 0x2e, 0x9a, 0xdb, 0xd0, 0x16, 0xb3, 0xb4, 0xf3, 0x23, 0xce, 0000,
    0xc1, 0x05, 0x82, 0xec, 0x81, 0xe1, 0xfc, 0x19, 0x40, 0x47, 0x4c, 0xa6, 0x84, 0xf9, 0xe5, 0x07,
    0xb5, 0x8a, 0xbd, 0x03, 0xbc, 0xe5, 0x23, 0x82, 0x05, 0x11};

#endif

#if defined(PSA_WANT_ALG_SP800_108_COUNTER_HMAC) || defined(PSA_WANT_ALG_SP800_108_COUNTER_CMAC)
static int test_sp800_108_counter(psa_algorithm_t alg,
    const uint8_t *key, size_t key_len,
    const uint8_t *label, size_t label_len,
    const uint8_t *context, size_t context_len,
    const uint8_t *ref, size_t ref_len)
{
    psa_key_derivation_operation_t op = PSA_KEY_DERIVATION_OPERATION_INIT;
    uint8_t data[64];
    psa_key_attributes_t key_attr = PSA_KEY_ATTRIBUTES_INIT;
    psa_key_id_t key_id = 0;
    psa_key_attributes_t label_attr = PSA_KEY_ATTRIBUTES_INIT;
    psa_key_id_t label_key = 0;
    psa_key_attributes_t out_attr = PSA_KEY_ATTRIBUTES_INIT;
    psa_key_id_t out_key = 0;
    size_t size;
    int res = 0;

    psa_set_key_usage_flags(&key_attr, PSA_KEY_USAGE_DERIVE);
    psa_set_key_algorithm(&key_attr, alg);
    psa_set_key_type(&key_attr, PSA_KEY_TYPE_DERIVE);
    TEST_ASSERT(psa_import_key(&key_attr, key, key_len, &key_id) == PSA_SUCCESS);

    if (label) {
        psa_set_key_usage_flags(&label_attr, PSA_KEY_USAGE_DERIVE);
        psa_set_key_algorithm(&label_attr, alg);
        psa_set_key_type(&label_attr, PSA_KEY_TYPE_RAW_DATA);  // or PSA_KEY_TYPE_RAW_DATA
        TEST_ASSERT(psa_import_key(&label_attr, label, label_len, &label_key) == PSA_SUCCESS);
    }

    psa_set_key_usage_flags(&out_attr, PSA_KEY_USAGE_EXPORT);
    psa_set_key_algorithm(&out_attr, alg);
    psa_set_key_type(&out_attr, PSA_KEY_TYPE_PASSWORD_HASH);
    psa_set_key_bits(&out_attr, PSA_BYTES_TO_BITS(ref_len));

    TEST_ASSERT(psa_key_derivation_setup(&op, alg) == PSA_SUCCESS);
    TEST_ASSERT(psa_key_derivation_input_bytes(&op, PSA_KEY_DERIVATION_INPUT_SECRET, key, key_len) == PSA_SUCCESS);
    if (label) {
        TEST_ASSERT(psa_key_derivation_input_bytes(&op, PSA_KEY_DERIVATION_INPUT_LABEL, label, label_len) == PSA_SUCCESS);
    }
    if (context) {
        TEST_ASSERT(psa_key_derivation_input_bytes(&op, PSA_KEY_DERIVATION_INPUT_CONTEXT, context, context_len) == PSA_SUCCESS);
    }
    TEST_ASSERT(psa_key_derivation_set_capacity(&op, ref_len) == PSA_SUCCESS);
    TEST_ASSERT(psa_key_derivation_output_bytes(&op, data, ref_len) == PSA_SUCCESS);
    ASSERT_COMPARE(data, ref_len, ref, ref_len);
    TEST_ASSERT(psa_key_derivation_abort(&op) == PSA_SUCCESS);

    TEST_ASSERT(psa_key_derivation_setup(&op, alg) == PSA_SUCCESS);
    TEST_ASSERT(psa_key_derivation_set_capacity(&op, ref_len) == PSA_SUCCESS);
    TEST_ASSERT(psa_key_derivation_input_key(&op, PSA_KEY_DERIVATION_INPUT_SECRET, key_id) == PSA_SUCCESS);
    if (label) {
        TEST_ASSERT(psa_key_derivation_input_key(&op, PSA_KEY_DERIVATION_INPUT_LABEL, label_key) == PSA_SUCCESS);
    }
    if (context) {
        TEST_ASSERT(psa_key_derivation_input_bytes(&op, PSA_KEY_DERIVATION_INPUT_CONTEXT, context, context_len) == PSA_SUCCESS);
    }
    TEST_ASSERT(psa_key_derivation_output_bytes(&op, data, ref_len) == PSA_SUCCESS);
    ASSERT_COMPARE(data, ref_len, ref, ref_len);
    TEST_ASSERT(psa_key_derivation_abort(&op) == PSA_SUCCESS);

    TEST_ASSERT(psa_key_derivation_setup(&op, alg) == PSA_SUCCESS);
    TEST_ASSERT(psa_key_derivation_input_key(&op, PSA_KEY_DERIVATION_INPUT_SECRET, key_id) == PSA_SUCCESS);
    if (label) {
        TEST_ASSERT(psa_key_derivation_input_key(&op, PSA_KEY_DERIVATION_INPUT_LABEL, label_key) == PSA_SUCCESS);
    }
    TEST_ASSERT(psa_key_derivation_set_capacity(&op, ref_len) == PSA_SUCCESS);
    if (context) {
        TEST_ASSERT(psa_key_derivation_input_bytes(&op, PSA_KEY_DERIVATION_INPUT_CONTEXT, context, context_len) == PSA_SUCCESS);
    }
    TEST_ASSERT(psa_key_derivation_output_key(&out_attr, &op, &out_key) == PSA_SUCCESS);
    TEST_ASSERT(psa_export_key(out_key, data, sizeof data, &size) == PSA_SUCCESS);
    ASSERT_COMPARE(data, size, ref, ref_len);
    TEST_ASSERT(psa_key_derivation_abort(&op) == PSA_SUCCESS);
    TEST_ASSERT(psa_destroy_key(out_key) == PSA_SUCCESS);

    res = 1;
exit:
    TEST_ASSERT(psa_destroy_key(key_id) == PSA_SUCCESS);
    TEST_ASSERT(psa_destroy_key(label_key) == PSA_SUCCESS);

    return res;
}
#endif // PSA_WANT_ALG_SP800_108_COUNTER_CMAC || PSA_WANT_ALG_SP800_108_COUNTER_CMAC


// Tests for psa_key_derivation_verify_key / psa_key_derivation_verify_bytes
#ifdef PSA_WANT_ALG_HKDF
static int test_key_derivation_verify(
    psa_key_usage_t key_usage, psa_key_usage_t info_usage, psa_key_usage_t out_usage,
    int verify, psa_status_t expected)
{
    psa_key_derivation_operation_t op = PSA_KEY_DERIVATION_OPERATION_INIT;
    psa_key_attributes_t key_attr = PSA_KEY_ATTRIBUTES_INIT;
    psa_key_id_t key_id = 0;
    psa_key_attributes_t info_attr = PSA_KEY_ATTRIBUTES_INIT;
    psa_key_id_t info_key = 0;
    psa_key_attributes_t out_attr = PSA_KEY_ATTRIBUTES_INIT;
    psa_key_id_t out_key = 0;
    int res = 0;

    uint8_t key_data[32] = {1,2,3};
    uint8_t ref_data[32];
    uint8_t out_data[32];

    if (verify) {
        TEST_ASSERT(psa_key_derivation_setup(&op, PSA_ALG_HKDF(PSA_ALG_SHA_256)) == PSA_SUCCESS);
        TEST_ASSERT(psa_key_derivation_input_bytes(&op, PSA_KEY_DERIVATION_INPUT_SECRET, key_data, sizeof key_data) == PSA_SUCCESS);
        TEST_ASSERT(psa_key_derivation_input_bytes(&op, PSA_KEY_DERIVATION_INPUT_INFO, key_data, sizeof key_data) == PSA_SUCCESS);
        TEST_ASSERT(psa_key_derivation_output_bytes(&op, ref_data, sizeof ref_data) == PSA_SUCCESS);
        TEST_ASSERT(psa_key_derivation_abort(&op) == PSA_SUCCESS);
    }

    TEST_ASSERT(psa_key_derivation_setup(&op, PSA_ALG_HKDF(PSA_ALG_SHA_256)) == PSA_SUCCESS);

    if (key_usage) {
        psa_set_key_usage_flags(&key_attr, key_usage);
        psa_set_key_algorithm(&key_attr, PSA_ALG_HKDF(PSA_ALG_SHA_256));
        psa_set_key_type(&key_attr, PSA_KEY_TYPE_DERIVE);
        TEST_ASSERT(psa_import_key(&key_attr, key_data, sizeof key_data, &key_id) == PSA_SUCCESS);
        TEST_ASSERT(psa_key_derivation_input_key(&op, PSA_KEY_DERIVATION_INPUT_SECRET, key_id) == PSA_SUCCESS);
    } else {
        TEST_ASSERT(psa_key_derivation_input_bytes(&op, PSA_KEY_DERIVATION_INPUT_SECRET, key_data, sizeof key_data) == PSA_SUCCESS);
    }

    if (info_usage) {
        psa_set_key_usage_flags(&info_attr, info_usage);
        psa_set_key_algorithm(&info_attr, PSA_ALG_HKDF(PSA_ALG_SHA_256));
        psa_set_key_type(&info_attr, PSA_KEY_TYPE_RAW_DATA);
        TEST_ASSERT(psa_import_key(&info_attr, key_data, sizeof key_data, &info_key) == PSA_SUCCESS);
        TEST_ASSERT(psa_key_derivation_input_key(&op, PSA_KEY_DERIVATION_INPUT_INFO, info_key) == PSA_SUCCESS);
    } else {
        TEST_ASSERT(psa_key_derivation_input_bytes(&op, PSA_KEY_DERIVATION_INPUT_INFO, key_data, sizeof key_data) == PSA_SUCCESS);
    }

    if (out_usage) {
        psa_set_key_usage_flags(&out_attr, out_usage);
        psa_set_key_algorithm(&out_attr, PSA_ALG_HKDF(PSA_ALG_SHA_256));
        psa_set_key_type(&out_attr, PSA_KEY_TYPE_PASSWORD_HASH);
        if (verify) {
            TEST_ASSERT(psa_import_key(&out_attr, ref_data, sizeof ref_data, &out_key) == PSA_SUCCESS);
            TEST_ASSERT(psa_key_derivation_verify_key(&op, out_key) == expected);
        } else {
            psa_set_key_bits(&out_attr, PSA_BYTES_TO_BITS(sizeof out_data));
            TEST_ASSERT(psa_key_derivation_output_key(&out_attr, &op, &out_key) == expected);
        }
    } else {
        if (verify) {
            TEST_ASSERT(psa_key_derivation_verify_bytes(&op, ref_data, sizeof ref_data) == expected);
        } else {
            TEST_ASSERT(psa_key_derivation_output_bytes(&op, out_data, sizeof out_data) == expected);
        }
    }

    TEST_ASSERT(psa_key_derivation_abort(&op) == PSA_SUCCESS);

    res = 1;
exit:
    TEST_ASSERT(psa_destroy_key(key_id) == PSA_SUCCESS);
    TEST_ASSERT(psa_destroy_key(info_key) == PSA_SUCCESS);
    TEST_ASSERT(psa_destroy_key(out_key) == PSA_SUCCESS);

    return res;
}
#endif // PSA_WANT_ALG_HKDF


int main(void)
{
    TEST_ASSERT(psa_crypto_init() == PSA_SUCCESS);

#ifdef PSA_WANT_ALG_PBKDF2_HMAC
    TEST_ASSERT(test_pbkdf2(PSA_ALG_PBKDF2_HMAC(PSA_ALG_SHA_1), 1, (const uint8_t *) "password", 8, (const uint8_t *) "salt", 4, PBKDF2_SHA1_K1, sizeof PBKDF2_SHA1_K1));
    TEST_ASSERT(test_pbkdf2(PSA_ALG_PBKDF2_HMAC(PSA_ALG_SHA_1), 2, (const uint8_t *) "password", 8, (const uint8_t *) "salt", 4, PBKDF2_SHA1_K2, sizeof PBKDF2_SHA1_K2));
    TEST_ASSERT(test_pbkdf2(PSA_ALG_PBKDF2_HMAC(PSA_ALG_SHA_1), 4096, (const uint8_t *) "password", 8, (const uint8_t *) "salt", 4, PBKDF2_SHA1_K4k, sizeof PBKDF2_SHA1_K4k));
    TEST_ASSERT(test_pbkdf2(PSA_ALG_PBKDF2_HMAC(PSA_ALG_SHA_256), 1, (const uint8_t *) "password", 8, (const uint8_t *) "salt", 4, PBKDF2_SHA256_K1, sizeof PBKDF2_SHA256_K1));
    TEST_ASSERT(test_pbkdf2(PSA_ALG_PBKDF2_HMAC(PSA_ALG_SHA_256), 2, (const uint8_t *) "password", 8, (const uint8_t *) "salt", 4, PBKDF2_SHA256_K2, sizeof PBKDF2_SHA256_K2));
    TEST_ASSERT(test_pbkdf2(PSA_ALG_PBKDF2_HMAC(PSA_ALG_SHA_256), 4096, (const uint8_t *) "password", 8, (const uint8_t *) "salt", 4, PBKDF2_SHA256_K4k, sizeof PBKDF2_SHA256_K4k));
#endif

#ifdef PSA_WANT_ALG_PBKDF2_AES_CMAC_PRF_128
    TEST_ASSERT(test_pbkdf2(PSA_ALG_PBKDF2_AES_CMAC_PRF_128, 16384, (const uint8_t *) "12SECRETPASSWORD34", 18, PBKDF2_CMAC_SALT, 26, PBKDF2_CMAC_K16k, sizeof PBKDF2_CMAC_K16k));
#endif

#ifdef PSA_WANT_ALG_SP800_108_COUNTER_HMAC
    TEST_ASSERT(test_sp800_108_counter(PSA_ALG_SP800_108_COUNTER_HMAC(PSA_ALG_SHA_256), SP800_108_HMAC_Key, sizeof SP800_108_HMAC_Key,
        NULL, 0, NULL, 0, SP800_108_HMAC_K1, sizeof SP800_108_HMAC_K1));
    TEST_ASSERT(test_sp800_108_counter(PSA_ALG_SP800_108_COUNTER_HMAC(PSA_ALG_SHA_256), SP800_108_HMAC_Key, sizeof SP800_108_HMAC_Key,
        (const uint8_t *) "label", 5, NULL, 0, SP800_108_HMAC_K2, sizeof SP800_108_HMAC_K2));
    TEST_ASSERT(test_sp800_108_counter(PSA_ALG_SP800_108_COUNTER_HMAC(PSA_ALG_SHA_256), SP800_108_HMAC_Key, sizeof SP800_108_HMAC_Key,
        NULL, 0, (const uint8_t *) "context", 7, SP800_108_HMAC_K3, sizeof SP800_108_HMAC_K3));
    TEST_ASSERT(test_sp800_108_counter(PSA_ALG_SP800_108_COUNTER_HMAC(PSA_ALG_SHA_256), SP800_108_HMAC_Key, sizeof SP800_108_HMAC_Key,
        (const uint8_t *) "label", 5, (const uint8_t *) "context", 7, SP800_108_HMAC_K4, sizeof SP800_108_HMAC_K4));
    TEST_ASSERT(test_sp800_108_counter(PSA_ALG_SP800_108_COUNTER_HMAC(PSA_ALG_SHA_256), SP800_108_HMAC_Key1, sizeof SP800_108_HMAC_Key1,
        SP800_108_HMAC_Label1, sizeof SP800_108_HMAC_Label1, SP800_108_HMAC_Context1, sizeof SP800_108_HMAC_Context1, SP800_108_HMAC_Output1, sizeof SP800_108_HMAC_Output1));
    TEST_ASSERT(test_sp800_108_counter(PSA_ALG_SP800_108_COUNTER_HMAC(PSA_ALG_SHA_256), SP800_108_HMAC_Key2, sizeof SP800_108_HMAC_Key2,
        SP800_108_HMAC_Label2, sizeof SP800_108_HMAC_Label2, NULL, 0, SP800_108_HMAC_Output2, sizeof SP800_108_HMAC_Output2));
#endif

#ifdef PSA_WANT_ALG_SP800_108_COUNTER_CMAC
    TEST_ASSERT(test_sp800_108_counter(PSA_ALG_SP800_108_COUNTER_CMAC, SP800_108_CMAC_Key, sizeof SP800_108_CMAC_Key,
        NULL, 0, NULL, 0, SP800_108_CMAC_K1, sizeof SP800_108_CMAC_K1));
    TEST_ASSERT(test_sp800_108_counter(PSA_ALG_SP800_108_COUNTER_CMAC, SP800_108_CMAC_Key, sizeof SP800_108_CMAC_Key,
        (const uint8_t *) "label", 5, NULL, 0, SP800_108_CMAC_K2, sizeof SP800_108_CMAC_K2));
    TEST_ASSERT(test_sp800_108_counter(PSA_ALG_SP800_108_COUNTER_CMAC, SP800_108_CMAC_Key, sizeof SP800_108_CMAC_Key,
        NULL, 0, (const uint8_t *) "context", 7, SP800_108_CMAC_K3, sizeof SP800_108_CMAC_K3));
    TEST_ASSERT(test_sp800_108_counter(PSA_ALG_SP800_108_COUNTER_CMAC, SP800_108_CMAC_Key, sizeof SP800_108_CMAC_Key,
        (const uint8_t *) "label", 5, (const uint8_t *) "context", 7, SP800_108_CMAC_K4, sizeof SP800_108_CMAC_K4));
    TEST_ASSERT(test_sp800_108_counter(PSA_ALG_SP800_108_COUNTER_CMAC, SP800_108_CMAC_Key1, sizeof SP800_108_CMAC_Key1,
        SP800_108_CMAC_Label1, sizeof SP800_108_CMAC_Label1, SP800_108_CMAC_Context1, sizeof SP800_108_CMAC_Context1, SP800_108_CMAC_Output1, sizeof SP800_108_CMAC_Output1));
    TEST_ASSERT(test_sp800_108_counter(PSA_ALG_SP800_108_COUNTER_CMAC, SP800_108_CMAC_Key2, sizeof SP800_108_CMAC_Key2,
        SP800_108_CMAC_Label2, sizeof SP800_108_CMAC_Label2, NULL, 0, SP800_108_CMAC_Output2, sizeof SP800_108_CMAC_Output2));
#endif

#ifdef PSA_WANT_ALG_HKDF
    // output_bytes
    TEST_ASSERT(test_key_derivation_verify(PSA_KEY_USAGE_DERIVE,            PSA_KEY_USAGE_DERIVE,            0,                               0, PSA_SUCCESS));
    TEST_ASSERT(test_key_derivation_verify(PSA_KEY_USAGE_DERIVE,            0,                               0,                               0, PSA_SUCCESS));
    TEST_ASSERT(test_key_derivation_verify(0,                               PSA_KEY_USAGE_DERIVE,            0,                               0, PSA_SUCCESS));
    TEST_ASSERT(test_key_derivation_verify(0,                               0,                               0,                               0, PSA_SUCCESS));
    TEST_ASSERT(test_key_derivation_verify(0,                               PSA_KEY_USAGE_VERIFY_DERIVATION, 0,                               0, PSA_ERROR_NOT_PERMITTED));
    TEST_ASSERT(test_key_derivation_verify(PSA_KEY_USAGE_VERIFY_DERIVATION, 0,                               0,                               0, PSA_ERROR_NOT_PERMITTED));
    // output_key
    TEST_ASSERT(test_key_derivation_verify(PSA_KEY_USAGE_DERIVE,            PSA_KEY_USAGE_DERIVE,            PSA_KEY_USAGE_DERIVE,            0, PSA_SUCCESS));
    TEST_ASSERT(test_key_derivation_verify(PSA_KEY_USAGE_DERIVE,            0,                               PSA_KEY_USAGE_DERIVE,            0, PSA_SUCCESS));
    TEST_ASSERT(test_key_derivation_verify(0,                               PSA_KEY_USAGE_DERIVE,            PSA_KEY_USAGE_DERIVE,            0, PSA_ERROR_NOT_PERMITTED));
    TEST_ASSERT(test_key_derivation_verify(0,                               0,                               PSA_KEY_USAGE_DERIVE,            0, PSA_ERROR_NOT_PERMITTED));
    TEST_ASSERT(test_key_derivation_verify(0,                               PSA_KEY_USAGE_VERIFY_DERIVATION, PSA_KEY_USAGE_DERIVE,            0, PSA_ERROR_NOT_PERMITTED));
    TEST_ASSERT(test_key_derivation_verify(PSA_KEY_USAGE_VERIFY_DERIVATION, 0,                               PSA_KEY_USAGE_DERIVE,            0, PSA_ERROR_NOT_PERMITTED));
    TEST_ASSERT(test_key_derivation_verify(PSA_KEY_USAGE_DERIVE,            PSA_KEY_USAGE_DERIVE,            PSA_KEY_USAGE_VERIFY_DERIVATION, 0, PSA_SUCCESS));
    // verify_bytes
    TEST_ASSERT(test_key_derivation_verify(PSA_KEY_USAGE_VERIFY_DERIVATION, PSA_KEY_USAGE_VERIFY_DERIVATION, 0,                               1, PSA_SUCCESS));
    TEST_ASSERT(test_key_derivation_verify(PSA_KEY_USAGE_VERIFY_DERIVATION, 0,                               0,                               1, PSA_SUCCESS));
    TEST_ASSERT(test_key_derivation_verify(0,                               PSA_KEY_USAGE_VERIFY_DERIVATION, 0,                               1, PSA_SUCCESS));
    TEST_ASSERT(test_key_derivation_verify(0,                               0,                               0,                               1, PSA_SUCCESS));
    TEST_ASSERT(test_key_derivation_verify(0,                               PSA_KEY_USAGE_DERIVE,            0,                               1, PSA_ERROR_NOT_PERMITTED));
    TEST_ASSERT(test_key_derivation_verify(PSA_KEY_USAGE_DERIVE,            0,                               0,                               1, PSA_ERROR_NOT_PERMITTED));
    // verify_key
    TEST_ASSERT(test_key_derivation_verify(PSA_KEY_USAGE_VERIFY_DERIVATION, PSA_KEY_USAGE_VERIFY_DERIVATION, PSA_KEY_USAGE_VERIFY_DERIVATION, 1, PSA_SUCCESS));
    TEST_ASSERT(test_key_derivation_verify(PSA_KEY_USAGE_VERIFY_DERIVATION, 0,                               PSA_KEY_USAGE_VERIFY_DERIVATION, 1, PSA_SUCCESS));
    TEST_ASSERT(test_key_derivation_verify(0,                               PSA_KEY_USAGE_VERIFY_DERIVATION, PSA_KEY_USAGE_VERIFY_DERIVATION, 1, PSA_SUCCESS));
    TEST_ASSERT(test_key_derivation_verify(0,                               0,                               PSA_KEY_USAGE_VERIFY_DERIVATION, 1, PSA_SUCCESS));
    TEST_ASSERT(test_key_derivation_verify(0,                               PSA_KEY_USAGE_DERIVE,            PSA_KEY_USAGE_VERIFY_DERIVATION, 1, PSA_ERROR_NOT_PERMITTED));
    TEST_ASSERT(test_key_derivation_verify(PSA_KEY_USAGE_DERIVE,            0,                               PSA_KEY_USAGE_VERIFY_DERIVATION, 1, PSA_ERROR_NOT_PERMITTED));
    TEST_ASSERT(test_key_derivation_verify(PSA_KEY_USAGE_VERIFY_DERIVATION, PSA_KEY_USAGE_VERIFY_DERIVATION, PSA_KEY_USAGE_DERIVE,            1, PSA_ERROR_NOT_PERMITTED));
#endif // PSA_WANT_ALG_HKDF

    return 0;
exit:
    return 1;
}
