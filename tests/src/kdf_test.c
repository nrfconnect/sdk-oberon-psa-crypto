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
 * Additional tests for key derivation, XCHACHA20, CBC-PKCS7, Ascon, and XOF.
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
    if (alg == PSA_ALG_SP800_108_COUNTER_CMAC) {
        psa_set_key_type(&key_attr, PSA_KEY_TYPE_AES);
    } else if (PSA_ALG_IS_SP800_108_COUNTER_HMAC(alg)) {
        psa_set_key_type(&key_attr, PSA_KEY_TYPE_HMAC);
    } else {
        psa_set_key_type(&key_attr, PSA_KEY_TYPE_DERIVE);
    }
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

    if (alg != PSA_ALG_SP800_108_COUNTER_CMAC) {
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
    }

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

#ifdef PSA_WANT_ALG_SRP_PASSWORD_HASH
static const uint8_t srp_salt[16] = {
    0xBE, 0xB2, 0x53, 0x79, 0xD1, 0xA8, 0x58, 0x1E, 0xB5, 0xA7, 0x27, 0x67, 0x3A, 0x24, 0x41, 0xEE};

static int srp_password_hash(uint8_t *hash, size_t hash_len,
    const char *user, const char *pw,
    const uint8_t *salt, size_t salt_len,
    psa_algorithm_t hash_alg)
{
    psa_hash_operation_t hash_op = PSA_HASH_OPERATION_INIT;
    size_t length;

    // h = H(salt | H(user | ":" | pass))
    TEST_ASSERT(psa_hash_setup(&hash_op, hash_alg) == PSA_SUCCESS);
    TEST_ASSERT(psa_hash_update(&hash_op, (const uint8_t*)user, strlen(user)) == PSA_SUCCESS);
    TEST_ASSERT(psa_hash_update(&hash_op, (const uint8_t*)":", 1) == PSA_SUCCESS);
    TEST_ASSERT(psa_hash_update(&hash_op, (const uint8_t*)pw, strlen(pw)) == PSA_SUCCESS);
    TEST_ASSERT(psa_hash_finish(&hash_op, hash, hash_len, &length) == PSA_SUCCESS);
    TEST_EQUAL(length, hash_len);

    TEST_ASSERT(psa_hash_setup(&hash_op, hash_alg) == PSA_SUCCESS);
    TEST_ASSERT(psa_hash_update(&hash_op, salt, salt_len) == PSA_SUCCESS);
    TEST_ASSERT(psa_hash_update(&hash_op, hash, length) == PSA_SUCCESS);
    TEST_ASSERT(psa_hash_finish(&hash_op, hash, hash_len, &length) == PSA_SUCCESS);
    TEST_EQUAL(length, hash_len);

    return 1;
exit:
    psa_hash_abort(&hash_op);
    return 0;
}

static int test_srp_password_hash_kdf(psa_algorithm_t hash_alg, const char *password, const char *user)
{
    psa_key_derivation_operation_t kdf = PSA_KEY_DERIVATION_OPERATION_INIT;
    psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;
    psa_key_id_t pkey = 0, skey = 0;
    uint8_t data1[64], data2[64];
    size_t length, hash_len = PSA_HASH_LENGTH(hash_alg);
    int res = 0;

    psa_set_key_usage_flags(&attributes, PSA_KEY_USAGE_DERIVE);
    psa_set_key_algorithm(&attributes, PSA_ALG_SRP_PASSWORD_HASH(hash_alg));
    psa_set_key_bits(&attributes, PSA_BYTES_TO_BITS(strlen(password)));
    psa_set_key_type(&attributes, PSA_KEY_TYPE_PASSWORD);
    TEST_ASSERT(psa_import_key(&attributes, (const uint8_t*)password, strlen(password), &pkey) == PSA_SUCCESS);

    TEST_ASSERT(psa_key_derivation_setup(&kdf, PSA_ALG_SRP_PASSWORD_HASH(hash_alg)) == PSA_SUCCESS);
    TEST_ASSERT(psa_key_derivation_input_bytes(&kdf, PSA_KEY_DERIVATION_INPUT_INFO, (const uint8_t*)user, strlen(user)) == PSA_SUCCESS);
    TEST_ASSERT(psa_key_derivation_input_key(&kdf, PSA_KEY_DERIVATION_INPUT_PASSWORD, pkey) == PSA_SUCCESS);
    TEST_ASSERT(psa_key_derivation_input_bytes(&kdf, PSA_KEY_DERIVATION_INPUT_SALT, srp_salt, sizeof srp_salt) == PSA_SUCCESS);

    psa_set_key_usage_flags(&attributes, PSA_KEY_USAGE_EXPORT);
    psa_set_key_algorithm(&attributes, PSA_ALG_SRP_6(hash_alg));
    psa_set_key_bits(&attributes, 3072);
    psa_set_key_type(&attributes, PSA_KEY_TYPE_SRP_KEY_PAIR(PSA_DH_FAMILY_RFC3526));
    TEST_ASSERT(psa_key_derivation_output_key(&attributes, &kdf, &skey) == PSA_SUCCESS);

    TEST_ASSERT(psa_export_key(skey, data1, sizeof data1, &length) == PSA_SUCCESS);
    TEST_ASSERT(srp_password_hash(data2, hash_len, user, password, srp_salt, sizeof srp_salt, hash_alg));
    ASSERT_COMPARE(data1, length, data2, hash_len);

    res = 1;
exit:
    TEST_ASSERT(psa_key_derivation_abort(&kdf) == PSA_SUCCESS);
    TEST_ASSERT(psa_destroy_key(pkey) == PSA_SUCCESS);
    TEST_ASSERT(psa_destroy_key(skey) == PSA_SUCCESS);

    return res;
}
#endif // PSA_WANT_ALG_SRP_PASSWORD_HASH


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
        if ((key_usage & (PSA_KEY_USAGE_DERIVE | PSA_KEY_USAGE_VERIFY_DERIVATION)) == 0) {
            TEST_ASSERT(psa_key_derivation_input_key(&op, PSA_KEY_DERIVATION_INPUT_SECRET, key_id) == expected);
            res = 1; goto exit;
        } else {
            TEST_ASSERT(psa_key_derivation_input_key(&op, PSA_KEY_DERIVATION_INPUT_SECRET, key_id) == PSA_SUCCESS);
        }
    } else {
        TEST_ASSERT(psa_key_derivation_input_bytes(&op, PSA_KEY_DERIVATION_INPUT_SECRET, key_data, sizeof key_data) == PSA_SUCCESS);
    }

    if (info_usage) {
        psa_set_key_usage_flags(&info_attr, info_usage);
        psa_set_key_algorithm(&info_attr, PSA_ALG_HKDF(PSA_ALG_SHA_256));
        psa_set_key_type(&info_attr, PSA_KEY_TYPE_RAW_DATA);
        TEST_ASSERT(psa_import_key(&info_attr, key_data, sizeof key_data, &info_key) == PSA_SUCCESS);
        if ((info_usage & (PSA_KEY_USAGE_DERIVE | PSA_KEY_USAGE_VERIFY_DERIVATION)) == 0) {
            TEST_ASSERT(psa_key_derivation_input_key(&op, PSA_KEY_DERIVATION_INPUT_INFO, info_key) == expected);
            res = 1; goto exit;
        } else {
            TEST_ASSERT(psa_key_derivation_input_key(&op, PSA_KEY_DERIVATION_INPUT_INFO, info_key) == PSA_SUCCESS);
        }
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


#ifdef PSA_WANT_KEY_TYPE_XCHACHA20

// XChaCha20 test vectors from "draft-irtf-cfrg-xchacha-03"
static const uint8_t xchachaKey[32] = {
    0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87, 0x88, 0x89, 0x8a, 0x8b, 0x8c, 0x8d, 0x8e, 0x8f,
    0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97, 0x98, 0x99, 0x9a, 0x9b, 0x9c, 0x9d, 0x9e, 0x9f};
static const uint8_t xchachaData[304] =
    "The dhole (pronounced \"dole\") is also known as the Asiatic wild dog, red dog, and whistling dog. "
    "It is about the size of a German shepherd but looks more like a long-legged fox. This highly elusive "
    "and skilled jumper is classified with wolves, coyotes, jackals, and foxes in the taxonomic family Canidae.";
static const uint8_t xchachaNonce[24] =
    "@ABCDEFGHIJKLMNOPQRSTUVX";
static const uint8_t xchachaResult[304] = {
    0x45, 0x59, 0xab, 0xba, 0x4e, 0x48, 0xc1, 0x61, 0x02, 0xe8, 0xbb, 0x2c, 0x05, 0xe6, 0x94, 0x7f,
    0x50, 0xa7, 0x86, 0xde, 0x16, 0x2f, 0x9b, 0x0b, 0x7e, 0x59, 0x2a, 0x9b, 0x53, 0xd0, 0xd4, 0xe9,
    0x8d, 0x8d, 0x64, 0x10, 0xd5, 0x40, 0xa1, 0xa6, 0x37, 0x5b, 0x26, 0xd8, 0x0d, 0xac, 0xe4, 0xfa,
    0xb5, 0x23, 0x84, 0xc7, 0x31, 0xac, 0xbf, 0x16, 0xa5, 0x92, 0x3c, 0x0c, 0x48, 0xd3, 0x57, 0x5d,
    0x4d, 0x0d, 0x2c, 0x67, 0x3b, 0x66, 0x6f, 0xaa, 0x73, 0x10, 0x61, 0x27, 0x77, 0x01, 0x09, 0x3a,
    0x6b, 0xf7, 0xa1, 0x58, 0xa8, 0x86, 0x42, 0x92, 0xa4, 0x1c, 0x48, 0xe3, 0xa9, 0xb4, 0xc0, 0xda,
    0xec, 0xe0, 0xf8, 0xd9, 0x8d, 0x0d, 0x7e, 0x05, 0xb3, 0x7a, 0x30, 0x7b, 0xbb, 0x66, 0x33, 0x31,
    0x64, 0xec, 0x9e, 0x1b, 0x24, 0xea, 0x0d, 0x6c, 0x3f, 0xfd, 0xdc, 0xec, 0x4f, 0x68, 0xe7, 0x44,
    0x30, 0x56, 0x19, 0x3a, 0x03, 0xc8, 0x10, 0xe1, 0x13, 0x44, 0xca, 0x06, 0xd8, 0xed, 0x8a, 0x2b,
    0xfb, 0x1e, 0x8d, 0x48, 0xcf, 0xa6, 0xbc, 0x0e, 0xb4, 0xe2, 0x46, 0x4b, 0x74, 0x81, 0x42, 0x40,
    0x7c, 0x9f, 0x43, 0x1a, 0xee, 0x76, 0x99, 0x60, 0xe1, 0x5b, 0xa8, 0xb9, 0x68, 0x90, 0x46, 0x6e,
    0xf2, 0x45, 0x75, 0x99, 0x85, 0x23, 0x85, 0xc6, 0x61, 0xf7, 0x52, 0xce, 0x20, 0xf9, 0xda, 0x0c,
    0x09, 0xab, 0x6b, 0x19, 0xdf, 0x74, 0xe7, 0x6a, 0x95, 0x96, 0x74, 0x46, 0xf8, 0xd0, 0xfd, 0x41,
    0x5e, 0x7b, 0xee, 0x2a, 0x12, 0xa1, 0x14, 0xc2, 0x0e, 0xb5, 0x29, 0x2a, 0xe7, 0xa3, 0x49, 0xae,
    0x57, 0x78, 0x20, 0xd5, 0x52, 0x0a, 0x1f, 0x3f, 0xb6, 0x2a, 0x17, 0xce, 0x6a, 0x7e, 0x68, 0xfa,
    0x7c, 0x79, 0x11, 0x1d, 0x88, 0x60, 0x92, 0x0b, 0xc0, 0x48, 0xef, 0x43, 0xfe, 0x84, 0x48, 0x6c,
    0xcb, 0x87, 0xc2, 0x5f, 0x0a, 0xe0, 0x45, 0xf0, 0xcc, 0xe1, 0xe7, 0x98, 0x9a, 0x9a, 0xa2, 0x20,
    0xa2, 0x8b, 0xdd, 0x48, 0x27, 0xe7, 0x51, 0xa2, 0x4a, 0x6d, 0x5c, 0x62, 0xd7, 0x90, 0xa6, 0x63,
    0x93, 0xb9, 0x31, 0x11, 0xc1, 0xa5, 0x5d, 0xd7, 0x42, 0x1a, 0x10, 0x18, 0x49, 0x74, 0xc7, 0xc5};

// XChaCha tests
static int test_xchacha20()
{
    psa_cipher_operation_t op = PSA_CIPHER_OPERATION_INIT;
    psa_key_attributes_t key_attr = PSA_KEY_ATTRIBUTES_INIT;
    psa_key_id_t key_id = 0;
    uint8_t pt[304], ct[304];
    size_t ct_len, pt_len;
    int res = 0;

    psa_set_key_usage_flags(&key_attr, PSA_KEY_USAGE_ENCRYPT | PSA_KEY_USAGE_DECRYPT);
    psa_set_key_algorithm(&key_attr, PSA_ALG_STREAM_CIPHER);
    psa_set_key_type(&key_attr, PSA_KEY_TYPE_XCHACHA20);
    TEST_ASSERT(psa_import_key(&key_attr, xchachaKey, sizeof xchachaKey, &key_id) == PSA_SUCCESS);

    TEST_ASSERT(psa_cipher_encrypt_setup(&op, key_id, PSA_ALG_STREAM_CIPHER) == PSA_SUCCESS);
    TEST_ASSERT(psa_cipher_set_iv(&op, xchachaNonce, sizeof xchachaNonce) == PSA_SUCCESS);
    TEST_ASSERT(psa_cipher_update(&op, xchachaData, sizeof xchachaData, ct, sizeof ct, &ct_len) == PSA_SUCCESS);
    ASSERT_COMPARE(ct, ct_len, xchachaResult, sizeof xchachaResult);
    TEST_ASSERT(psa_cipher_finish(&op, ct, sizeof ct, &pt_len) == PSA_SUCCESS);
    TEST_ASSERT(pt_len == 0);

    TEST_ASSERT(psa_cipher_decrypt_setup(&op, key_id, PSA_ALG_STREAM_CIPHER) == PSA_SUCCESS);
    TEST_ASSERT(psa_cipher_set_iv(&op, xchachaNonce, sizeof xchachaNonce) == PSA_SUCCESS);
    TEST_ASSERT(psa_cipher_update(&op, ct, ct_len, pt, sizeof pt, &pt_len) == PSA_SUCCESS);
    ASSERT_COMPARE(pt, pt_len, xchachaData, sizeof xchachaData);
    TEST_ASSERT(psa_cipher_finish(&op, ct, sizeof ct, &pt_len) == PSA_SUCCESS);
    TEST_ASSERT(pt_len == 0);

    res = 1;
exit:
    TEST_ASSERT(psa_destroy_key(key_id) == PSA_SUCCESS);

    return res;
}

#ifdef PSA_WANT_ALG_XCHACHA20_POLY1305

// XChaCha20-Poly1305 test vectors from "draft-irtf-cfrg-xchacha-03"
static const uint8_t xchachaPolyNonce[24] =
    "@ABCDEFGHIJKLMNOPQRSTUVW";
static const uint8_t xchachaPolyData[114] =
    "Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.";
static const uint8_t xchachaPolyAD[12] = {
    0x50,0x51,0x52,0x53,0xc0,0xc1,0xc2,0xc3,0xc4,0xc5,0xc6,0xc7};
static const uint8_t xchachaPolyTag[16] = {
    0xc0,0x87,0x59,0x24,0xc1,0xc7,0x98,0x79,0x47,0xde,0xaf,0xd8,0x78,0x0a,0xcf,0x49};
static const uint8_t xchachaPolyResult[114] = {
    0xbd,0x6d,0x17,0x9d,0x3e,0x83,0xd4,0x3b,0x95,0x76,0x57,0x94,0x93,0xc0,0xe9,0x39,
    0x57,0x2a,0x17,0x00,0x25,0x2b,0xfa,0xcc,0xbe,0xd2,0x90,0x2c,0x21,0x39,0x6c,0xbb,
    0x73,0x1c,0x7f,0x1b,0x0b,0x4a,0xa6,0x44,0x0b,0xf3,0xa8,0x2f,0x4e,0xda,0x7e,0x39,
    0xae,0x64,0xc6,0x70,0x8c,0x54,0xc2,0x16,0xcb,0x96,0xb7,0x2e,0x12,0x13,0xb4,0x52,
    0x2f,0x8c,0x9b,0xa4,0x0d,0xb5,0xd9,0x45,0xb1,0x1b,0x69,0xb9,0x82,0xc1,0xbb,0x9e,
    0x3f,0x3f,0xac,0x2b,0xc3,0x69,0x48,0x8f,0x76,0xb2,0x38,0x35,0x65,0xd3,0xff,0xf9,
    0x21,0xf9,0x66,0x4c,0x97,0x63,0x7d,0xa9,0x76,0x88,0x12,0xf6,0x15,0xc6,0x8b,0x13,
    0xb5,0x2e};

static int test_xchacha20_poly1305()
{
    psa_aead_operation_t op = PSA_AEAD_OPERATION_INIT;
    psa_key_attributes_t key_attr = PSA_KEY_ATTRIBUTES_INIT;
    psa_key_id_t key_id = 0;
    uint8_t pt[114], ct[114], tag[16];
    size_t ct_len, pt_len, t_len;
    int res = 0;

    psa_set_key_usage_flags(&key_attr, PSA_KEY_USAGE_ENCRYPT | PSA_KEY_USAGE_DECRYPT);
    psa_set_key_algorithm(&key_attr, PSA_ALG_XCHACHA20_POLY1305);
    psa_set_key_type(&key_attr, PSA_KEY_TYPE_XCHACHA20);
    TEST_ASSERT(psa_import_key(&key_attr, xchachaKey, sizeof xchachaKey, &key_id) == PSA_SUCCESS);

    TEST_ASSERT(psa_aead_encrypt_setup(&op, key_id, PSA_ALG_XCHACHA20_POLY1305) == PSA_SUCCESS);
    TEST_ASSERT(psa_aead_set_nonce(&op, xchachaPolyNonce, sizeof xchachaPolyNonce) == PSA_SUCCESS);
    TEST_ASSERT(psa_aead_update_ad(&op, xchachaPolyAD, sizeof xchachaPolyAD) == PSA_SUCCESS);
    TEST_ASSERT(psa_aead_update(&op, xchachaPolyData, sizeof xchachaPolyData, ct, sizeof ct, &ct_len) == PSA_SUCCESS);
    ASSERT_COMPARE(ct, ct_len, xchachaPolyResult, sizeof xchachaPolyResult);
    TEST_ASSERT(psa_aead_finish(&op, ct, sizeof ct, &pt_len, tag, sizeof tag, &t_len) == PSA_SUCCESS);
    TEST_ASSERT(pt_len == 0);
    ASSERT_COMPARE(tag, t_len, xchachaPolyTag, sizeof xchachaPolyTag);

    TEST_ASSERT(psa_aead_decrypt_setup(&op, key_id, PSA_ALG_XCHACHA20_POLY1305) == PSA_SUCCESS);
    TEST_ASSERT(psa_aead_set_nonce(&op, xchachaPolyNonce, sizeof xchachaPolyNonce) == PSA_SUCCESS);
    TEST_ASSERT(psa_aead_update_ad(&op, xchachaPolyAD, sizeof xchachaPolyAD) == PSA_SUCCESS);
    TEST_ASSERT(psa_aead_update(&op, xchachaPolyResult, sizeof xchachaPolyResult, pt, sizeof pt, &pt_len) == PSA_SUCCESS);
    ASSERT_COMPARE(pt, pt_len, xchachaPolyData, sizeof xchachaPolyData);
    TEST_ASSERT(psa_aead_verify(&op, pt, sizeof pt, &pt_len, tag, t_len) == PSA_SUCCESS);
    TEST_ASSERT(pt_len == 0);

    res = 1;
exit:
    TEST_ASSERT(psa_destroy_key(key_id) == PSA_SUCCESS);

    return res;
}
#endif // PSA_WANT_ALG_XCHACHA20_POLY1305
#endif // PSA_WANT_KEY_TYPE_XCHACHA20

#ifdef PSA_WANT_ALG_SHAKE128
static const uint8_t shake128_in[] = "The quick brown fox jumps over the lazy dog";
static const uint8_t shake128_out[] = {
    0xf4, 0x20, 0x2e, 0x3c, 0x58, 0x52, 0xf9, 0x18, 0x2a, 0x04, 0x30, 0xfd, 0x81, 0x44, 0xf0, 0xa7,
    0x4b, 0x95, 0xe7, 0x41, 0x7e, 0xca, 0xe1, 0x7d, 0xb0, 0xf8, 0xcf, 0xee, 0xd0, 0xe3, 0xe6, 0x6e};
#endif // PSA_WANT_ALG_SHAKE128

#ifdef PSA_WANT_ALG_SHAKE256
static const uint8_t shake256_in[] = "The quick brown fox jumps over the lazy dog";
static const uint8_t shake256_out[] = {
    0x2f, 0x67, 0x13, 0x43, 0xd9, 0xb2, 0xe1, 0x60, 0x4d, 0xc9, 0xdc, 0xf0, 0x75, 0x3e, 0x5f, 0xe1,
    0x5c, 0x7c, 0x64, 0xa0, 0xd2, 0x83, 0xcb, 0xbf, 0x72, 0x2d, 0x41, 0x1a, 0x0e, 0x36, 0xf6, 0xca};
#endif // PSA_WANT_ALG_SHAKE256

#if defined(PSA_WANT_ALG_SHAKE128) || defined(PSA_WANT_ALG_SHAKE256)
static int test_shake(psa_algorithm_t alg, const uint8_t *in, size_t inlen, const uint8_t ref[32]) {
    psa_xof_operation_t op = PSA_XOF_OPERATION_INIT;
    uint8_t out[32];

    TEST_ASSERT(psa_xof_setup(&op, alg) == PSA_SUCCESS);
    TEST_ASSERT(psa_xof_update(&op, in, inlen) == PSA_SUCCESS);
    TEST_ASSERT(psa_xof_output(&op, out, 32) == PSA_SUCCESS);
    ASSERT_COMPARE(out, 32, ref, 32);
    TEST_ASSERT(psa_xof_abort(&op) == PSA_SUCCESS);

    // incremental input & output
    TEST_ASSERT(psa_xof_setup(&op, alg) == PSA_SUCCESS);
    TEST_ASSERT(psa_xof_update(&op, in, 7) == PSA_SUCCESS);
    TEST_ASSERT(psa_xof_update(&op, in + 7, inlen - 7) == PSA_SUCCESS);
    TEST_ASSERT(psa_xof_output(&op, out, 13) == PSA_SUCCESS);
    ASSERT_COMPARE(out, 13, ref, 13);
    TEST_ASSERT(psa_xof_output(&op, out, 19) == PSA_SUCCESS);
    ASSERT_COMPARE(out, 19, ref + 13, 19);
    TEST_ASSERT(psa_xof_abort(&op) == PSA_SUCCESS);

    // negative tests
    TEST_ASSERT(psa_xof_setup(&op, alg) == PSA_SUCCESS);
    TEST_ASSERT(psa_xof_setup(&op, alg) == PSA_ERROR_BAD_STATE);
    TEST_ASSERT(psa_xof_abort(&op) == PSA_SUCCESS);

    TEST_ASSERT(psa_xof_setup(&op, PSA_ALG_SHA_256) == PSA_ERROR_INVALID_ARGUMENT);
    TEST_ASSERT(psa_xof_abort(&op) == PSA_SUCCESS);

    TEST_ASSERT(psa_xof_setup(&op, 0x0D000000) == PSA_ERROR_NOT_SUPPORTED);
    TEST_ASSERT(psa_xof_abort(&op) == PSA_SUCCESS);

    TEST_ASSERT(psa_xof_update(&op, in, inlen) == PSA_ERROR_BAD_STATE);
    TEST_ASSERT(psa_xof_abort(&op) == PSA_SUCCESS);

    TEST_ASSERT(psa_xof_setup(&op, alg) == PSA_SUCCESS);
    TEST_ASSERT(psa_xof_update(&op, in, inlen) == PSA_SUCCESS);
    TEST_ASSERT(psa_xof_output(&op, out, 32) == PSA_SUCCESS);
    TEST_ASSERT(psa_xof_update(&op, in, inlen) == PSA_ERROR_BAD_STATE);
    TEST_ASSERT(psa_xof_abort(&op) == PSA_SUCCESS);

    TEST_ASSERT(psa_xof_output(&op, out, 32) == PSA_ERROR_BAD_STATE);
    TEST_ASSERT(psa_xof_abort(&op) == PSA_SUCCESS);

    return 1;
exit:
    return 0;
}
#endif // PSA_WANT_ALG_SHAKE128 || PSA_WANT_ALG_SHAKE256

#ifdef PSA_WANT_ALG_CBC_PKCS7
static int test_pkcs_padding()
{
    psa_cipher_operation_t op = PSA_CIPHER_OPERATION_INIT;
    psa_key_attributes_t key_attr = PSA_KEY_ATTRIBUTES_INIT;
    psa_key_id_t key = 0, key1 = 0;
    uint8_t pad, data[32], pdata[48], ct[64], pt[32];
    size_t plen, ctlen, ptlen, mlen, len;
    int res = 0;

    memset(data, 0xAA, sizeof data);
    psa_set_key_usage_flags(&key_attr, PSA_KEY_USAGE_ENCRYPT | PSA_KEY_USAGE_DECRYPT);
    psa_set_key_algorithm(&key_attr, PSA_ALG_CBC_PKCS7);
    psa_set_key_type(&key_attr, PSA_KEY_TYPE_AES);
    TEST_ASSERT(psa_import_key(&key_attr, data, 16, &key) == PSA_SUCCESS);
    psa_set_key_algorithm(&key_attr, PSA_ALG_CBC_NO_PADDING);
    TEST_ASSERT(psa_import_key(&key_attr, data, 16, &key1) == PSA_SUCCESS);

    for (len = 0; len <= 32; len++) {
        TEST_ASSERT(psa_cipher_encrypt(key, PSA_ALG_CBC_PKCS7, data, len, ct, 64, &ctlen) == PSA_SUCCESS);
        TEST_ASSERT(ctlen == ((len + 32) & ~15));

        // large output buffer
        memset(pt, 0, 32);
        TEST_ASSERT(psa_cipher_decrypt(key, PSA_ALG_CBC_PKCS7, ct, ctlen, pt, 32, &ptlen) == PSA_SUCCESS);
        ASSERT_COMPARE(pt, ptlen, data, len);
        memset(pt, 0, 32);
        TEST_ASSERT(psa_cipher_decrypt_setup(&op, key, PSA_ALG_CBC_PKCS7) == PSA_SUCCESS);
        TEST_ASSERT(psa_cipher_set_iv(&op, ct, 16) == PSA_SUCCESS);
        TEST_ASSERT(psa_cipher_update(&op, ct + 16, ctlen - 16, pt, 32, &mlen) == PSA_SUCCESS);
        TEST_ASSERT(psa_cipher_finish(&op, pt + mlen, 32 - mlen, &ptlen) == PSA_SUCCESS);
        ptlen += mlen;
        ASSERT_COMPARE(pt, ptlen, data, len);

        // minimal output buffer
        memset(pt, 0, 32);
        TEST_ASSERT(psa_cipher_decrypt(key, PSA_ALG_CBC_PKCS7, ct, ctlen, pt, len, &ptlen) == PSA_SUCCESS);
        ASSERT_COMPARE(pt, ptlen, data, len);
        memset(pt, 0, 32);
        TEST_ASSERT(psa_cipher_decrypt_setup(&op, key, PSA_ALG_CBC_PKCS7) == PSA_SUCCESS);
        TEST_ASSERT(psa_cipher_set_iv(&op, ct, 16) == PSA_SUCCESS);
        TEST_ASSERT(psa_cipher_update(&op, ct + 16, ctlen - 16, pt, len, &mlen) == PSA_SUCCESS);
        TEST_ASSERT(psa_cipher_finish(&op, pt + mlen, len - mlen, &ptlen) == PSA_SUCCESS);
        ptlen += mlen;
        ASSERT_COMPARE(pt, ptlen, data, len);

        if (len > 0) {
            // output buffer too small
            TEST_ASSERT(psa_cipher_decrypt(key, PSA_ALG_CBC_PKCS7, ct, ctlen, pt, len - 1, &ptlen) == PSA_ERROR_BUFFER_TOO_SMALL);
            if ((len & 15) != 0) {
                TEST_ASSERT(psa_cipher_decrypt_setup(&op, key, PSA_ALG_CBC_PKCS7) == PSA_SUCCESS);
                TEST_ASSERT(psa_cipher_set_iv(&op, ct, 16) == PSA_SUCCESS);
                TEST_ASSERT(psa_cipher_update(&op, ct + 16, ctlen - 16, pt, len - 1, &mlen) == PSA_SUCCESS);
                TEST_ASSERT(psa_cipher_finish(&op, pt + mlen, len - mlen - 1, &ptlen) == PSA_ERROR_BUFFER_TOO_SMALL);
                TEST_ASSERT(psa_cipher_abort(&op) == PSA_SUCCESS);
            }
        }

        // synthesize wrong padding using CBC_NO_PADDING
        plen = (len + 16) & ~15;
        pad = (uint8_t)(plen - len);
        if (len == 32) pad = 17; // wrong pad
        if (len == 31) pad = 0; // wrong pad
        memcpy(pdata, data, len);
        memset(pdata + len, pad, plen - len);
        if (len < 31) pdata[plen - 1] = pad + 1; // too large or inconsistent
        TEST_ASSERT(psa_cipher_encrypt(key1, PSA_ALG_CBC_NO_PADDING, pdata, plen, ct, 64, &ctlen) == PSA_SUCCESS);
        TEST_ASSERT(ctlen == plen + 16);

        TEST_ASSERT(psa_cipher_decrypt(key, PSA_ALG_CBC_PKCS7, ct, ctlen, pt, len, &ptlen) == PSA_ERROR_INVALID_PADDING);
        TEST_ASSERT(psa_cipher_decrypt_setup(&op, key, PSA_ALG_CBC_PKCS7) == PSA_SUCCESS);
        TEST_ASSERT(psa_cipher_set_iv(&op, ct, 16) == PSA_SUCCESS);
        TEST_ASSERT(psa_cipher_update(&op, ct + 16, ctlen - 16, pt, len, &mlen) == PSA_SUCCESS);
        TEST_ASSERT(psa_cipher_finish(&op, pt + mlen, len - mlen, &ptlen) == PSA_ERROR_INVALID_PADDING);
        TEST_ASSERT(psa_cipher_abort(&op) == PSA_SUCCESS);
    }

    res = 1;
exit:
    TEST_ASSERT(psa_destroy_key(key) == PSA_SUCCESS);
    TEST_ASSERT(psa_destroy_key(key1) == PSA_SUCCESS);
    return res;
}
#endif // PSA_WANT_ALG_CBC_PKCS7


#ifdef PSA_WANT_ALG_ASCON_HASH256
static const uint8_t ascon_hash_in1[] = {
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16};
static const uint8_t ascon_hash_res1[] = {
    0xB4, 0xF8, 0x8D, 0x12, 0x1E, 0xDD, 0xF6, 0xD1, 0xFE, 0xA9, 0xAE, 0xF1, 0x5F, 0x68, 0xA0, 0xF3,
    0xA1, 0x6D, 0x3D, 0x2C, 0xDD, 0x98, 0x17, 0x22, 0x58, 0x09, 0xC2, 0x04, 0x52, 0xB0, 0x4C, 0x61};
static const uint8_t ascon_hash_in2[] = {
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E};
static const uint8_t ascon_hash_res2[] = {
    0x64, 0x21, 0x33, 0x0D, 0xF9, 0x9C, 0x05, 0xEB, 0x71, 0x54, 0x15, 0xEE, 0x17, 0xB4, 0x55, 0xF2,
    0x67, 0x4F, 0x86, 0x2A, 0xE3, 0xCC, 0x5B, 0xAD, 0xFF, 0xE4, 0x3A, 0x4A, 0x3E, 0xD2, 0x73, 0xE1};

static int test_ascon_hash()
{
    psa_hash_operation_t op = PSA_HASH_OPERATION_INIT;
    uint8_t h[32];
    size_t length;
    int res = 0;

    TEST_ASSERT(psa_hash_compute(PSA_ALG_ASCON_HASH256, ascon_hash_in1, sizeof ascon_hash_in1, h, sizeof h, &length) == PSA_SUCCESS);
    ASSERT_COMPARE(h, length, ascon_hash_res1, sizeof ascon_hash_res1);

    TEST_ASSERT(psa_hash_setup(&op, PSA_ALG_ASCON_HASH256) == PSA_SUCCESS);
    TEST_ASSERT(psa_hash_update(&op, ascon_hash_in1, sizeof ascon_hash_in1) == PSA_SUCCESS);
    TEST_ASSERT(psa_hash_finish(&op, h, sizeof h, &length) == PSA_SUCCESS);
    ASSERT_COMPARE(h, length, ascon_hash_res1, sizeof ascon_hash_res1);

    TEST_ASSERT(psa_hash_compute(PSA_ALG_ASCON_HASH256, ascon_hash_in2, sizeof ascon_hash_in2, h, sizeof h, &length) == PSA_SUCCESS);
    ASSERT_COMPARE(h, length, ascon_hash_res2, sizeof ascon_hash_res2);

    TEST_ASSERT(psa_hash_setup(&op, PSA_ALG_ASCON_HASH256) == PSA_SUCCESS);
    TEST_ASSERT(psa_hash_update(&op, ascon_hash_in2, 7) == PSA_SUCCESS);
    TEST_ASSERT(psa_hash_update(&op, ascon_hash_in2 + 7, sizeof ascon_hash_in2 - 7) == PSA_SUCCESS);
    TEST_ASSERT(psa_hash_finish(&op, h, sizeof h, &length) == PSA_SUCCESS);
    ASSERT_COMPARE(h, length, ascon_hash_res2, sizeof ascon_hash_res2);

    res = 1;
exit:
    return res;
}
#endif // PSA_WANT_ALG_ASCON_HASH256

#ifdef PSA_WANT_ALG_ASCON_XOF128
static const uint8_t ascon_xof_in1[] = {
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16};
static const uint8_t ascon_xof_res1[] = {
    0x5A, 0xE2, 0x1E, 0x68, 0xEF, 0x4F, 0xDC, 0x6F, 0xEF, 0xBF, 0x60, 0x4B, 0x0B, 0xD8, 0x67, 0x24,
    0x06, 0xF6, 0xF2, 0x3F, 0x0B, 0xDF, 0x2F, 0x28, 0xE5, 0x46, 0x0B, 0x08, 0x1D, 0x90, 0x68, 0xB8};
static const uint8_t ascon_xof_in2[] = {
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E};
static const uint8_t ascon_xof_res2[] = {
    0x75, 0x17, 0xD9, 0xB0, 0x38, 0x3D, 0xC7, 0x74, 0x2E, 0x9E, 0x13, 0x35, 0xD9, 0x7D, 0x3F, 0x1C,
    0x5A, 0x97, 0x14, 0x16, 0xCA, 0x4E, 0x72, 0xBF, 0x50, 0x4E, 0x96, 0x2F, 0x80, 0x28, 0x68, 0x62};

static int test_ascon_xof()
{
    psa_xof_operation_t op = PSA_XOF_OPERATION_INIT;
    uint8_t h[32];
    int res = 0;

    TEST_ASSERT(psa_xof_setup(&op, PSA_ALG_ASCON_XOF128) == PSA_SUCCESS);
    TEST_ASSERT(psa_xof_update(&op, ascon_xof_in1, sizeof ascon_xof_in1) == PSA_SUCCESS);
    TEST_ASSERT(psa_xof_output(&op, h, sizeof h) == PSA_SUCCESS);
    ASSERT_COMPARE(h, sizeof h, ascon_xof_res1, sizeof ascon_xof_res1);
    TEST_ASSERT(psa_xof_abort(&op) == PSA_SUCCESS);

    TEST_ASSERT(psa_xof_setup(&op, PSA_ALG_ASCON_XOF128) == PSA_SUCCESS);
    TEST_ASSERT(psa_xof_update(&op, ascon_xof_in2, 11) == PSA_SUCCESS);
    TEST_ASSERT(psa_xof_update(&op, ascon_xof_in2 + 11, sizeof ascon_xof_in2 - 11) == PSA_SUCCESS);
    TEST_ASSERT(psa_xof_output(&op, h, 7) == PSA_SUCCESS);
    ASSERT_COMPARE(h, 7, ascon_xof_res2, 7);
    TEST_ASSERT(psa_xof_output(&op, h, 12) == PSA_SUCCESS);
    ASSERT_COMPARE(h, 12, ascon_xof_res2 + 7, 12);
    TEST_ASSERT(psa_xof_output(&op, h, 13) == PSA_SUCCESS);
    ASSERT_COMPARE(h, 13, ascon_xof_res2 + 19, 13);
    TEST_ASSERT(psa_xof_abort(&op) == PSA_SUCCESS);

    TEST_ASSERT(psa_xof_setup(&op, PSA_ALG_ASCON_XOF128) == PSA_SUCCESS);
    TEST_ASSERT(psa_xof_output(&op, h, 7) == PSA_SUCCESS);
    TEST_ASSERT(psa_xof_update(&op, ascon_xof_in2, 11) == PSA_ERROR_BAD_STATE);
    TEST_ASSERT(psa_xof_abort(&op) == PSA_SUCCESS);

    TEST_ASSERT(psa_xof_setup(&op, PSA_ALG_ASCON_XOF128) == PSA_SUCCESS);
    TEST_ASSERT(psa_xof_set_context(&op, ascon_xof_in1, 7) == PSA_ERROR_INVALID_ARGUMENT);
    TEST_ASSERT(psa_xof_abort(&op) == PSA_SUCCESS);

    res = 1;
exit:
    return res;
}
#endif // PSA_WANT_ALG_ASCON_XOF128

#ifdef PSA_WANT_ALG_ASCON_CXOF128
static const uint8_t ascon_cxof_in[] = {
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E};
static const uint8_t ascon_cxof_ctx[] = {
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A};
static const uint8_t ascon_cxof_res[] = {
    0x30, 0xFE, 0x87, 0xD4, 0x5C, 0x34, 0xF1, 0x6A, 0x5A, 0x5E, 0xF7, 0x22, 0x6E, 0x77, 0xA3, 0x34,
    0xE3, 0x70, 0xCE, 0xDC, 0x2E, 0xD2, 0x80, 0xE9, 0x76, 0x20, 0x04, 0xB7, 0x22, 0x97, 0x9B, 0x93};
static const uint8_t ascon_cxof_resE[] = {
    0xD7, 0x75, 0x26, 0x0D, 0x6E, 0x96, 0x3C, 0xCA, 0xD7, 0x89, 0x8A, 0x45, 0xE9, 0x45, 0x7C, 0xD0};
static const uint8_t ascon_cxof_resEE[] = {
    0x4F, 0x50, 0x15, 0x9E, 0xF7, 0x0B, 0xB3, 0xDA, 0xD8, 0x80, 0x7E, 0x03, 0x4E, 0xAE, 0xBD, 0x44};

static int test_ascon_cxof()
{
    psa_xof_operation_t op = PSA_XOF_OPERATION_INIT;
    uint8_t h[32];
    int res = 0;

    TEST_ASSERT(psa_xof_setup(&op, PSA_ALG_ASCON_CXOF128) == PSA_SUCCESS);
    TEST_ASSERT(psa_xof_set_context(&op, ascon_cxof_ctx, sizeof ascon_cxof_ctx) == PSA_SUCCESS);
    TEST_ASSERT(psa_xof_update(&op, ascon_cxof_in, sizeof ascon_cxof_in) == PSA_SUCCESS);
    TEST_ASSERT(psa_xof_output(&op, h, 13) == PSA_SUCCESS);
    ASSERT_COMPARE(h, 13, ascon_cxof_res, 13);
    TEST_ASSERT(psa_xof_output(&op, h, 17) == PSA_SUCCESS);
    ASSERT_COMPARE(h, 17, ascon_cxof_res + 13, 17);
    TEST_ASSERT(psa_xof_abort(&op) == PSA_SUCCESS);

    TEST_ASSERT(psa_xof_setup(&op, PSA_ALG_ASCON_CXOF128) == PSA_SUCCESS);
    TEST_ASSERT(psa_xof_update(&op, ascon_cxof_in, sizeof ascon_cxof_in) == PSA_SUCCESS);
    TEST_ASSERT(psa_xof_output(&op, h, 15) == PSA_SUCCESS);
    ASSERT_COMPARE(h, 15, ascon_cxof_resE, 15);
    TEST_ASSERT(psa_xof_abort(&op) == PSA_SUCCESS);

    TEST_ASSERT(psa_xof_setup(&op, PSA_ALG_ASCON_CXOF128) == PSA_SUCCESS);
    TEST_ASSERT(psa_xof_output(&op, h, 11) == PSA_SUCCESS);
    ASSERT_COMPARE(h, 11, ascon_cxof_resEE, 11);
    TEST_ASSERT(psa_xof_abort(&op) == PSA_SUCCESS);

    TEST_ASSERT(psa_xof_setup(&op, PSA_ALG_ASCON_CXOF128) == PSA_SUCCESS);
    TEST_ASSERT(psa_xof_update(&op, ascon_cxof_in, sizeof ascon_cxof_in) == PSA_SUCCESS);
    TEST_ASSERT(psa_xof_set_context(&op, ascon_cxof_ctx, sizeof ascon_cxof_ctx) == PSA_ERROR_BAD_STATE);
    TEST_ASSERT(psa_xof_abort(&op) == PSA_SUCCESS);

    TEST_ASSERT(psa_xof_setup(&op, PSA_ALG_ASCON_CXOF128) == PSA_SUCCESS);
    TEST_ASSERT(psa_xof_update(&op, ascon_cxof_in, sizeof ascon_cxof_in) == PSA_SUCCESS);
    TEST_ASSERT(psa_xof_output(&op, h, 13) == PSA_SUCCESS);
    TEST_ASSERT(psa_xof_set_context(&op, ascon_cxof_ctx, sizeof ascon_cxof_ctx) == PSA_ERROR_BAD_STATE);
    TEST_ASSERT(psa_xof_abort(&op) == PSA_SUCCESS);

    TEST_ASSERT(psa_xof_setup(&op, PSA_ALG_ASCON_CXOF128) == PSA_SUCCESS);
    TEST_ASSERT(psa_xof_output(&op, h, 13) == PSA_SUCCESS);
    TEST_ASSERT(psa_xof_set_context(&op, ascon_cxof_ctx, sizeof ascon_cxof_ctx) == PSA_ERROR_BAD_STATE);
    TEST_ASSERT(psa_xof_abort(&op) == PSA_SUCCESS);

    TEST_ASSERT(psa_xof_setup(&op, PSA_ALG_ASCON_CXOF128) == PSA_SUCCESS);
    TEST_ASSERT(psa_xof_set_context(&op, ascon_cxof_ctx, sizeof ascon_cxof_ctx) == PSA_SUCCESS);
    TEST_ASSERT(psa_xof_set_context(&op, ascon_cxof_ctx, sizeof ascon_cxof_ctx) == PSA_ERROR_BAD_STATE);
    TEST_ASSERT(psa_xof_abort(&op) == PSA_SUCCESS);

    res = 1;
exit:
    return res;
}
#endif // PSA_WANT_ALG_ASCON_CXOF128

#ifdef PSA_WANT_ALG_ASCON_AEAD128
static const uint8_t ascon_aead_key[] = {
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F};
static const uint8_t ascon_aead_nonce[] = {
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F};
static const uint8_t ascon_aead_pt1[] = {
    0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2A, 0x2B, 0x2C, 0x2D, 0x2E, 0x2F,
    0x30, 0x31, 0x32};
static const uint8_t ascon_aead_ct1[] = {
    0xE8, 0xC3, 0xDE, 0xEE, 0x24, 0x6C, 0xC5, 0xEA, 0xE3, 0xE8, 0x72, 0x31, 0x38, 0x97, 0xA2, 0xBB,
    0x60, 0x89, 0xAA};
static const uint8_t ascon_aead_tag1[] = {
    0x26, 0xE4, 0x09, 0x9A, 0x8F, 0x7C, 0x06, 0xAA, 0x8C, 0xBF, 0x6A, 0x20, 0xA0, 0x31, 0x6D, 0x61};
static const uint8_t ascon_aead_pt2[] = {
    0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2A, 0x2B, 0x2C, 0x2D, 0x2E, 0x2F,
    0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3A};
static const uint8_t ascon_aead_aad2[] = {
    0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3A, 0x3B, 0x3C, 0x3D, 0x3E, 0x3F,
    0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4A};
static const uint8_t ascon_aead_ct2[] = {
    0xE4, 0xC1, 0xBB, 0x6B, 0x1B, 0x26, 0x4F, 0x12, 0xEE, 0xC2, 0xAB, 0xB5, 0x42, 0x76, 0x1A, 0xBB,
    0xC0, 0xD8, 0x28, 0x6F, 0xB9, 0x90, 0xCB, 0x04, 0x0D, 0xC1, 0x07};
static const uint8_t ascon_aead_tag2[] = {
    0xAD, 0xD3, 0x4C, 0xB2, 0xB4, 0xCE, 0xFB, 0x49, 0xB2, 0xEA, 0xAE, 0x62, 0x57, 0x01, 0xA6, 0xDF};

static int test_ascon_aead()
{
    psa_aead_operation_t op = PSA_AEAD_OPERATION_INIT;
    psa_key_attributes_t attr = PSA_KEY_ATTRIBUTES_INIT;
    uint8_t ct[32], tag[16];
    size_t l, length;
    psa_key_id_t key = 0;
    int res = 0;

    psa_set_key_usage_flags(&attr, PSA_KEY_USAGE_ENCRYPT | PSA_KEY_USAGE_DECRYPT);
    psa_set_key_algorithm(&attr, PSA_ALG_ASCON_AEAD128);
    psa_set_key_type(&attr, PSA_KEY_TYPE_ASCON);
    TEST_ASSERT(psa_import_key(&attr, ascon_aead_key, sizeof ascon_aead_key, &key) == PSA_SUCCESS);

    TEST_ASSERT(psa_aead_encrypt_setup(&op, key, PSA_ALG_ASCON_AEAD128) == PSA_SUCCESS);
    TEST_ASSERT(psa_aead_set_nonce(&op, ascon_aead_nonce, sizeof ascon_aead_nonce) == PSA_SUCCESS);
    TEST_ASSERT(psa_aead_update(&op, ascon_aead_pt1, sizeof ascon_aead_pt1, ct, sizeof ct, &length) == PSA_SUCCESS);
    ASSERT_COMPARE(ct, length, ascon_aead_ct1, sizeof ascon_aead_ct1);
    TEST_ASSERT(psa_aead_finish(&op, NULL, 0, &l, tag, sizeof tag, &length) == PSA_SUCCESS);
    ASSERT_COMPARE(tag, length, ascon_aead_tag1, sizeof ascon_aead_tag1);

    TEST_ASSERT(psa_aead_encrypt_setup(&op, key, PSA_ALG_ASCON_AEAD128) == PSA_SUCCESS);
    TEST_ASSERT(psa_aead_set_nonce(&op, ascon_aead_nonce, sizeof ascon_aead_nonce) == PSA_SUCCESS);
    TEST_ASSERT(psa_aead_update_ad(&op, ascon_aead_aad2, sizeof ascon_aead_aad2) == PSA_SUCCESS);
    TEST_ASSERT(psa_aead_update(&op, ascon_aead_pt2, sizeof ascon_aead_pt2, ct, sizeof ct, &length) == PSA_SUCCESS);
    ASSERT_COMPARE(ct, length, ascon_aead_ct2, sizeof ascon_aead_ct2);
    TEST_ASSERT(psa_aead_finish(&op, NULL, 0, &l, tag, sizeof tag, &length) == PSA_SUCCESS);
    ASSERT_COMPARE(tag, length, ascon_aead_tag2, sizeof ascon_aead_tag2);

    TEST_ASSERT(psa_aead_abort(&op) == PSA_SUCCESS);

    res = 1;
exit:
    TEST_ASSERT(psa_destroy_key(key) == PSA_SUCCESS);
    return res;
}
#endif // PSA_WANT_ALG_ASCON_AEAD128


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

#ifdef PSA_WANT_ALG_SRP_PASSWORD_HASH
    TEST_ASSERT(test_srp_password_hash_kdf(PSA_ALG_SHA_256, "password", "user"));
    TEST_ASSERT(test_srp_password_hash_kdf(PSA_ALG_SHA_256, "abcd", "client"));
    TEST_ASSERT(test_srp_password_hash_kdf(PSA_ALG_SHA_512, "password", "user"));
#endif

#ifdef PSA_WANT_ALG_HKDF
    // output_bytes
    TEST_ASSERT(test_key_derivation_verify(PSA_KEY_USAGE_DERIVE,            PSA_KEY_USAGE_DERIVE,            0,                               0, PSA_SUCCESS));
    TEST_ASSERT(test_key_derivation_verify(PSA_KEY_USAGE_DERIVE,            0,                               0,                               0, PSA_SUCCESS));
    TEST_ASSERT(test_key_derivation_verify(0,                               PSA_KEY_USAGE_DERIVE,            0,                               0, PSA_SUCCESS));
    TEST_ASSERT(test_key_derivation_verify(0,                               0,                               0,                               0, PSA_SUCCESS));
    TEST_ASSERT(test_key_derivation_verify(0,                               PSA_KEY_USAGE_VERIFY_DERIVATION, 0,                               0, PSA_ERROR_NOT_PERMITTED));
    TEST_ASSERT(test_key_derivation_verify(PSA_KEY_USAGE_VERIFY_DERIVATION, 0,                               0,                               0, PSA_ERROR_NOT_PERMITTED));
    TEST_ASSERT(test_key_derivation_verify(0,                               PSA_KEY_USAGE_EXPORT,            0,                               0, PSA_ERROR_NOT_PERMITTED));
    TEST_ASSERT(test_key_derivation_verify(PSA_KEY_USAGE_EXPORT,            0,                               0,                               0, PSA_ERROR_NOT_PERMITTED));
    // output_key
    TEST_ASSERT(test_key_derivation_verify(PSA_KEY_USAGE_DERIVE,            PSA_KEY_USAGE_DERIVE,            PSA_KEY_USAGE_DERIVE,            0, PSA_SUCCESS));
    TEST_ASSERT(test_key_derivation_verify(PSA_KEY_USAGE_DERIVE,            0,                               PSA_KEY_USAGE_DERIVE,            0, PSA_SUCCESS));
    TEST_ASSERT(test_key_derivation_verify(0,                               PSA_KEY_USAGE_DERIVE,            PSA_KEY_USAGE_DERIVE,            0, PSA_ERROR_NOT_PERMITTED));
    TEST_ASSERT(test_key_derivation_verify(0,                               0,                               PSA_KEY_USAGE_DERIVE,            0, PSA_ERROR_NOT_PERMITTED));
    TEST_ASSERT(test_key_derivation_verify(0,                               PSA_KEY_USAGE_VERIFY_DERIVATION, PSA_KEY_USAGE_DERIVE,            0, PSA_ERROR_NOT_PERMITTED));
    TEST_ASSERT(test_key_derivation_verify(PSA_KEY_USAGE_VERIFY_DERIVATION, 0,                               PSA_KEY_USAGE_DERIVE,            0, PSA_ERROR_NOT_PERMITTED));
    TEST_ASSERT(test_key_derivation_verify(PSA_KEY_USAGE_DERIVE,            PSA_KEY_USAGE_DERIVE,            PSA_KEY_USAGE_VERIFY_DERIVATION, 0, PSA_SUCCESS));
    TEST_ASSERT(test_key_derivation_verify(0,                               PSA_KEY_USAGE_EXPORT,            PSA_KEY_USAGE_DERIVE,            0, PSA_ERROR_NOT_PERMITTED));
    TEST_ASSERT(test_key_derivation_verify(PSA_KEY_USAGE_EXPORT,            0,                               PSA_KEY_USAGE_DERIVE,            0, PSA_ERROR_NOT_PERMITTED));
    // verify_bytes
    TEST_ASSERT(test_key_derivation_verify(PSA_KEY_USAGE_VERIFY_DERIVATION, PSA_KEY_USAGE_VERIFY_DERIVATION, 0,                               1, PSA_SUCCESS));
    TEST_ASSERT(test_key_derivation_verify(PSA_KEY_USAGE_VERIFY_DERIVATION, 0,                               0,                               1, PSA_SUCCESS));
    TEST_ASSERT(test_key_derivation_verify(0,                               PSA_KEY_USAGE_VERIFY_DERIVATION, 0,                               1, PSA_SUCCESS));
    TEST_ASSERT(test_key_derivation_verify(0,                               0,                               0,                               1, PSA_SUCCESS));
    TEST_ASSERT(test_key_derivation_verify(PSA_KEY_USAGE_DERIVE,            PSA_KEY_USAGE_DERIVE,            0,                               1, PSA_SUCCESS));
    TEST_ASSERT(test_key_derivation_verify(0,                               PSA_KEY_USAGE_DERIVE,            0,                               1, PSA_SUCCESS));
    TEST_ASSERT(test_key_derivation_verify(PSA_KEY_USAGE_DERIVE,            0,                               0,                               1, PSA_SUCCESS));
    TEST_ASSERT(test_key_derivation_verify(0,                               PSA_KEY_USAGE_EXPORT,            0,                               1, PSA_ERROR_NOT_PERMITTED));
    TEST_ASSERT(test_key_derivation_verify(PSA_KEY_USAGE_EXPORT,            0,                               0,                               1, PSA_ERROR_NOT_PERMITTED));
    // verify_key
    TEST_ASSERT(test_key_derivation_verify(PSA_KEY_USAGE_VERIFY_DERIVATION, PSA_KEY_USAGE_VERIFY_DERIVATION, PSA_KEY_USAGE_VERIFY_DERIVATION, 1, PSA_SUCCESS));
    TEST_ASSERT(test_key_derivation_verify(PSA_KEY_USAGE_VERIFY_DERIVATION, 0,                               PSA_KEY_USAGE_VERIFY_DERIVATION, 1, PSA_SUCCESS));
    TEST_ASSERT(test_key_derivation_verify(0,                               PSA_KEY_USAGE_VERIFY_DERIVATION, PSA_KEY_USAGE_VERIFY_DERIVATION, 1, PSA_SUCCESS));
    TEST_ASSERT(test_key_derivation_verify(0,                               0,                               PSA_KEY_USAGE_VERIFY_DERIVATION, 1, PSA_SUCCESS));
    TEST_ASSERT(test_key_derivation_verify(PSA_KEY_USAGE_VERIFY_DERIVATION, PSA_KEY_USAGE_VERIFY_DERIVATION, PSA_KEY_USAGE_DERIVE,            1, PSA_ERROR_NOT_PERMITTED));
    TEST_ASSERT(test_key_derivation_verify(PSA_KEY_USAGE_DERIVE,            PSA_KEY_USAGE_DERIVE,            PSA_KEY_USAGE_VERIFY_DERIVATION, 1, PSA_SUCCESS));
    TEST_ASSERT(test_key_derivation_verify(PSA_KEY_USAGE_DERIVE,            0,                               PSA_KEY_USAGE_VERIFY_DERIVATION, 1, PSA_SUCCESS));
    TEST_ASSERT(test_key_derivation_verify(0,                               PSA_KEY_USAGE_DERIVE,            PSA_KEY_USAGE_VERIFY_DERIVATION, 1, PSA_SUCCESS));
    TEST_ASSERT(test_key_derivation_verify(0,                               PSA_KEY_USAGE_EXPORT,            PSA_KEY_USAGE_VERIFY_DERIVATION, 1, PSA_ERROR_NOT_PERMITTED));
    TEST_ASSERT(test_key_derivation_verify(PSA_KEY_USAGE_EXPORT,            0,                               PSA_KEY_USAGE_VERIFY_DERIVATION, 1, PSA_ERROR_NOT_PERMITTED));
    TEST_ASSERT(test_key_derivation_verify(PSA_KEY_USAGE_VERIFY_DERIVATION, 0,                               PSA_KEY_USAGE_EXPORT,            1, PSA_ERROR_NOT_PERMITTED));
#endif // PSA_WANT_ALG_HKDF

#ifdef PSA_WANT_KEY_TYPE_XCHACHA20
    TEST_ASSERT(test_xchacha20());
#ifdef PSA_WANT_ALG_XCHACHA20_POLY1305
    TEST_ASSERT(test_xchacha20_poly1305());
#endif // PSA_WANT_ALG_XCHACHA20_POLY1305
#endif // PSA_WANT_KEY_TYPE_XCHACHA20

#ifdef PSA_WANT_ALG_SHAKE128
    TEST_ASSERT(test_shake(PSA_ALG_SHAKE128, shake128_in, sizeof shake128_in - 1, shake128_out));
#endif // PSA_WANT_ALG_SHAKE128
#ifdef PSA_WANT_ALG_SHAKE256
    TEST_ASSERT(test_shake(PSA_ALG_SHAKE256, shake256_in, sizeof shake256_in - 1, shake256_out));
#endif // PSA_WANT_ALG_SHAKE256

#ifdef PSA_WANT_ALG_CBC_PKCS7
    TEST_ASSERT(test_pkcs_padding());
#endif // PSA_WANT_ALG_CBC_PKCS7

#ifdef PSA_WANT_ALG_ASCON_HASH256
    TEST_ASSERT(test_ascon_hash());
#endif // PSA_WANT_ALG_ASCON_HASH256
#ifdef PSA_WANT_ALG_ASCON_XOF128
    TEST_ASSERT(test_ascon_xof());
#endif // PSA_WANT_ALG_ASCON_XOF128
#ifdef PSA_WANT_ALG_ASCON_CXOF128
    TEST_ASSERT(test_ascon_cxof());
#endif // PSA_WANT_ALG_ASCON_CXOF128
#ifdef PSA_WANT_ALG_ASCON_AEAD128
    TEST_ASSERT(test_ascon_aead());
#endif // PSA_WANT_ALG_ASCON_AEAD128

    return 0;
exit:
    return 1;
}
