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
#include "oberon_test_drbg.h"


int send_message(psa_pake_operation_t *from, psa_pake_operation_t *to, psa_pake_step_t step, const uint8_t *cmp, size_t size)
{
    uint8_t data[1024];
    size_t length;

    TEST_ASSERT(psa_pake_output(from, step, data, sizeof data, &length) == PSA_SUCCESS);
    TEST_ASSERT(length == size);
    if (cmp != NULL) {
        ASSERT_COMPARE(data, length, cmp, size);
    }
    TEST_ASSERT(psa_pake_input(to, step, data, length) == PSA_SUCCESS);

    return 1;
exit:
    return 0;
}

int send_message_err(psa_pake_operation_t *from, psa_pake_operation_t *to, psa_pake_step_t step, int n)
{
    uint8_t data[1024];
    size_t length;

    if (n == 1) { // wrong step
        TEST_ASSERT(psa_pake_output(from, step, data, sizeof data, &length) == PSA_ERROR_BAD_STATE);
        TEST_ASSERT(psa_pake_input(to, step, data, 32) == PSA_ERROR_BAD_STATE);
    } else {
        TEST_ASSERT(psa_pake_output(from, step, data, sizeof data, &length) == PSA_SUCCESS);
        if (n == 2) { // wrong input size
            TEST_ASSERT(psa_pake_input(to, step, data, length + 8) == PSA_ERROR_INVALID_ARGUMENT);
        } else if (n == 3) { // wrong proof size
            TEST_ASSERT(psa_pake_input(to, step, data, length + 8) == PSA_ERROR_INVALID_ARGUMENT);
        } else if (n == 4) { // wrong proof data
            data[0]++;
            TEST_ASSERT(psa_pake_input(to, step, data, length) == PSA_ERROR_INVALID_SIGNATURE);
        } else if (n == 5) { // wrong data
            data[34]++;
            TEST_ASSERT(psa_pake_input(to, step, data, length) == PSA_ERROR_INVALID_ARGUMENT);
        } else {
            TEST_ASSERT(psa_pake_input(to, step, data, length) == PSA_SUCCESS);
        }
    }

    return 1;
exit:
    return 0;
}

/*
 * JPAKE Tests
 */
#ifdef PSA_WANT_ALG_JPAKE

static const uint8_t jpake_psk[] = {
    0x00, 0x74, 0x68, 0x72, 0x65, 0x61, 0x64, 0x6a, 0x70, 0x61, 0x6b, 0x65, 0x74, 0x65, 0x73, 0x74};

static const uint8_t jpake_pms1[] = {
    0xf3, 0xd4, 0x7f, 0x59, 0x98, 0x44, 0xdb, 0x92, 0xa5, 0x69, 0xbb, 0xe7, 0x98, 0x1e, 0x39, 0xd9,
    0x31, 0xfd, 0x74, 0x3b, 0xf2, 0x2e, 0x98, 0xf9, 0xb4, 0x38, 0xf7, 0x19, 0xd3, 0xc4, 0xf3, 0x51};
static const uint8_t jpake_pms2[] = {
    0x9a, 0xb4, 0xcf, 0xc7, 0x4c, 0xc1, 0xb3, 0x12, 0xdf, 0x87, 0xa8, 0x62, 0x53, 0xae, 0xbe, 0xd8,
    0x57, 0x8a, 0x02, 0x8b, 0x37, 0x73, 0x15, 0x32, 0x05, 0x8a, 0x44, 0xd5, 0x41, 0x90, 0xf4, 0x36};
static const uint8_t jpake_pms3[] = {
    0xa6, 0xa2, 0x47, 0xff, 0xb3, 0x90, 0x81, 0xf6, 0x28, 0x93, 0x31, 0x09, 0x59, 0xbb, 0x13, 0xe9,
    0x2a, 0x84, 0xea, 0x22, 0x67, 0x41, 0xaf, 0x79, 0x2e, 0x30, 0x25, 0xc6, 0x6a, 0x75, 0x9a, 0x22};

static const uint8_t jpake_random1[] = {
    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, // g1
    0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x21,
    0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, // v1
    0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55,
    0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69, 0x6a, 0x6b, 0x6c, 0x6d, 0x6e, 0x6f, 0x70, // g2
    0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x77, 0x78, 0x79, 0x7a, 0x7b, 0x7c, 0x7d, 0x7e, 0x7f, 0x81,
    0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, // v2
    0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55,
    0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69, 0x6a, 0x6b, 0x6c, 0x6d, 0x6e, 0x6f, 0x70, // g3
    0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x77, 0x78, 0x79, 0x7a, 0x7b, 0x7c, 0x7d, 0x7e, 0x7f, 0x81,
    0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, // v3
    0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55,
    0xc1, 0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7, 0xc8, 0xc9, 0xca, 0xcb, 0xcc, 0xcd, 0xce, 0xcf, 0xd0, // g4
    0xd1, 0xd2, 0xd3, 0xd4, 0xd5, 0xd6, 0xd7, 0xd8, 0xd9, 0xda, 0xdb, 0xdc, 0xdd, 0xde, 0xdf, 0xe1,
    0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, // v4
    0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55,
    0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, // v5
    0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55,
    0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, // v6
    0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55};
static const uint8_t jpake_random23[] = {
    0x5f, 0xd5, 0x79, 0xd3, 0x0e, 0xd3, 0x2a, 0x92, 0x60, 0x9e, 0xa4, 0xd7, 0xdf, 0xe3, 0x0a, 0x1b, // g1
    0x8c, 0xb1, 0xaa, 0x98, 0x21, 0xb5, 0x1f, 0xb0, 0xbc, 0xad, 0x1d, 0x94, 0x0f, 0xaa, 0x46, 0xf8,
    0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, // v1
    0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55,
    0x16, 0xda, 0xea, 0xd4, 0x48, 0xf5, 0xa2, 0x3c, 0x87, 0xb1, 0x5b, 0xed, 0x64, 0xc7, 0x3f, 0xaa, // g2
    0x54, 0xef, 0x06, 0x11, 0x57, 0xcd, 0x14, 0xdf, 0x75, 0x8b, 0x3a, 0x27, 0x11, 0xe1, 0x3a, 0x62,
    0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, // v2
    0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55,
    0x74, 0xb5, 0xc7, 0xd3, 0x51, 0x0d, 0x03, 0xcd, 0xfc, 0xd0, 0xd1, 0xc7, 0x78, 0x01, 0x84, 0x01, // g3
    0x55, 0x72, 0xad, 0xd2, 0x5a, 0x48, 0x83, 0x4c, 0x86, 0xe6, 0x38, 0xda, 0xc3, 0x1b, 0x2d, 0xad,
    0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, // v3
    0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55,
    0xf6, 0x7f, 0xa8, 0xc1, 0x60, 0x68, 0xce, 0x67, 0x48, 0x3b, 0x94, 0xbf, 0xbe, 0x95, 0xa3, 0x9c, // g4
    0xd4, 0xf9, 0x8f, 0x34, 0x88, 0x63, 0x03, 0x45, 0xd9, 0x73, 0x24, 0xf8, 0x82, 0x97, 0x7e, 0xe3,
    0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, // v4
    0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55,
    0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, // v5
    0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55,
    0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, // v6
    0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55};

static int setup_jpake_endpoint(psa_pake_operation_t *op,
    const char *user, const char *peer, psa_key_id_t pw_key)
{
    psa_pake_cipher_suite_t suite = PSA_PAKE_CIPHER_SUITE_INIT;
    psa_pake_primitive_t jpake_primitive =
        PSA_PAKE_PRIMITIVE(PSA_PAKE_PRIMITIVE_TYPE_ECC, PSA_ECC_FAMILY_SECP_R1, 256);

    psa_pake_cs_set_algorithm(&suite, PSA_ALG_JPAKE(PSA_ALG_SHA_256));
    psa_pake_cs_set_primitive(&suite, jpake_primitive);
    psa_pake_cs_set_key_confirmation(&suite, PSA_PAKE_UNCONFIRMED_KEY);

    TEST_ASSERT(psa_pake_setup(op, pw_key, &suite) == PSA_SUCCESS);
    TEST_ASSERT(psa_pake_set_user(op, (const uint8_t*)user, strlen(user)) == PSA_SUCCESS);
    TEST_ASSERT(psa_pake_set_peer(op, (const uint8_t*)peer, strlen(peer)) == PSA_SUCCESS);

    return 1;
exit:
    return 0;
}

static int test_jpake(const uint8_t *pw, size_t pw_len, int vect)
{
    psa_pake_operation_t first = PSA_PAKE_OPERATION_INIT;
    psa_pake_operation_t second = PSA_PAKE_OPERATION_INIT;
    psa_key_derivation_operation_t kdf = PSA_KEY_DERIVATION_OPERATION_INIT;
    psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;
    psa_key_id_t pw_key = 0, key = 0;
    uint8_t secret1[32], secret2[32];
    size_t share_size, public_size, proof_size;

    if (vect == 1) {
        oberon_test_drbg_setup(jpake_random1, sizeof jpake_random1);
    } else {
        oberon_test_drbg_setup(jpake_random23, sizeof jpake_random23);
    }

    psa_set_key_usage_flags(&attributes, PSA_KEY_USAGE_DERIVE);
    psa_set_key_algorithm(&attributes, PSA_ALG_JPAKE(PSA_ALG_SHA_256));
    psa_set_key_type(&attributes, PSA_KEY_TYPE_PASSWORD_HASH);
    TEST_ASSERT(psa_import_key(&attributes, pw, pw_len, &pw_key) == PSA_SUCCESS);

    TEST_ASSERT(setup_jpake_endpoint(&first, "client", "server", pw_key));
    TEST_ASSERT(setup_jpake_endpoint(&second, "server", "client", pw_key));

    share_size = PSA_PAKE_OUTPUT_SIZE(PSA_ALG_JPAKE(PSA_ALG_SHA_256),
        PSA_PAKE_PRIMITIVE(PSA_PAKE_PRIMITIVE_TYPE_ECC, PSA_ECC_FAMILY_SECP_R1, 256),
        PSA_PAKE_STEP_KEY_SHARE);
    public_size = PSA_PAKE_OUTPUT_SIZE(PSA_ALG_JPAKE(PSA_ALG_SHA_256),
        PSA_PAKE_PRIMITIVE(PSA_PAKE_PRIMITIVE_TYPE_ECC, PSA_ECC_FAMILY_SECP_R1, 256),
        PSA_PAKE_STEP_ZK_PUBLIC);
    proof_size = PSA_PAKE_OUTPUT_SIZE(PSA_ALG_JPAKE(PSA_ALG_SHA_256),
        PSA_PAKE_PRIMITIVE(PSA_PAKE_PRIMITIVE_TYPE_ECC, PSA_ECC_FAMILY_SECP_R1, 256),
        PSA_PAKE_STEP_ZK_PROOF);

    // Get g1
    TEST_ASSERT(send_message(&first, &second, PSA_PAKE_STEP_KEY_SHARE, NULL, share_size));
    // Get V1, the ZKP public key for x1
    TEST_ASSERT(send_message(&first, &second, PSA_PAKE_STEP_ZK_PUBLIC, NULL, public_size));
    // Get r1, the ZKP proof for x1
    TEST_ASSERT(send_message(&first, &second, PSA_PAKE_STEP_ZK_PROOF, NULL, proof_size));
    // Get g2
    TEST_ASSERT(send_message(&first, &second, PSA_PAKE_STEP_KEY_SHARE, NULL, share_size));
    // Get V2, the ZKP public key for x2
    TEST_ASSERT(send_message(&first, &second, PSA_PAKE_STEP_ZK_PUBLIC, NULL, public_size));
    // Get r2, the ZKP proof for x2
    TEST_ASSERT(send_message(&first, &second, PSA_PAKE_STEP_ZK_PROOF, NULL, proof_size));

    // Set g3
    TEST_ASSERT(send_message(&second, &first, PSA_PAKE_STEP_KEY_SHARE, NULL, share_size));
    // Set V3, the ZKP public key for x3
    TEST_ASSERT(send_message(&second, &first, PSA_PAKE_STEP_ZK_PUBLIC, NULL, public_size));
    // Set r3, the ZKP proof for x3
    TEST_ASSERT(send_message(&second, &first, PSA_PAKE_STEP_ZK_PROOF, NULL, proof_size));
    // Set g4
    TEST_ASSERT(send_message(&second, &first, PSA_PAKE_STEP_KEY_SHARE, NULL, share_size));
    // Set V4, the ZKP public key for x4
    TEST_ASSERT(send_message(&second, &first, PSA_PAKE_STEP_ZK_PUBLIC, NULL, public_size));
    // Set r4, the ZKP proof for x4
    TEST_ASSERT(send_message(&second, &first, PSA_PAKE_STEP_ZK_PROOF, NULL, proof_size));

    // Get A
    TEST_ASSERT(send_message(&first, &second, PSA_PAKE_STEP_KEY_SHARE, NULL, share_size));
    // Get V5, the ZKP public key for x2*s
    TEST_ASSERT(send_message(&first, &second, PSA_PAKE_STEP_ZK_PUBLIC, NULL, public_size));
    // Get r5, the ZKP proof for x2*s
    TEST_ASSERT(send_message(&first, &second, PSA_PAKE_STEP_ZK_PROOF, NULL, proof_size));

    // Set B
    TEST_ASSERT(send_message(&second, &first, PSA_PAKE_STEP_KEY_SHARE, NULL, share_size));
    // Set V6, the ZKP public key for x4*s
    TEST_ASSERT(send_message(&second, &first, PSA_PAKE_STEP_ZK_PUBLIC, NULL, public_size));
    // Set r6, the ZKP proof for x4*s
    TEST_ASSERT(send_message(&second, &first, PSA_PAKE_STEP_ZK_PROOF, NULL, proof_size));

    psa_set_key_type(&attributes, PSA_KEY_TYPE_DERIVE);
    psa_set_key_usage_flags(&attributes, PSA_KEY_USAGE_DERIVE);
    psa_set_key_algorithm(&attributes, PSA_ALG_TLS12_ECJPAKE_TO_PMS);

    // Set up the first KDF
    TEST_ASSERT(psa_pake_get_shared_key(&first, &attributes, &key) == PSA_SUCCESS);
    TEST_ASSERT(psa_pake_abort(&first) == PSA_SUCCESS);
    TEST_ASSERT(psa_key_derivation_setup(&kdf, PSA_ALG_TLS12_ECJPAKE_TO_PMS) == PSA_SUCCESS);
    TEST_ASSERT(psa_key_derivation_input_key(&kdf, PSA_KEY_DERIVATION_INPUT_SECRET, key) == PSA_SUCCESS);
    TEST_ASSERT(psa_key_derivation_output_bytes(&kdf, secret1, sizeof secret1) == PSA_SUCCESS);
    TEST_ASSERT(psa_key_derivation_abort(&kdf) == PSA_SUCCESS);
    TEST_ASSERT(psa_destroy_key(key) == PSA_SUCCESS);

    // Set up the second KDF
    TEST_ASSERT(psa_pake_get_shared_key(&second, &attributes, &key) == PSA_SUCCESS);
    TEST_ASSERT(psa_pake_abort(&second) == PSA_SUCCESS);
    TEST_ASSERT(psa_key_derivation_setup(&kdf, PSA_ALG_TLS12_ECJPAKE_TO_PMS) == PSA_SUCCESS);
    TEST_ASSERT(psa_key_derivation_input_key(&kdf, PSA_KEY_DERIVATION_INPUT_SECRET, key) == PSA_SUCCESS);
    TEST_ASSERT(psa_key_derivation_output_bytes(&kdf, secret2, sizeof secret2) == PSA_SUCCESS);
    TEST_ASSERT(psa_key_derivation_abort(&kdf) == PSA_SUCCESS);
    TEST_ASSERT(psa_destroy_key(key) == PSA_SUCCESS);

    ASSERT_COMPARE(secret1, sizeof secret1, secret2, sizeof secret2);
    if (vect == 1) {
        ASSERT_COMPARE(secret1, sizeof secret1, jpake_pms1, sizeof jpake_pms1);
    } else if (vect == 2) {
        ASSERT_COMPARE(secret1, sizeof secret1, jpake_pms2, sizeof jpake_pms2);
    } else if (vect == 3) {
        ASSERT_COMPARE(secret1, sizeof secret1, jpake_pms3, sizeof jpake_pms3);
    }

    TEST_ASSERT(psa_destroy_key(pw_key) == PSA_SUCCESS);

    return 1;
exit:
    psa_destroy_key(key);
    psa_destroy_key(pw_key);
    return 0;
}

static int setup_jpake_endpoint_err(psa_pake_operation_t *op,
    const char *user, const char *peer, psa_key_id_t *key, int n)
{
    uint8_t psk[16], data[64];
    size_t length;
    psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;
    psa_status_t expected = PSA_SUCCESS;
    psa_pake_cipher_suite_t suite = PSA_PAKE_CIPHER_SUITE_INIT;
    if (n == 1) { // wrong algorithm
        psa_pake_cs_set_algorithm(&suite, PSA_ALG_SHA_256);
        expected = PSA_ERROR_INVALID_ARGUMENT;
    } else {
        psa_pake_cs_set_algorithm(&suite, PSA_ALG_JPAKE(PSA_ALG_SHA_256));
    }

    if (n == 2) { // wrong primitive type
        psa_pake_cs_set_primitive(&suite,
            PSA_PAKE_PRIMITIVE((psa_pake_primitive_type_t) 0x03, PSA_ECC_FAMILY_SECP_R1, 256));
        expected = PSA_ERROR_INVALID_ARGUMENT;
    } else {
        psa_pake_cs_set_primitive(&suite,
            PSA_PAKE_PRIMITIVE(PSA_PAKE_PRIMITIVE_TYPE_ECC, PSA_ECC_FAMILY_SECP_R1, 256));
    }

    if (n == 3) { // incompatible confirmation
        psa_pake_cs_set_key_confirmation(&suite, PSA_PAKE_CONFIRMED_KEY);
        expected = PSA_ERROR_INVALID_ARGUMENT;
    } else {
        psa_pake_cs_set_key_confirmation(&suite, PSA_PAKE_UNCONFIRMED_KEY);
    }

    if (n == 4) { // incompatible usage
        psa_set_key_usage_flags(&attributes, PSA_KEY_USAGE_EXPORT);
        expected = PSA_ERROR_NOT_PERMITTED;
    } else {
        psa_set_key_usage_flags(&attributes, PSA_KEY_USAGE_DERIVE);
    }

    if (n == 5) { // incompatible algorithm
        psa_set_key_algorithm(&attributes, PSA_ALG_JPAKE(PSA_ALG_SHA_512));
        expected = PSA_ERROR_NOT_PERMITTED;
    } else {
        psa_set_key_algorithm(&attributes, PSA_ALG_JPAKE(PSA_ALG_SHA_256));
    }

    if (n == 6) { // wrong key type
        psa_set_key_type(&attributes, PSA_KEY_TYPE_RAW_DATA);
        expected = PSA_ERROR_INVALID_ARGUMENT;
    } else {
        psa_set_key_type(&attributes, PSA_KEY_TYPE_PASSWORD_HASH);
    }

    if (n == 7) { // wrong key data
        memset(psk, 0, sizeof psk);
        TEST_ASSERT(psa_import_key(&attributes, psk, sizeof psk, key) == PSA_SUCCESS);
        expected = PSA_ERROR_INVALID_ARGUMENT;
    } else {
        TEST_ASSERT(psa_import_key(&attributes, jpake_psk, sizeof jpake_psk, key) == PSA_SUCCESS);
    }

    TEST_ASSERT(psa_pake_setup(op, *key, &suite) == expected);
    if (expected != PSA_SUCCESS) return 1;

    if (n == 8) { // already started
        TEST_ASSERT(psa_pake_setup(op, *key, &suite) == PSA_ERROR_BAD_STATE);
        return 1;
    }

    if (n == 9) { // output before set_user
        TEST_ASSERT(psa_pake_output(op, PSA_PAKE_STEP_KEY_SHARE, data, sizeof data, &length) == PSA_ERROR_BAD_STATE);
    }

    if (n == 10) { // set_peer before set_user
        TEST_ASSERT(psa_pake_set_peer(op, (const uint8_t*)peer, strlen(peer)) == PSA_ERROR_BAD_STATE);
        return 1;
    }

    if (n == 11) { // wrong role
        TEST_ASSERT(psa_pake_set_role(op, PSA_PAKE_ROLE_CLIENT) == PSA_ERROR_INVALID_ARGUMENT);
        return 1;
    }

    if (n == 12) { // wrong user
        TEST_ASSERT(psa_pake_set_user(op, (const uint8_t*)"", 0) == PSA_ERROR_INVALID_ARGUMENT);
        return 1;
    } else {
        TEST_ASSERT(psa_pake_set_user(op, (const uint8_t*)user, strlen(user)) == PSA_SUCCESS);
    }

    if (n == 13) { // output before set_peer
        TEST_ASSERT(psa_pake_output(op, PSA_PAKE_STEP_KEY_SHARE, data, sizeof data, &length) == PSA_ERROR_BAD_STATE);
    }

    if (n == 14) { // wrong peer
        TEST_ASSERT(psa_pake_set_peer(op, (const uint8_t*)user, strlen(user)) == PSA_ERROR_INVALID_ARGUMENT);
        return 1;
    } else {
        TEST_ASSERT(psa_pake_set_peer(op, (const uint8_t*)peer, strlen(peer)) == PSA_SUCCESS);
    }

    return 1;
exit:
    return 0;
}

static int test_jpake_exchange_err(psa_pake_operation_t *op1, psa_pake_operation_t *op2, int n)
{
    if (n == 1) { // wrong direction
        TEST_ASSERT(send_message_err(op2, op1, PSA_PAKE_STEP_KEY_SHARE, 1));
        return 1;
    } else if (n == 2) { // key share missing
        TEST_ASSERT(send_message_err(op1, op2, PSA_PAKE_STEP_ZK_PUBLIC, 1));
        return 1;
    } else if (n == 3) { // wrong input size
        TEST_ASSERT(send_message_err(op1, op2, PSA_PAKE_STEP_KEY_SHARE, 2));
        return 1;
    } else {
        TEST_ASSERT(send_message_err(op1, op2, PSA_PAKE_STEP_KEY_SHARE, 0));
    }

    if (n == 4) { // wrong direction
        TEST_ASSERT(send_message_err(op2, op1, PSA_PAKE_STEP_ZK_PUBLIC, 1));
        return 1;
    } else if (n == 5) { // zk public missing
        TEST_ASSERT(send_message_err(op1, op2, PSA_PAKE_STEP_ZK_PROOF, 1));
        return 1;
    } else if (n == 6) { // wrong input size
        TEST_ASSERT(send_message_err(op1, op2, PSA_PAKE_STEP_ZK_PUBLIC, 2));
        return 1;
    } else {
        TEST_ASSERT(send_message_err(op1, op2, PSA_PAKE_STEP_ZK_PUBLIC, 0));
    }

    if (n == 7) { // wrong direction
        TEST_ASSERT(send_message_err(op2, op1, PSA_PAKE_STEP_ZK_PROOF, 1));
        return 1;
    } else if (n == 8) { // wrong proof size
        TEST_ASSERT(send_message_err(op1, op2, PSA_PAKE_STEP_ZK_PROOF, 3));
        return 1;
    } else if (n == 9) { // wrong proof data
        TEST_ASSERT(send_message_err(op1, op2, PSA_PAKE_STEP_ZK_PROOF, 4));
        return 1;
    } else {
        TEST_ASSERT(send_message_err(op1, op2, PSA_PAKE_STEP_ZK_PROOF, 0));
    }

    return 1;
exit:
    return 0;
}

static int test_jpake_err(int n)
{
    psa_pake_operation_t first = PSA_PAKE_OPERATION_INIT;
    psa_pake_operation_t second = PSA_PAKE_OPERATION_INIT;
    psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;
    psa_key_id_t key1 = 0, key2 = 0, key = 0;
    uint8_t data[32];
    size_t length;

    if (n <= 14) { // error in client setup
        TEST_ASSERT(setup_jpake_endpoint_err(&first, "client", "server", &key1, n));
        goto abort;
    } else {
        TEST_ASSERT(setup_jpake_endpoint_err(&first, "client", "server", &key1, 0));
    }
    if (n > 14 && n <= 28) { // error in server setup
        TEST_ASSERT(setup_jpake_endpoint_err(&second, "server", "client", &key2, n - 14));
        goto abort;
    } else {
        TEST_ASSERT(setup_jpake_endpoint_err(&second, "server", "client", &key2, 0));
    }

    psa_set_key_type(&attributes, PSA_KEY_TYPE_DERIVE);
    psa_set_key_usage_flags(&attributes, PSA_KEY_USAGE_DERIVE);
    psa_set_key_algorithm(&attributes, PSA_ALG_TLS12_ECJPAKE_TO_PMS);

    if (n > 28 && n <= 36) {
        TEST_ASSERT(test_jpake_exchange_err(&first, &second, n - 27)); // >= 2
        goto abort;
    } else {
        TEST_ASSERT(test_jpake_exchange_err(&first, &second, 0));
    }
    if (n > 36 && n <= 45) {
        TEST_ASSERT(test_jpake_exchange_err(&first, &second, n - 36));
        goto abort;
    } else {
        TEST_ASSERT(test_jpake_exchange_err(&first, &second, 0));
    }
    if (n > 45 && n <= 54) {
        TEST_ASSERT(test_jpake_exchange_err(&second, &first, n - 45));
        goto abort;
    } else {
        TEST_ASSERT(test_jpake_exchange_err(&second, &first, 0));
    }
    if (n == 55) { // wrong step
        TEST_ASSERT(psa_pake_input(&first, PSA_PAKE_STEP_SALT, jpake_psk, sizeof jpake_psk) == PSA_ERROR_INVALID_ARGUMENT);
        goto abort;
    }
    if (n == 56) { // wrong step
        TEST_ASSERT(psa_pake_output(&first, PSA_PAKE_STEP_CONFIRM, data, sizeof data, &length) == PSA_ERROR_INVALID_ARGUMENT);
        goto abort;
    }
    if (n > 56 && n <= 65) {
        TEST_ASSERT(test_jpake_exchange_err(&second, &first, n - 56));
        goto abort;
    } else {
        TEST_ASSERT(test_jpake_exchange_err(&second, &first, 0));
    }
    if (n == 66) { // early get_shared_secret
        TEST_ASSERT(psa_pake_get_shared_key(&first, &attributes, &key) == PSA_ERROR_BAD_STATE);
        TEST_ASSERT(psa_pake_get_shared_key(&second, &attributes, &key) == PSA_ERROR_BAD_STATE);
        goto abort;
    }
    if (n > 66 && n <= 74) {
        TEST_ASSERT(test_jpake_exchange_err(&first, &second, n - 65)); // >= 2
        goto abort;
    } else {
        TEST_ASSERT(test_jpake_exchange_err(&first, &second, 0));
    }
    if (n == 75) { // early get_shared_secret
        TEST_ASSERT(psa_pake_get_shared_key(&first, &attributes, &key) == PSA_ERROR_BAD_STATE);
        TEST_ASSERT(psa_pake_get_shared_key(&second, &attributes, &key) == PSA_ERROR_BAD_STATE);
        goto abort;
    }
    if (n > 75 && n <= 84) {
        TEST_ASSERT(test_jpake_exchange_err(&second, &first, n - 75));
        goto abort;
    } else {
        TEST_ASSERT(test_jpake_exchange_err(&second, &first, 0));
    }

    switch (n) {
    case 85: // invalid key type
        psa_set_key_type(&attributes, PSA_KEY_TYPE_RSA_PUBLIC_KEY);
        TEST_ASSERT(psa_pake_get_shared_key(&first, &attributes, &key) == PSA_ERROR_INVALID_ARGUMENT);
        TEST_ASSERT(key == 0);
        goto abort;
    case 86: // invalid key type
        psa_set_key_type(&attributes, PSA_KEY_TYPE_RSA_PUBLIC_KEY);
        TEST_ASSERT(psa_pake_get_shared_key(&second, &attributes, &key) == PSA_ERROR_INVALID_ARGUMENT);
        TEST_ASSERT(key == 0);
        goto abort;
    case 87: // key size > 0
        psa_set_key_bits(&attributes, 256);
        TEST_ASSERT(psa_pake_get_shared_key(&first, &attributes, &key) == PSA_ERROR_INVALID_ARGUMENT);
        TEST_ASSERT(key == 0);
        goto abort;
    case 88: // key size > 0
        psa_set_key_bits(&attributes, 256);
        TEST_ASSERT(psa_pake_get_shared_key(&second, &attributes, &key) == PSA_ERROR_INVALID_ARGUMENT);
        TEST_ASSERT(key == 0);
        goto abort;
    }

abort:
    TEST_ASSERT(psa_pake_abort(&first) == PSA_SUCCESS);
    TEST_ASSERT(psa_pake_abort(&second) == PSA_SUCCESS);
    TEST_ASSERT(psa_destroy_key(key) == PSA_SUCCESS);
    TEST_ASSERT(psa_destroy_key(key1) == PSA_SUCCESS);
    TEST_ASSERT(psa_destroy_key(key2) == PSA_SUCCESS);
    return 1;
exit:
    psa_destroy_key(key);
    psa_destroy_key(key1);
    psa_destroy_key(key2);
    return 0;
}
#endif // PSA_WANT_ALG_JPAKE


/*
 * SPAKE2+ Tests
 */
#if defined(PSA_WANT_ALG_SPAKE2P_HMAC) || defined(PSA_WANT_ALG_SPAKE2P_CMAC) || defined(PSA_WANT_ALG_SPAKE2P_MATTER)

static const uint8_t spake2p_w01_0[] = {
    0xbb, 0x8e, 0x1b, 0xbc, 0xf3, 0xc4, 0x8f, 0x62, 0xc0, 0x8d, 0xb2, 0x43, 0x65, 0x2a, 0xe5, 0x5d,
    0x3e, 0x55, 0x86, 0x05, 0x3f, 0xca, 0x77, 0x10, 0x29, 0x94, 0xf2, 0x3a, 0xd9, 0x54, 0x91, 0xb3,
    0x7e, 0x94, 0x5f, 0x34, 0xd7, 0x87, 0x85, 0xb8, 0xa3, 0xef, 0x44, 0xd0, 0xdf, 0x5a, 0x1a, 0x97,
    0xd6, 0xb3, 0xb4, 0x60, 0x40, 0x9a, 0x34, 0x5c, 0xa7, 0x83, 0x03, 0x87, 0xa7, 0x4b, 0x1d, 0xba};
static const uint8_t spake2p_w0L_0[] = {
    0xbb, 0x8e, 0x1b, 0xbc, 0xf3, 0xc4, 0x8f, 0x62, 0xc0, 0x8d, 0xb2, 0x43, 0x65, 0x2a, 0xe5, 0x5d,
    0x3e, 0x55, 0x86, 0x05, 0x3f, 0xca, 0x77, 0x10, 0x29, 0x94, 0xf2, 0x3a, 0xd9, 0x54, 0x91, 0xb3,
    0x04,
    0xeb, 0x7c, 0x9d, 0xb3, 0xd9, 0xa9, 0xeb, 0x1f, 0x8a, 0xda, 0xb8, 0x1b, 0x57, 0x94, 0xc1, 0xf1,
    0x3a, 0xe3, 0xe2, 0x25, 0xef, 0xbe, 0x91, 0xea, 0x48, 0x74, 0x25, 0x85, 0x4c, 0x7f, 0xc0, 0x0f,
    0x00, 0xbf, 0xed, 0xcb, 0xd0, 0x9b, 0x24, 0x00, 0x14, 0x2d, 0x40, 0xa1, 0x4f, 0x20, 0x64, 0xef,
    0x31, 0xdf, 0xaa, 0x90, 0x3b, 0x91, 0xd1, 0xfa, 0xea, 0x70, 0x93, 0xd8, 0x35, 0x96, 0x6e, 0xfd};
static const uint8_t spake2p_w01_2[] = {
    0x93, 0x13, 0xf3, 0xe3, 0x14, 0x51, 0xe8, 0xb5, 0xd3, 0x68, 0x78, 0x94, 0xed, 0xc4, 0xf6, 0x24,
    0x39, 0x73, 0x92, 0xf1, 0xc0, 0xb8, 0x6f, 0x9e, 0x5b, 0xb0, 0x39, 0xcb, 0x66, 0xa7, 0xa8, 0x30,
    0x4d, 0x5a, 0x0f, 0x0e, 0x44, 0x3f, 0x73, 0xda, 0xfa, 0x22, 0xa8, 0x99, 0x65, 0xa5, 0xba, 0x3a,
    0x69, 0xd6, 0xfa, 0xaf, 0x6f, 0x18, 0x48, 0x76, 0xa0, 0xb4, 0x01, 0xc7, 0xa8, 0xe3, 0xab, 0xf4};
static const uint8_t spake2p_w0L_2[] = {
    0x93, 0x13, 0xf3, 0xe3, 0x14, 0x51, 0xe8, 0xb5, 0xd3, 0x68, 0x78, 0x94, 0xed, 0xc4, 0xf6, 0x24, 
    0x39, 0x73, 0x92, 0xf1, 0xc0, 0xb8, 0x6f, 0x9e, 0x5b, 0xb0, 0x39, 0xcb, 0x66, 0xa7, 0xa8, 0x30, 
    0x04, 
    0xc7, 0xa5, 0xbc, 0x68, 0x8f, 0xbe, 0x4f, 0x4f, 0x00, 0x75, 0xb2, 0xe4, 0xcf, 0x30, 0x37, 0xbe, 
    0x17, 0xce, 0xab, 0x07, 0x46, 0xbe, 0xa0, 0xc2, 0xba, 0x49, 0xb8, 0x05, 0x97, 0xcf, 0x8a, 0xf1, 
    0x82, 0x05, 0x81, 0x6e, 0x00, 0x3d, 0x52, 0xd7, 0xca, 0xaa, 0x47, 0x29, 0x9c, 0xc9, 0xfe, 0xba, 
    0xc7, 0xa9, 0xbe, 0x38, 0xba, 0x26, 0xbb, 0xd0, 0x41, 0x73, 0x10, 0x46, 0xa4, 0x2b, 0x91, 0x81}; 
static const uint8_t spake2p_w01_4[] = {
    0x55, 0xce, 0x1c, 0x0e, 0x10, 0x5d, 0xae, 0x65, 0x78, 0x36, 0x8c, 0x64, 0xc8, 0x4b, 0xac, 0xaf,
    0xab, 0xa2, 0x43, 0xc5, 0xbc, 0xd3, 0xc1, 0xf7, 0x26, 0x8c, 0x63, 0xa9, 0x17, 0xbc, 0x64, 0x3b,
    0xc6, 0xe0, 0x15, 0xa8, 0x2d, 0x43, 0xe2, 0x85, 0x16, 0x55, 0xae, 0x7e, 0x95, 0x6c, 0x18, 0x70, 
    0x4d, 0xb5, 0x37, 0x94, 0x41, 0x21, 0x9b, 0xb3, 0xd7, 0x1c, 0x4c, 0x53, 0x3b, 0xdc, 0x40, 0x2d};
static const uint8_t spake2p_w0L_4[] = {
    0x55, 0xce, 0x1c, 0x0e, 0x10, 0x5d, 0xae, 0x65, 0x78, 0x36, 0x8c, 0x64, 0xc8, 0x4b, 0xac, 0xaf,
    0xab, 0xa2, 0x43, 0xc5, 0xbc, 0xd3, 0xc1, 0xf7, 0x26, 0x8c, 0x63, 0xa9, 0x17, 0xbc, 0x64, 0x3b,
    0x04, 
    0xfc, 0xd7, 0xe0, 0x0e, 0xe6, 0xac, 0x58, 0xc6, 0xb7, 0x5e, 0x0e, 0xa1, 0xb4, 0x4d, 0x45, 0xcd, 
    0xcd, 0x47, 0x98, 0x0d, 0x6d, 0xa6, 0x27, 0x15, 0x45, 0x07, 0x12, 0xe3, 0x6e, 0xaa, 0xb5, 0xda, 
    0x30, 0xf2, 0xa8, 0xa4, 0x8e, 0x01, 0x79, 0xf6, 0xba, 0x60, 0x62, 0x7f, 0x22, 0xee, 0xe1, 0x0d, 
    0x51, 0xb8, 0x0c, 0x5d, 0xee, 0xb1, 0x95, 0x61, 0xe9, 0x41, 0x7d, 0xb7, 0xef, 0xd4, 0x12, 0x86};
static const uint8_t spake2p_w01_6[] = {
    0xe6, 0x88, 0x7c, 0xf9, 0xbd, 0xfb, 0x75, 0x79, 0xc6, 0x9b, 0xf4, 0x79, 0x28, 0xa8, 0x45, 0x14,
    0xb5, 0xe3, 0x55, 0xac, 0x03, 0x48, 0x63, 0xf7, 0xff, 0xaf, 0x43, 0x90, 0xe6, 0x7d, 0x79, 0x8c,
    0x24, 0xb5, 0xae, 0x4a, 0xbd, 0xa8, 0x68, 0xec, 0x93, 0x36, 0xff, 0xc3, 0xb7, 0x8e, 0xe3, 0x1c,
    0x57, 0x55, 0xbe, 0xf1, 0x75, 0x92, 0x27, 0xef, 0x53, 0x72, 0xca, 0x13, 0x9b, 0x94, 0xe5, 0x12};
static const uint8_t spake2p_w0L_6[] = {
    0xe6, 0x88, 0x7c, 0xf9, 0xbd, 0xfb, 0x75, 0x79, 0xc6, 0x9b, 0xf4, 0x79, 0x28, 0xa8, 0x45, 0x14,
    0xb5, 0xe3, 0x55, 0xac, 0x03, 0x48, 0x63, 0xf7, 0xff, 0xaf, 0x43, 0x90, 0xe6, 0x7d, 0x79, 0x8c,
    0x04,
    0x95, 0x64, 0x5c, 0xfb, 0x74, 0xdf, 0x6e, 0x58, 0xf9, 0x74, 0x8b, 0xb8, 0x3a, 0x86, 0x62, 0x0b,
    0xab, 0x7c, 0x82, 0xe1, 0x07, 0xf5, 0x7d, 0x68, 0x70, 0xda, 0x8c, 0xbc, 0xb2, 0xff, 0x9f, 0x70,
    0x63, 0xa1, 0x4b, 0x64, 0x02, 0xc6, 0x2f, 0x99, 0xaf, 0xcb, 0x97, 0x06, 0xa4, 0xd1, 0xa1, 0x43,
    0x27, 0x32, 0x59, 0xfe, 0x76, 0xf1, 0xc6, 0x05, 0xa3, 0x63, 0x97, 0x45, 0xa9, 0x21, 0x54, 0xb9};

static const uint8_t spake2p_secret1[32] = {
    0x0c, 0x5f, 0x8c, 0xcd, 0x14, 0x13, 0x42, 0x3a, 0x54, 0xf6, 0xc1, 0xfb, 0x26, 0xff, 0x01, 0x53,
    0x4a, 0x87, 0xf8, 0x93, 0x77, 0x9c, 0x6e, 0x68, 0x66, 0x6d, 0x77, 0x2b, 0xfd, 0x91, 0xf3, 0xe7};
static const uint8_t spake2p_secret2[32] = {
    0x16, 0x16, 0xea, 0x63, 0xa4, 0xc3, 0x57, 0xf2, 0x90, 0xc5, 0x94, 0xad, 0x11, 0xa0, 0x91, 0x4b,
    0x4f, 0x82, 0x28, 0xe2, 0x18, 0x83, 0xe7, 0xae, 0xdb, 0x2c, 0xb8, 0xcb, 0x0d, 0x83, 0x17, 0x39};
static const uint8_t spake2p_secret3[16] = {
    0x97, 0xdf, 0x07, 0x79, 0xc5, 0x08, 0x05, 0x5a, 0xd6, 0x97, 0xed, 0xe1, 0x2a, 0x62, 0x1a, 0x2d};
static const uint8_t spake2p_secret4[32] = {
    0x77, 0xbd, 0xe8, 0x67, 0x50, 0x2d, 0xb8, 0xae, 0x3e, 0xfa, 0x82, 0x7f, 0x11, 0x0d, 0x57, 0xb7,
    0xaa, 0x88, 0xaa, 0x62, 0xef, 0x89, 0x3c, 0xf6, 0xfe, 0x3f, 0xa6, 0xa2, 0x1e, 0x3a, 0xa8, 0xb6};
static const uint8_t spake2p_secret5[16] = {
    0xbb, 0x22, 0x96, 0xfa, 0x25, 0x74, 0x32, 0x7d, 0x5e, 0x78, 0xc2, 0xda, 0x35, 0x55, 0x56, 0x7c};
static const uint8_t spake2p_secret6[16] = {
    0x80, 0x1d, 0xb2, 0x97, 0x65, 0x48, 0x16, 0xeb, 0x4f, 0x02, 0x86, 0x81, 0x29, 0xb9, 0xdc, 0x89};

static const uint8_t spake2p_random_1[2 * 40] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // shareP
    0xd1, 0x23, 0x2c, 0x8e, 0x86, 0x93, 0xd0, 0x23, 0x68, 0x97, 0x6c, 0x17, 0x4e, 0x20, 0x88, 0x85,
    0x1b, 0x83, 0x65, 0xd0, 0xd7, 0x9a, 0x9e, 0xee, 0x70, 0x9c, 0x6a, 0x05, 0xa2, 0xfa, 0xd5, 0x39,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // shareV
    0x71, 0x7a, 0x72, 0x34, 0x8a, 0x18, 0x20, 0x85, 0x10, 0x9c, 0x8d, 0x39, 0x17, 0xd6, 0xc4, 0x3d,
    0x59, 0xb2, 0x24, 0xdc, 0x6a, 0x7f, 0xc4, 0xf0, 0x48, 0x32, 0x32, 0xfa, 0x65, 0x16, 0xd8, 0xb3};
static const uint8_t spake2p_random_2[2 * 40] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // shareP
    0x5f, 0xd5, 0x79, 0xd3, 0x0e, 0xd3, 0x2a, 0x92, 0x60, 0x9e, 0xa4, 0xd7, 0xdf, 0xe3, 0x0a, 0x1b,
    0x8c, 0xb1, 0xaa, 0x98, 0x21, 0xb5, 0x1f, 0xb0, 0xbc, 0xad, 0x1d, 0x94, 0x0f, 0xaa, 0x46, 0xf8,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // shareV
    0x16, 0xda, 0xea, 0xd4, 0x48, 0xf5, 0xa2, 0x3c, 0x87, 0xb1, 0x5b, 0xed, 0x64, 0xc7, 0x3f, 0xaa,
    0x54, 0xef, 0x06, 0x11, 0x57, 0xcd, 0x14, 0xdf, 0x75, 0x8b, 0x3a, 0x27, 0x11, 0xe1, 0x3a, 0x62};
static const uint8_t spake2p_random_6[2 * 40] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // shareP
    0x8b, 0x0f, 0x3f, 0x38, 0x39, 0x05, 0xcf, 0x3a, 0x3b, 0xb9, 0x55, 0xef, 0x8f, 0xb6, 0x2e, 0x24,
    0x84, 0x9d, 0xd3, 0x49, 0xa0, 0x5c, 0xa7, 0x9a, 0xaf, 0xb1, 0x80, 0x41, 0xd3, 0x0c, 0xbd, 0xb6,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // shareV
    0x2e, 0x08, 0x95, 0xb0, 0xe7, 0x63, 0xd6, 0xd5, 0xa9, 0x56, 0x44, 0x33, 0xe6, 0x4a, 0xc3, 0xca,
    0xc7, 0x4f, 0xf8, 0x97, 0xf6, 0xc3, 0x44, 0x52, 0x47, 0xba, 0x1b, 0xab, 0x40, 0x08, 0x2a, 0x91};

static const char spake2p_hmac[] = "SPAKE2+-P256-SHA256-HKDF-SHA256-HMAC-SHA256 Test Vectors";
static const char spake2p_s512[] = "SPAKE2+-P256-SHA512-HKDF-SHA512-HMAC-SHA512 Test Vectors";
static const char spake2p_cmac[] = "SPAKE2+-P256-SHA256-HKDF-SHA256-CMAC-AES-128 Test Vectors";
static const char spake2p_d_01[] = "SPAKE2+-P256-SHA256-HKDF draft-01";
static const char spake2p_zero[] = "";
static const char spake2p_null[] = "";


static int setup_spake2p_endpoint(psa_pake_operation_t *op,
    psa_pake_role_t role, const char *user, const char *peer, const char *context,
    psa_algorithm_t alg, psa_key_id_t key)
{
    psa_pake_cipher_suite_t suite = PSA_PAKE_CIPHER_SUITE_INIT;
    psa_pake_primitive_t spake2p_primitive =
        PSA_PAKE_PRIMITIVE(PSA_PAKE_PRIMITIVE_TYPE_ECC, PSA_ECC_FAMILY_SECP_R1, 256);

    psa_pake_cs_set_algorithm(&suite, alg);
    psa_pake_cs_set_primitive(&suite, spake2p_primitive);

    TEST_ASSERT(psa_pake_setup(op, key, &suite) == PSA_SUCCESS);
    TEST_ASSERT(psa_pake_set_role(op, role) == PSA_SUCCESS);

    if (user) {
        TEST_ASSERT(psa_pake_set_user(op, (const uint8_t*)user, strlen(user)) == PSA_SUCCESS);
    }
    if (peer) {
        TEST_ASSERT(psa_pake_set_peer(op, (const uint8_t*)peer, strlen(peer)) == PSA_SUCCESS);
    }
    if (context) {
        size_t len = strlen(context);
        if (context == spake2p_null) context = NULL;
        TEST_ASSERT(psa_pake_set_context(op, (const uint8_t*)context, len) == PSA_SUCCESS);
    }

    return 1;
exit:
    return 0;
}

static int test_spake2p(psa_algorithm_t alg, const char *context, const char *user, const char *peer, int vect)
{
    psa_pake_operation_t client = PSA_PAKE_OPERATION_INIT;
    psa_pake_operation_t server = PSA_PAKE_OPERATION_INIT;
    psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;
    psa_key_id_t key = 0, ckey = 0, skey = 0;
    uint8_t secret1[64], secret2[64], pub_key[97];
    size_t length1, length2, pub_len;
    psa_key_derivation_operation_t kdf = PSA_KEY_DERIVATION_OPERATION_INIT;
    psa_algorithm_t kdf_alg = PSA_ALG_PBKDF2_HMAC(PSA_ALG_GET_HASH(alg));
    size_t share_size, conf_size;

    if (vect >= 2 && vect <= 5) { // use password -> secret vector
        oberon_test_drbg_setup(spake2p_random_2, sizeof spake2p_random_2);

        psa_set_key_usage_flags(&attributes, PSA_KEY_USAGE_DERIVE);
        psa_set_key_algorithm(&attributes, kdf_alg);
        psa_set_key_type(&attributes, PSA_KEY_TYPE_PASSWORD);
        if (vect <= 3) {
            TEST_ASSERT(psa_import_key(&attributes, (const uint8_t*)"p", 1, &key) == PSA_SUCCESS);
        } else {
            TEST_ASSERT(psa_import_key(&attributes,
                (const uint8_t*)"this is a very long password and it is very nice, so it should be completely ok.",
                80, &key) == PSA_SUCCESS);
        }

        psa_set_key_usage_flags(&attributes, PSA_KEY_USAGE_DERIVE | PSA_KEY_USAGE_EXPORT);
        psa_set_key_algorithm(&attributes, alg);
        psa_set_key_bits(&attributes, 256);
        psa_set_key_type(&attributes, PSA_KEY_TYPE_SPAKE2P_KEY_PAIR(PSA_ECC_FAMILY_SECP_R1));
        TEST_ASSERT(psa_key_derivation_setup(&kdf, kdf_alg) == PSA_SUCCESS);
        TEST_ASSERT(psa_key_derivation_input_integer(&kdf, PSA_KEY_DERIVATION_INPUT_COST, 10) == PSA_SUCCESS);
        TEST_ASSERT(psa_key_derivation_input_bytes(&kdf, PSA_KEY_DERIVATION_INPUT_SALT,
            (const uint8_t*)"clientserver", 12) == PSA_SUCCESS);
        TEST_ASSERT(psa_key_derivation_input_key(&kdf, PSA_KEY_DERIVATION_INPUT_PASSWORD, key) == PSA_SUCCESS);
        TEST_ASSERT(psa_key_derivation_output_key(&attributes, &kdf, &ckey) == PSA_SUCCESS);
        TEST_ASSERT(psa_key_derivation_abort(&kdf) == PSA_SUCCESS);
        TEST_ASSERT(psa_destroy_key(key) == PSA_SUCCESS);

        if (vect <= 3) {
            TEST_ASSERT(psa_export_key(ckey, pub_key, sizeof pub_key, &pub_len) == PSA_SUCCESS);
            ASSERT_COMPARE(pub_key, pub_len, spake2p_w01_2, sizeof spake2p_w01_2);
            TEST_ASSERT(psa_export_public_key(ckey, pub_key, sizeof pub_key, &pub_len) == PSA_SUCCESS);
            ASSERT_COMPARE(pub_key, pub_len, spake2p_w0L_2, sizeof spake2p_w0L_2);
        } else {
            TEST_ASSERT(psa_export_key(ckey, pub_key, sizeof pub_key, &pub_len) == PSA_SUCCESS);
            ASSERT_COMPARE(pub_key, pub_len, spake2p_w01_4, sizeof spake2p_w01_4);
            TEST_ASSERT(psa_export_public_key(ckey, pub_key, sizeof pub_key, &pub_len) == PSA_SUCCESS);
            ASSERT_COMPARE(pub_key, pub_len, spake2p_w0L_4, sizeof spake2p_w0L_4);
        }

        psa_set_key_type(&attributes, PSA_KEY_TYPE_SPAKE2P_PUBLIC_KEY(PSA_ECC_FAMILY_SECP_R1));
        TEST_ASSERT(psa_import_key(&attributes, pub_key, pub_len, &skey) == PSA_SUCCESS);

    } else if (vect == 6) {
        oberon_test_drbg_setup(spake2p_random_6, sizeof spake2p_random_6);

        psa_set_key_usage_flags(&attributes, PSA_KEY_USAGE_DERIVE);
        psa_set_key_algorithm(&attributes, alg);
        psa_set_key_type(&attributes, PSA_KEY_TYPE_SPAKE2P_KEY_PAIR(PSA_ECC_FAMILY_SECP_R1));
        TEST_ASSERT(psa_import_key(&attributes, spake2p_w01_6, sizeof spake2p_w01_6, &ckey) == PSA_SUCCESS);

        TEST_ASSERT(psa_export_public_key(ckey, pub_key, sizeof pub_key, &pub_len) == PSA_SUCCESS);
        ASSERT_COMPARE(pub_key, pub_len, spake2p_w0L_6, sizeof spake2p_w0L_6);
        psa_set_key_type(&attributes, PSA_KEY_TYPE_SPAKE2P_PUBLIC_KEY(PSA_ECC_FAMILY_SECP_R1));
        TEST_ASSERT(psa_import_key(&attributes, pub_key, pub_len, &skey) == PSA_SUCCESS);

    } else { // use w0:w1
        oberon_test_drbg_setup(spake2p_random_1, sizeof spake2p_random_1);

        psa_set_key_usage_flags(&attributes, PSA_KEY_USAGE_DERIVE);
        psa_set_key_algorithm(&attributes, alg);
        psa_set_key_type(&attributes, PSA_KEY_TYPE_SPAKE2P_KEY_PAIR(PSA_ECC_FAMILY_SECP_R1));
        TEST_ASSERT(psa_import_key(&attributes, spake2p_w01_0, sizeof spake2p_w01_0, &ckey) == PSA_SUCCESS);

        TEST_ASSERT(psa_export_public_key(ckey, pub_key, sizeof pub_key, &pub_len) == PSA_SUCCESS);
        ASSERT_COMPARE(pub_key, pub_len, spake2p_w0L_0, sizeof spake2p_w0L_0);
        psa_set_key_type(&attributes, PSA_KEY_TYPE_SPAKE2P_PUBLIC_KEY(PSA_ECC_FAMILY_SECP_R1));
        TEST_ASSERT(psa_import_key(&attributes, pub_key, pub_len, &skey) == PSA_SUCCESS);
    }

    TEST_ASSERT(setup_spake2p_endpoint(&client, PSA_PAKE_ROLE_CLIENT, user, peer, context, alg, ckey));
    TEST_ASSERT(setup_spake2p_endpoint(&server, PSA_PAKE_ROLE_SERVER, peer, user, context, alg, skey));

    share_size = PSA_PAKE_OUTPUT_SIZE(alg,
        PSA_PAKE_PRIMITIVE(PSA_PAKE_PRIMITIVE_TYPE_ECC, PSA_ECC_FAMILY_SECP_R1, 256),
        PSA_PAKE_STEP_KEY_SHARE);
    conf_size = PSA_PAKE_OUTPUT_SIZE(alg,
        PSA_PAKE_PRIMITIVE(PSA_PAKE_PRIMITIVE_TYPE_ECC, PSA_ECC_FAMILY_SECP_R1, 256),
        PSA_PAKE_STEP_CONFIRM);

    // shareP
    TEST_ASSERT(send_message(&client, &server, PSA_PAKE_STEP_KEY_SHARE, NULL, share_size));
    // shareV
    TEST_ASSERT(send_message(&server, &client, PSA_PAKE_STEP_KEY_SHARE, NULL, share_size));
    // confirmV
    TEST_ASSERT(send_message(&server, &client, PSA_PAKE_STEP_CONFIRM, NULL, conf_size));
    // confirmP
    TEST_ASSERT(send_message(&client, &server, PSA_PAKE_STEP_CONFIRM, NULL, conf_size));

    psa_set_key_type(&attributes, PSA_KEY_TYPE_AES);
    psa_set_key_usage_flags(&attributes, PSA_KEY_USAGE_EXPORT);
    psa_set_key_algorithm(&attributes, PSA_ALG_GCM);
    psa_set_key_bits(&attributes, 0);

    // get client secret
    TEST_ASSERT(psa_pake_get_shared_key(&client, &attributes, &key) == PSA_SUCCESS);
    TEST_ASSERT(psa_pake_abort(&client) == PSA_SUCCESS);
    TEST_ASSERT(psa_destroy_key(ckey) == PSA_SUCCESS);
    TEST_ASSERT(psa_export_key(key, secret1, sizeof secret1, &length1) == PSA_SUCCESS);
    TEST_ASSERT(psa_destroy_key(key) == PSA_SUCCESS);

    // get server secret
    TEST_ASSERT(psa_pake_get_shared_key(&server, &attributes, &key) == PSA_SUCCESS);
    TEST_ASSERT(psa_pake_abort(&server) == PSA_SUCCESS);
    TEST_ASSERT(psa_destroy_key(skey) == PSA_SUCCESS);
    TEST_ASSERT(psa_export_key(key, secret2, sizeof secret2, &length2) == PSA_SUCCESS);
    TEST_ASSERT(psa_destroy_key(key) == PSA_SUCCESS);

    ASSERT_COMPARE(secret1, length1, secret2, length2);

    switch (vect) {
    case 1:
        ASSERT_COMPARE(secret1, length1, spake2p_secret1, sizeof spake2p_secret1);
        break;
    case 2:
        ASSERT_COMPARE(secret1, length1, spake2p_secret2, sizeof spake2p_secret2);
        break;
    case 3:
        ASSERT_COMPARE(secret1, length1, spake2p_secret3, sizeof spake2p_secret3);
        break;
    case 4:
        ASSERT_COMPARE(secret1, length1, spake2p_secret4, sizeof spake2p_secret4);
        break;
    case 5:
        ASSERT_COMPARE(secret1, length1, spake2p_secret5, sizeof spake2p_secret5);
        break;
    case 6:
        ASSERT_COMPARE(secret1, length1, spake2p_secret6, sizeof spake2p_secret6);
        break;
    }

    return 1;
exit:
    psa_destroy_key(ckey);
    psa_destroy_key(skey);
    psa_destroy_key(key);
    return 0;
}

static int setup_spake2p_endpoint_err(psa_pake_operation_t *op,
    psa_pake_role_t role, const char *user, const char *peer, psa_key_id_t *key, int n)
{
    uint8_t w0[128];
    psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;
    psa_status_t expected = PSA_SUCCESS;
    psa_pake_cipher_suite_t suite = PSA_PAKE_CIPHER_SUITE_INIT;

    if (n == 1) { // wrong algorithm
        psa_pake_cs_set_algorithm(&suite, PSA_ALG_SHA_256);
        expected = PSA_ERROR_INVALID_ARGUMENT;
    } else {
        psa_pake_cs_set_algorithm(&suite, PSA_ALG_SPAKE2P_HMAC(PSA_ALG_SHA_256));
    }

    if (n == 2) { // incompatible type
        psa_pake_cs_set_primitive(&suite,
            PSA_PAKE_PRIMITIVE(PSA_PAKE_PRIMITIVE_TYPE_DH, PSA_DH_FAMILY_RFC3526, 3072));
        expected = PSA_ERROR_INVALID_ARGUMENT;
    } else if (n == 3) { // incompatible family
        psa_pake_cs_set_primitive(&suite,
            PSA_PAKE_PRIMITIVE(PSA_PAKE_PRIMITIVE_TYPE_ECC, PSA_ECC_FAMILY_SECP_R2, 256));
        expected = PSA_ERROR_INVALID_ARGUMENT;
    } else if (n == 4) { // incompatible size
        psa_pake_cs_set_primitive(&suite,
            PSA_PAKE_PRIMITIVE(PSA_PAKE_PRIMITIVE_TYPE_ECC, PSA_ECC_FAMILY_SECP_R1, 384));
        expected = PSA_ERROR_INVALID_ARGUMENT;
    } else {
        psa_pake_cs_set_primitive(&suite,
            PSA_PAKE_PRIMITIVE(PSA_PAKE_PRIMITIVE_TYPE_ECC, PSA_ECC_FAMILY_SECP_R1, 256));
    }

    if (n == 5) { // incompatible confirmation
        psa_pake_cs_set_key_confirmation(&suite, PSA_PAKE_UNCONFIRMED_KEY);
        expected = PSA_ERROR_INVALID_ARGUMENT;
    }

    if (n == 6) { // incompatible usage
        psa_set_key_usage_flags(&attributes, PSA_KEY_USAGE_EXPORT);
        expected = PSA_ERROR_NOT_PERMITTED;
    } else {
        psa_set_key_usage_flags(&attributes, PSA_KEY_USAGE_DERIVE);
    }

    if (n == 7) { // incompatible algorithm
        psa_set_key_algorithm(&attributes, PSA_ALG_SRP_6(PSA_ALG_SHA_512));
        expected = PSA_ERROR_NOT_PERMITTED;
    } else {
        psa_set_key_algorithm(&attributes, PSA_ALG_SPAKE2P_HMAC(PSA_ALG_SHA_256));
    }

    if (role == PSA_PAKE_ROLE_CLIENT) {
        psa_set_key_type(&attributes, PSA_KEY_TYPE_SPAKE2P_KEY_PAIR(PSA_ECC_FAMILY_SECP_R1));
        if (n == 8) { // wrong w0
            memset(w0, 0xFF, 32);
            memcpy(w0 + 32, spake2p_w01_0 + 32, 32);
            TEST_ASSERT(psa_import_key(&attributes, w0, 64, key) == PSA_ERROR_INVALID_ARGUMENT);
            return 1;
        } else if (n == 9) { // wrong w1
            memcpy(w0, spake2p_w01_0, 32);
            memset(w0 + 32, 0xFF, 32);
            TEST_ASSERT(psa_import_key(&attributes, w0, 64, key) == PSA_ERROR_INVALID_ARGUMENT);
            return 1;
        } else {
            TEST_ASSERT(psa_import_key(&attributes, spake2p_w01_0, sizeof spake2p_w01_0, key) == PSA_SUCCESS);
        }
    } else {
        psa_set_key_type(&attributes, PSA_KEY_TYPE_SPAKE2P_PUBLIC_KEY(PSA_ECC_FAMILY_SECP_R1));
        if (n == 8) { // wrong w0
            memset(w0, 0xFF, 32);
            memcpy(w0 + 32, spake2p_w0L_0 + 32, 65);
            TEST_ASSERT(psa_import_key(&attributes, w0, 97, key) == PSA_ERROR_INVALID_ARGUMENT);
            return 1;
        } else if (n == 9) { // wrong L
            memcpy(w0, spake2p_w0L_0, 32);
            memset(w0, 0, 65);
            TEST_ASSERT(psa_import_key(&attributes, w0, 97, key) == PSA_ERROR_INVALID_ARGUMENT);
            return 1;
        } else {
            TEST_ASSERT(psa_import_key(&attributes, spake2p_w0L_0, sizeof spake2p_w0L_0, key) == PSA_SUCCESS);
        }
    }

    if (n == 10) { // set_role before setup
        TEST_ASSERT(psa_pake_set_role(op, PSA_PAKE_ROLE_CLIENT) == PSA_ERROR_BAD_STATE);
        return 1;
    }

    TEST_ASSERT(psa_pake_setup(op, *key, &suite) == expected);
    if (expected != PSA_SUCCESS) return 1;

    if (n == 11) { // already started
        TEST_ASSERT(psa_pake_setup(op, *key, &suite) == PSA_ERROR_BAD_STATE);
        return 1;
    }

    if (n == 12) { // set_user before set_role
        TEST_ASSERT(psa_pake_set_user(op, (const uint8_t*)user, strlen(user)) == PSA_ERROR_BAD_STATE);
        return 1;
    }

    if (n == 13) { // wrong role
        TEST_ASSERT(psa_pake_set_role(op, PSA_PAKE_ROLE_FIRST) == PSA_ERROR_INVALID_ARGUMENT);
        return 1;
    } else if (n == 14 && role == PSA_PAKE_ROLE_SERVER) { // incompatible role
        TEST_ASSERT(psa_pake_set_role(op, PSA_PAKE_ROLE_CLIENT) == PSA_ERROR_INVALID_ARGUMENT);
        return 1;
    } else {
        TEST_ASSERT(psa_pake_set_role(op, role) == PSA_SUCCESS);
    }

    TEST_ASSERT(psa_pake_set_user(op, (const uint8_t*)user, strlen(user)) == PSA_SUCCESS);
    TEST_ASSERT(psa_pake_set_peer(op, (const uint8_t*)peer, strlen(peer)) == PSA_SUCCESS);
    TEST_ASSERT(psa_pake_set_context(op, (const uint8_t*)spake2p_hmac, strlen(spake2p_hmac)) == PSA_SUCCESS);

    return 1;
exit:
    return 0;
}

static int test_spake2p_err(int n)
{
    psa_pake_operation_t client = PSA_PAKE_OPERATION_INIT;
    psa_pake_operation_t server = PSA_PAKE_OPERATION_INIT;
    psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;
    psa_key_id_t key = 0, ckey = 0, skey = 0;
    uint8_t data[64];
    size_t length;

    if (n <= 14) { // error in client setup
        TEST_ASSERT(setup_spake2p_endpoint_err(&client, PSA_PAKE_ROLE_CLIENT, "client", "server", &ckey, n));
        goto abort;
    } else {
        TEST_ASSERT(setup_spake2p_endpoint_err(&client, PSA_PAKE_ROLE_CLIENT, "client", "server", &ckey, 0));
    }
    if (n > 14 && n <= 28) { // error in server setup
        TEST_ASSERT(setup_spake2p_endpoint_err(&server, PSA_PAKE_ROLE_SERVER, "server", "client", &skey, n - 14));
        goto abort;
    } else {
        TEST_ASSERT(setup_spake2p_endpoint_err(&server, PSA_PAKE_ROLE_SERVER, "server", "client", &skey, 0));
    }

    psa_set_key_type(&attributes, PSA_KEY_TYPE_AES);
    psa_set_key_usage_flags(&attributes, PSA_KEY_USAGE_EXPORT);
    psa_set_key_algorithm(&attributes, PSA_ALG_GCM);

    switch (n) {
    case 29:
        TEST_ASSERT(send_message_err(&server, &client, PSA_PAKE_STEP_KEY_SHARE, 1));
        goto abort;
    case 30:
        TEST_ASSERT(send_message_err(&server, &client, PSA_PAKE_STEP_CONFIRM, 1));
        goto abort;
    case 31:
        TEST_ASSERT(send_message_err(&client, &server, PSA_PAKE_STEP_KEY_SHARE, 0));
        TEST_ASSERT(send_message_err(&server, &client, PSA_PAKE_STEP_CONFIRM, 1));
        goto abort;
    case 32:
        TEST_ASSERT(send_message_err(&client, &server, PSA_PAKE_STEP_KEY_SHARE, 0));
        TEST_ASSERT(send_message_err(&server, &client, PSA_PAKE_STEP_KEY_SHARE, 0));
        TEST_ASSERT(send_message_err(&client, &server, PSA_PAKE_STEP_CONFIRM, 1));
        goto abort;
    case 33: // wrong input size
        TEST_ASSERT(send_message_err(&client, &server, PSA_PAKE_STEP_KEY_SHARE, 2));
        goto abort;
    case 34: // wrong input size
        TEST_ASSERT(send_message_err(&client, &server, PSA_PAKE_STEP_KEY_SHARE, 0));
        TEST_ASSERT(send_message_err(&server, &client, PSA_PAKE_STEP_KEY_SHARE, 2));
        goto abort;
    case 35: // wrong confirm size
        TEST_ASSERT(send_message_err(&client, &server, PSA_PAKE_STEP_KEY_SHARE, 0));
        TEST_ASSERT(send_message_err(&server, &client, PSA_PAKE_STEP_KEY_SHARE, 0));
        TEST_ASSERT(send_message_err(&server, &client, PSA_PAKE_STEP_CONFIRM, 3));
        goto abort;
    case 36: // wrong confirm size
        TEST_ASSERT(send_message_err(&client, &server, PSA_PAKE_STEP_KEY_SHARE, 0));
        TEST_ASSERT(send_message_err(&server, &client, PSA_PAKE_STEP_KEY_SHARE, 0));
        TEST_ASSERT(send_message_err(&server, &client, PSA_PAKE_STEP_CONFIRM, 0));
        TEST_ASSERT(send_message_err(&client, &server, PSA_PAKE_STEP_CONFIRM, 3));
        goto abort;
    case 37: // wrong step
        TEST_ASSERT(psa_pake_input(&server, PSA_PAKE_STEP_ZK_PUBLIC, spake2p_w01_0, sizeof spake2p_w01_0) == PSA_ERROR_INVALID_ARGUMENT);
        goto abort;
    case 38: // wrong step
        TEST_ASSERT(psa_pake_output(&server, PSA_PAKE_STEP_ZK_PROOF, data, sizeof data, &length) == PSA_ERROR_INVALID_ARGUMENT);
        goto abort;
    case 39: // wrong confirm
        TEST_ASSERT(send_message_err(&client, &server, PSA_PAKE_STEP_KEY_SHARE, 0));
        TEST_ASSERT(send_message_err(&server, &client, PSA_PAKE_STEP_KEY_SHARE, 0));
        TEST_ASSERT(send_message_err(&server, &client, PSA_PAKE_STEP_CONFIRM, 4));
        goto abort;
    case 40: // wrong confirm
        TEST_ASSERT(send_message_err(&client, &server, PSA_PAKE_STEP_KEY_SHARE, 0));
        TEST_ASSERT(send_message_err(&server, &client, PSA_PAKE_STEP_KEY_SHARE, 0));
        TEST_ASSERT(send_message_err(&server, &client, PSA_PAKE_STEP_CONFIRM, 0));
        TEST_ASSERT(send_message_err(&client, &server, PSA_PAKE_STEP_CONFIRM, 4));
        goto abort;
    default:
        TEST_ASSERT(send_message_err(&client, &server, PSA_PAKE_STEP_KEY_SHARE, 0));
        TEST_ASSERT(send_message_err(&server, &client, PSA_PAKE_STEP_KEY_SHARE, 0));
        TEST_ASSERT(send_message_err(&server, &client, PSA_PAKE_STEP_CONFIRM, 0));
        TEST_ASSERT(send_message_err(&client, &server, PSA_PAKE_STEP_CONFIRM, 0));
        break;
    }

    switch (n) {
    case 41: // invalid key type
        psa_set_key_type(&attributes, PSA_KEY_TYPE_RSA_PUBLIC_KEY);
        TEST_ASSERT(psa_pake_get_shared_key(&client, &attributes, &key) == PSA_ERROR_INVALID_ARGUMENT);
        TEST_ASSERT(key == 0);
        break;
    case 42: // invalid key type
        psa_set_key_type(&attributes, PSA_KEY_TYPE_RSA_PUBLIC_KEY);
        TEST_ASSERT(psa_pake_get_shared_key(&server, &attributes, &key) == PSA_ERROR_INVALID_ARGUMENT);
        TEST_ASSERT(key == 0);
        break;
    case 43: // key size > 0
        psa_set_key_bits(&attributes, 256);
        TEST_ASSERT(psa_pake_get_shared_key(&client, &attributes, &key) == PSA_ERROR_INVALID_ARGUMENT);
        TEST_ASSERT(key == 0);
        break;
    case 44: // key size > 0
        psa_set_key_bits(&attributes, 256);
        TEST_ASSERT(psa_pake_get_shared_key(&server, &attributes, &key) == PSA_ERROR_INVALID_ARGUMENT);
        TEST_ASSERT(key == 0);
        break;
    }

abort:
    TEST_ASSERT(psa_pake_abort(&client) == PSA_SUCCESS);
    TEST_ASSERT(psa_pake_abort(&server) == PSA_SUCCESS);
    TEST_ASSERT(psa_destroy_key(ckey) == PSA_SUCCESS);
    TEST_ASSERT(psa_destroy_key(skey) == PSA_SUCCESS);
    TEST_ASSERT(psa_destroy_key(key) == PSA_SUCCESS);
    return 1;
exit:
    psa_destroy_key(ckey);
    psa_destroy_key(skey);
    psa_destroy_key(key);
    return 0;
}
#endif /* PSA_WANT_ALG_SPAKE2P_HMAC || PSA_WANT_ALG_SPAKE2P_CMAC || PSA_WANT_ALG_SPAKE2P_MATTER */


/*
 * SRP-6-3072-SHA512 Tests
 */
#ifdef PSA_WANT_ALG_SRP_6

// Salt (s)
static const uint8_t srp_salt[16] = {
    0xBE, 0xB2, 0x53, 0x79, 0xD1, 0xA8, 0x58, 0x1E, 0xB5, 0xA7, 0x27, 0x67, 0x3A, 0x24, 0x41, 0xEE};
// Verifier (v)
static const uint8_t srp_verifier256[384] = {
    0xeb, 0xe5, 0x2c, 0x3c, 0xac, 0x71, 0x2e, 0x0b, 0xe1, 0xba, 0x08, 0xd4, 0xda, 0xe9, 0xd3, 0x8c,
    0x96, 0x0c, 0x3f, 0x09, 0x2e, 0xd0, 0xee, 0x37, 0x5b, 0x12, 0x17, 0x3b, 0x1c, 0xbe, 0x8c, 0x2d,
    0x33, 0x80, 0xeb, 0x4b, 0x38, 0xf0, 0xc5, 0x29, 0xb3, 0xc5, 0xb2, 0x07, 0x22, 0x6c, 0x2b, 0x4c,
    0x77, 0x41, 0x24, 0x9d, 0x96, 0x5a, 0x14, 0x37, 0xab, 0xe4, 0x80, 0xb1, 0xbb, 0x33, 0x15, 0x84,
    0x67, 0x3e, 0x6e, 0x0b, 0x83, 0xda, 0xaf, 0x3b, 0x2f, 0xa3, 0x70, 0xf1, 0x0d, 0xc3, 0xb8, 0xd5,
    0x99, 0xb4, 0x19, 0x13, 0x3b, 0xce, 0x88, 0xa4, 0x2c, 0xc2, 0x67, 0x55, 0x43, 0x56, 0x3f, 0xaa,
    0x99, 0x9d, 0x93, 0x9e, 0x90, 0xc1, 0xc8, 0xe7, 0x02, 0x4b, 0x90, 0x68, 0x11, 0xfa, 0xa9, 0x03,
    0x45, 0x12, 0x89, 0x0e, 0x21, 0xb0, 0x71, 0x35, 0xa1, 0xad, 0x30, 0x63, 0x80, 0xaa, 0x5c, 0x94,
    0x62, 0xa2, 0x1e, 0x0d, 0x63, 0x5a, 0x20, 0xb0, 0x76, 0x09, 0x11, 0x45, 0xf8, 0xf1, 0xc0, 0x16,
    0x6e, 0xfd, 0xe2, 0x24, 0xaf, 0x4d, 0x0c, 0xe5, 0xff, 0xb9, 0x85, 0x7d, 0xda, 0xc9, 0x38, 0x75,
    0x75, 0x8e, 0x4f, 0x19, 0x11, 0x31, 0xf5, 0x83, 0x7e, 0x3d, 0xd5, 0xbb, 0xf8, 0xc3, 0x24, 0x28,
    0x79, 0xd0, 0xbd, 0x7b, 0xc9, 0xf7, 0x5a, 0x0e, 0x49, 0x28, 0x04, 0xc6, 0x9b, 0x4f, 0xba, 0xc8,
    0xec, 0x02, 0x84, 0x47, 0x29, 0xa5, 0x65, 0xb8, 0x59, 0xf1, 0x76, 0xe8, 0xff, 0xf9, 0x34, 0x8d,
    0xeb, 0x0f, 0xf1, 0xee, 0x42, 0x9c, 0x2f, 0xff, 0xc1, 0x4a, 0xf6, 0x76, 0x4d, 0xc0, 0xc4, 0x57,
    0x8d, 0x41, 0xcd, 0x39, 0x07, 0xe2, 0x1c, 0xde, 0x6d, 0xb9, 0x4a, 0xa6, 0x4f, 0xb7, 0x91, 0x13,
    0xdd, 0xe0, 0x81, 0x44, 0xc7, 0x7b, 0x40, 0x4d, 0x15, 0xad, 0xdb, 0x04, 0xd0, 0x01, 0x57, 0x9d,
    0x19, 0xbf, 0xa1, 0x68, 0x30, 0xda, 0x36, 0x6a, 0x74, 0x76, 0xa2, 0x9a, 0xad, 0xcd, 0xef, 0x47,
    0x42, 0x3c, 0xa6, 0x52, 0xf7, 0x73, 0xeb, 0x04, 0x57, 0xc0, 0x81, 0x66, 0x83, 0x91, 0x3b, 0x63,
    0xf1, 0x5a, 0x4b, 0x17, 0xd2, 0xbb, 0xf3, 0xda, 0x2d, 0xbf, 0x97, 0x6f, 0xe5, 0xbf, 0x66, 0xdb,
    0x1c, 0xd5, 0xa0, 0x2f, 0x0f, 0x47, 0x65, 0xbc, 0x63, 0x6e, 0xbe, 0x15, 0x1d, 0x95, 0x03, 0x1c,
    0x6a, 0x3f, 0xc2, 0x85, 0xc3, 0xdf, 0x13, 0x0b, 0xe7, 0xcc, 0x72, 0x81, 0xf3, 0x66, 0x4f, 0xec,
    0xac, 0xb6, 0x6b, 0xe8, 0x05, 0x71, 0x55, 0x1d, 0x15, 0xa7, 0x1b, 0x05, 0x99, 0xef, 0x76, 0xb8,
    0x79, 0x3f, 0x1e, 0x75, 0xeb, 0x61, 0x1f, 0x33, 0xdd, 0x33, 0xa0, 0x46, 0xd9, 0xc4, 0x76, 0xdf,
    0x84, 0xc7, 0x6c, 0x5f, 0xa8, 0x5b, 0x66, 0x27, 0xe6, 0xc3, 0x87, 0x56, 0xc8, 0x4b, 0x27, 0x1a};
static const uint8_t srp_verifier512[384] = {
    0x9b, 0x5e, 0x06, 0x17, 0x01, 0xea, 0x7a, 0xeb, 0x39, 0xcf, 0x6e, 0x35, 0x19, 0x65, 0x5a, 0x85,
    0x3c, 0xf9, 0x4c, 0x75, 0xca, 0xf2, 0x55, 0x5e, 0xf1, 0xfa, 0xf7, 0x59, 0xbb, 0x79, 0xcb, 0x47,
    0x70, 0x14, 0xe0, 0x4a, 0x88, 0xd6, 0x8f, 0xfc, 0x05, 0x32, 0x38, 0x91, 0xd4, 0xc2, 0x05, 0xb8,
    0xde, 0x81, 0xc2, 0xf2, 0x03, 0xd8, 0xfa, 0xd1, 0xb2, 0x4d, 0x2c, 0x10, 0x97, 0x37, 0xf1, 0xbe,
    0xbb, 0xd7, 0x1f, 0x91, 0x24, 0x47, 0xc4, 0xa0, 0x3c, 0x26, 0xb9, 0xfa, 0xd8, 0xed, 0xb3, 0xe7,
    0x80, 0x77, 0x8e, 0x30, 0x25, 0x29, 0xed, 0x1e, 0xe1, 0x38, 0xcc, 0xfc, 0x36, 0xd4, 0xba, 0x31,
    0x3c, 0xc4, 0x8b, 0x14, 0xea, 0x8c, 0x22, 0xa0, 0x18, 0x6b, 0x22, 0x2e, 0x65, 0x5f, 0x2d, 0xf5,
    0x60, 0x3f, 0xd7, 0x5d, 0xf7, 0x6b, 0x3b, 0x08, 0xff, 0x89, 0x50, 0x06, 0x9a, 0xdd, 0x03, 0xa7,
    0x54, 0xee, 0x4a, 0xe8, 0x85, 0x87, 0xcc, 0xe1, 0xbf, 0xde, 0x36, 0x79, 0x4d, 0xba, 0xe4, 0x59,
    0x2b, 0x7b, 0x90, 0x4f, 0x44, 0x2b, 0x04, 0x1c, 0xb1, 0x7a, 0xeb, 0xad, 0x1e, 0x3a, 0xeb, 0xe3,
    0xcb, 0xe9, 0x9d, 0xe6, 0x5f, 0x4b, 0xb1, 0xfa, 0x00, 0xb0, 0xe7, 0xaf, 0x06, 0x86, 0x3d, 0xb5,
    0x3b, 0x02, 0x25, 0x4e, 0xc6, 0x6e, 0x78, 0x1e, 0x3b, 0x62, 0xa8, 0x21, 0x2c, 0x86, 0xbe, 0xb0,
    0xd5, 0x0b, 0x5b, 0xa6, 0xd0, 0xb4, 0x78, 0xd8, 0xc4, 0xe9, 0xbb, 0xce, 0xc2, 0x17, 0x65, 0x32,
    0x6f, 0xbd, 0x14, 0x05, 0x8d, 0x2b, 0xbd, 0xe2, 0xc3, 0x30, 0x45, 0xf0, 0x38, 0x73, 0xe5, 0x39,
    0x48, 0xd7, 0x8b, 0x79, 0x4f, 0x07, 0x90, 0xe4, 0x8c, 0x36, 0xae, 0xd6, 0xe8, 0x80, 0xf5, 0x57,
    0x42, 0x7b, 0x2f, 0xc0, 0x6d, 0xb5, 0xe1, 0xe2, 0xe1, 0xd7, 0xe6, 0x61, 0xac, 0x48, 0x2d, 0x18,
    0xe5, 0x28, 0xd7, 0x29, 0x5e, 0xf7, 0x43, 0x72, 0x95, 0xff, 0x1a, 0x72, 0xd4, 0x02, 0x77, 0x17,
    0x13, 0xf1, 0x68, 0x76, 0xdd, 0x05, 0x0a, 0xe5, 0xb7, 0xad, 0x53, 0xcc, 0xb9, 0x08, 0x55, 0xc9,
    0x39, 0x56, 0x64, 0x83, 0x58, 0xad, 0xfd, 0x96, 0x64, 0x22, 0xf5, 0x24, 0x98, 0x73, 0x2d, 0x68,
    0xd1, 0xd7, 0xfb, 0xef, 0x10, 0xd7, 0x80, 0x34, 0xab, 0x8d, 0xcb, 0x6f, 0x0f, 0xcf, 0x88, 0x5c,
    0xc2, 0xb2, 0xea, 0x2c, 0x3e, 0x6a, 0xc8, 0x66, 0x09, 0xea, 0x05, 0x8a, 0x9d, 0xa8, 0xcc, 0x63,
    0x53, 0x1d, 0xc9, 0x15, 0x41, 0x4d, 0xf5, 0x68, 0xb0, 0x94, 0x82, 0xdd, 0xac, 0x19, 0x54, 0xde,
    0xc7, 0xeb, 0x71, 0x4f, 0x6f, 0xf7, 0xd4, 0x4c, 0xd5, 0xb8, 0x6f, 0x6b, 0xd1, 0x15, 0x81, 0x09,
    0x30, 0x63, 0x7c, 0x01, 0xd0, 0xf6, 0x01, 0x3b, 0xc9, 0x74, 0x0f, 0xa2, 0xc6, 0x33, 0xba, 0x89};

static const uint8_t srp_secret256[32] = {
    0x46, 0x8f, 0x4b, 0xb3, 0x04, 0xeb, 0x97, 0xc9, 0xc5, 0x14, 0x1b, 0xa8, 0x1e, 0x44, 0x36, 0x9a,
    0x92, 0x9c, 0x3a, 0xa7, 0xd6, 0x95, 0x07, 0x8c, 0xc7, 0xed, 0x77, 0x61, 0x91, 0x5d, 0x03, 0x96};
static const uint8_t srp_secret512[64] = {
    0x5c, 0xbc, 0x21, 0x9d, 0xb0, 0x52, 0x13, 0x8e, 0xe1, 0x14, 0x8c, 0x71, 0xcd, 0x44, 0x98, 0x96,
    0x3d, 0x68, 0x25, 0x49, 0xce, 0x91, 0xca, 0x24, 0xf0, 0x98, 0x46, 0x8f, 0x06, 0x01, 0x5b, 0xeb,
    0x6a, 0xf2, 0x45, 0xc2, 0x09, 0x3f, 0x98, 0xc3, 0x65, 0x1b, 0xca, 0x83, 0xab, 0x8c, 0xab, 0x2b,
    0x58, 0x0b, 0xbf, 0x02, 0x18, 0x4f, 0xef, 0xdf, 0x26, 0x14, 0x2f, 0x73, 0xdf, 0x95, 0xac, 0x50};

static const uint8_t srp_random_cs[2 * 32] = { // client key : server key
    0x60, 0x97, 0x55, 0x27, 0x03, 0x5c, 0xf2, 0xad, 0x19, 0x89, 0x80, 0x6f, 0x04, 0x07, 0x21, 0x0b,
    0xc8, 0x1e, 0xdc, 0x04, 0xe2, 0x76, 0x2a, 0x56, 0xaf, 0xd5, 0x29, 0xdd, 0xda, 0x2d, 0x43, 0x93,
    0xe4, 0x87, 0xcb, 0x59, 0xd3, 0x1a, 0xc5, 0x50, 0x47, 0x1e, 0x81, 0xf0, 0x0f, 0x69, 0x28, 0xe0,
    0x1d, 0xda, 0x08, 0xe9, 0x74, 0xa0, 0x04, 0xf4, 0x9e, 0x61, 0xf5, 0xd1, 0x05, 0x28, 0x4d, 0x20};
static const uint8_t srp_random_sc[2 * 32] = { // server key : client key
    0xe4, 0x87, 0xcb, 0x59, 0xd3, 0x1a, 0xc5, 0x50, 0x47, 0x1e, 0x81, 0xf0, 0x0f, 0x69, 0x28, 0xe0,
    0x1d, 0xda, 0x08, 0xe9, 0x74, 0xa0, 0x04, 0xf4, 0x9e, 0x61, 0xf5, 0xd1, 0x05, 0x28, 0x4d, 0x20,
    0x60, 0x97, 0x55, 0x27, 0x03, 0x5c, 0xf2, 0xad, 0x19, 0x89, 0x80, 0x6f, 0x04, 0x07, 0x21, 0x0b,
    0xc8, 0x1e, 0xdc, 0x04, 0xe2, 0x76, 0x2a, 0x56, 0xaf, 0xd5, 0x29, 0xdd, 0xda, 0x2d, 0x43, 0x93};

static int setup_srp_endpoint(psa_pake_operation_t *op,
    psa_pake_role_t role, const char *user,
    psa_algorithm_t alg, psa_key_id_t key)
{
    psa_pake_cipher_suite_t suite = PSA_PAKE_CIPHER_SUITE_INIT;
    psa_pake_primitive_t srp_primitive =
        PSA_PAKE_PRIMITIVE(PSA_PAKE_PRIMITIVE_TYPE_DH, PSA_DH_FAMILY_RFC3526, 3072);

    psa_pake_cs_set_algorithm(&suite, alg);
    psa_pake_cs_set_primitive(&suite, srp_primitive);

    TEST_ASSERT(psa_pake_setup(op, key, &suite) == PSA_SUCCESS);
    TEST_ASSERT(psa_pake_set_role(op, role) == PSA_SUCCESS);
    TEST_ASSERT(psa_pake_set_user(op, (const uint8_t*)user, strlen(user)) == PSA_SUCCESS);

    return 1;
exit:
    return 0;
}

static int test_srp(psa_algorithm_t hash_alg, int n, const char *user, const char *pw, const uint8_t *v)
{
    psa_pake_operation_t client = PSA_PAKE_OPERATION_INIT;
    psa_pake_operation_t server = PSA_PAKE_OPERATION_INIT;
    psa_key_derivation_operation_t kdf = PSA_KEY_DERIVATION_OPERATION_INIT;
    psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;
    psa_algorithm_t alg = PSA_ALG_SRP_6(hash_alg);
    psa_key_id_t key = 0, skey = 0, ckey = 0;
    uint8_t secret1[64], secret2[64], pub_key[384];
    size_t pub_len, length1, length2;
    size_t share_size, conf_size;

    if (n == 2 || n == 5) {
        oberon_test_drbg_setup(srp_random_sc, sizeof srp_random_sc);
    } else {
        oberon_test_drbg_setup(srp_random_cs, sizeof srp_random_cs);
    }

    psa_set_key_usage_flags(&attributes, PSA_KEY_USAGE_DERIVE);
    psa_set_key_algorithm(&attributes, PSA_ALG_SRP_PASSWORD_HASH(hash_alg));
    psa_set_key_bits(&attributes, PSA_BYTES_TO_BITS(strlen(pw)));
    psa_set_key_type(&attributes, PSA_KEY_TYPE_PASSWORD);
    TEST_ASSERT(psa_import_key(&attributes, (const uint8_t*)pw, strlen(pw), &key) == PSA_SUCCESS);

    TEST_ASSERT(psa_key_derivation_setup(&kdf, PSA_ALG_SRP_PASSWORD_HASH(hash_alg)) == PSA_SUCCESS);
    TEST_ASSERT(psa_key_derivation_input_bytes(&kdf, PSA_KEY_DERIVATION_INPUT_INFO, (const uint8_t*)user, strlen(user)) == PSA_SUCCESS);
    TEST_ASSERT(psa_key_derivation_input_key(&kdf, PSA_KEY_DERIVATION_INPUT_PASSWORD, key) == PSA_SUCCESS);
    TEST_ASSERT(psa_key_derivation_input_bytes(&kdf, PSA_KEY_DERIVATION_INPUT_SALT, srp_salt, sizeof srp_salt) == PSA_SUCCESS);
    TEST_ASSERT(psa_destroy_key(key) == PSA_SUCCESS);
    psa_set_key_usage_flags(&attributes, PSA_KEY_USAGE_DERIVE);
    psa_set_key_algorithm(&attributes, alg);
    psa_set_key_bits(&attributes, 3072);
    psa_set_key_type(&attributes, PSA_KEY_TYPE_SRP_KEY_PAIR(PSA_DH_FAMILY_RFC3526));
    TEST_ASSERT(psa_key_derivation_output_key(&attributes, &kdf, &ckey) == PSA_SUCCESS);

    TEST_ASSERT(psa_export_public_key(ckey, pub_key, sizeof pub_key, &pub_len) == PSA_SUCCESS);
    ASSERT_COMPARE(pub_key, pub_len, v, pub_len);
    psa_set_key_type(&attributes, PSA_KEY_TYPE_SRP_PUBLIC_KEY(PSA_DH_FAMILY_RFC3526));
    psa_set_key_bits(&attributes, 0);
    TEST_ASSERT(psa_import_key(&attributes, pub_key, pub_len, &skey) == PSA_SUCCESS);

    TEST_ASSERT(setup_srp_endpoint(&client, PSA_PAKE_ROLE_CLIENT, user, alg, ckey));
    TEST_ASSERT(setup_srp_endpoint(&server, PSA_PAKE_ROLE_SERVER, user, alg, skey));

    share_size = PSA_PAKE_OUTPUT_SIZE(alg,
        PSA_PAKE_PRIMITIVE(PSA_PAKE_PRIMITIVE_TYPE_DH, PSA_DH_FAMILY_RFC3526, 3072),
        PSA_PAKE_STEP_KEY_SHARE);
    conf_size = PSA_PAKE_OUTPUT_SIZE(alg,
        PSA_PAKE_PRIMITIVE(PSA_PAKE_PRIMITIVE_TYPE_DH, PSA_DH_FAMILY_RFC3526, 3072),
        PSA_PAKE_STEP_CONFIRM);

    switch (n) {
    case 1:
        TEST_ASSERT(psa_pake_input(&client, PSA_PAKE_STEP_SALT, srp_salt, sizeof srp_salt) == PSA_SUCCESS);
        TEST_ASSERT(psa_pake_input(&server, PSA_PAKE_STEP_SALT, srp_salt, sizeof srp_salt) == PSA_SUCCESS);
        TEST_ASSERT(send_message(&client, &server, PSA_PAKE_STEP_KEY_SHARE, NULL, share_size)); // client key
        TEST_ASSERT(send_message(&server, &client, PSA_PAKE_STEP_KEY_SHARE, NULL, share_size)); // server key
        break;
    case 2:
        TEST_ASSERT(psa_pake_input(&client, PSA_PAKE_STEP_SALT, srp_salt, sizeof srp_salt) == PSA_SUCCESS);
        TEST_ASSERT(psa_pake_input(&server, PSA_PAKE_STEP_SALT, srp_salt, sizeof srp_salt) == PSA_SUCCESS);
        TEST_ASSERT(send_message(&server, &client, PSA_PAKE_STEP_KEY_SHARE, NULL, share_size)); // server key
        TEST_ASSERT(send_message(&client, &server, PSA_PAKE_STEP_KEY_SHARE, NULL, share_size)); // client key
        break;
    case 3:
        TEST_ASSERT(send_message(&client, &server, PSA_PAKE_STEP_KEY_SHARE, NULL, share_size)); // client key
        TEST_ASSERT(psa_pake_input(&client, PSA_PAKE_STEP_SALT, srp_salt, sizeof srp_salt) == PSA_SUCCESS);
        TEST_ASSERT(psa_pake_input(&server, PSA_PAKE_STEP_SALT, srp_salt, sizeof srp_salt) == PSA_SUCCESS);
        TEST_ASSERT(send_message(&server, &client, PSA_PAKE_STEP_KEY_SHARE, NULL, share_size)); // server key
        break;
    case 4:
        TEST_ASSERT(send_message(&client, &server, PSA_PAKE_STEP_KEY_SHARE, NULL, share_size)); // client key
        TEST_ASSERT(send_message(&server, &client, PSA_PAKE_STEP_KEY_SHARE, NULL, share_size)); // server key
        TEST_ASSERT(psa_pake_input(&client, PSA_PAKE_STEP_SALT, srp_salt, sizeof srp_salt) == PSA_SUCCESS);
        TEST_ASSERT(psa_pake_input(&server, PSA_PAKE_STEP_SALT, srp_salt, sizeof srp_salt) == PSA_SUCCESS);
        break;
    case 5:
        TEST_ASSERT(send_message(&server, &client, PSA_PAKE_STEP_KEY_SHARE, NULL, share_size)); // server key
        TEST_ASSERT(psa_pake_input(&client, PSA_PAKE_STEP_SALT, srp_salt, sizeof srp_salt) == PSA_SUCCESS);
        TEST_ASSERT(psa_pake_input(&server, PSA_PAKE_STEP_SALT, srp_salt, sizeof srp_salt) == PSA_SUCCESS);
        TEST_ASSERT(send_message(&client, &server, PSA_PAKE_STEP_KEY_SHARE, NULL, share_size)); // client key
        break;
    case 6:
        TEST_ASSERT(send_message(&client, &server, PSA_PAKE_STEP_KEY_SHARE, NULL, share_size)); // client key
        TEST_ASSERT(send_message(&server, &client, PSA_PAKE_STEP_KEY_SHARE, NULL, share_size)); // server key
        TEST_ASSERT(psa_pake_input(&server, PSA_PAKE_STEP_SALT, srp_salt, sizeof srp_salt) == PSA_SUCCESS);
        TEST_ASSERT(psa_pake_input(&client, PSA_PAKE_STEP_SALT, srp_salt, sizeof srp_salt) == PSA_SUCCESS);
        break;
    }

    TEST_ASSERT(send_message(&client, &server, PSA_PAKE_STEP_CONFIRM, NULL, conf_size)); // client proof
    TEST_ASSERT(send_message(&server, &client, PSA_PAKE_STEP_CONFIRM, NULL, conf_size)); // server proof

    psa_set_key_type(&attributes, PSA_KEY_TYPE_DERIVE);
    psa_set_key_usage_flags(&attributes, PSA_KEY_USAGE_EXPORT);
    psa_set_key_algorithm(&attributes, PSA_ALG_HKDF(hash_alg));

    // get client secret
    TEST_ASSERT(psa_pake_get_shared_key(&client, &attributes, &key) == PSA_SUCCESS);
    TEST_ASSERT(psa_pake_abort(&client) == PSA_SUCCESS);
    TEST_ASSERT(psa_destroy_key(ckey) == PSA_SUCCESS);
    TEST_ASSERT(psa_export_key(key, secret1, sizeof secret1, &length1) == PSA_SUCCESS);
    TEST_ASSERT(psa_destroy_key(key) == PSA_SUCCESS);

    // get server secret
    TEST_ASSERT(psa_pake_get_shared_key(&server, &attributes, &key) == PSA_SUCCESS);
    TEST_ASSERT(psa_pake_abort(&server) == PSA_SUCCESS);
    TEST_ASSERT(psa_destroy_key(skey) == PSA_SUCCESS);
    TEST_ASSERT(psa_export_key(key, secret2, sizeof secret2, &length2) == PSA_SUCCESS);
    TEST_ASSERT(psa_destroy_key(key) == PSA_SUCCESS);

    ASSERT_COMPARE(secret1, length1, secret2, length2);

    if (hash_alg == PSA_ALG_SHA_256) {
        ASSERT_COMPARE(secret1, length1, srp_secret256, sizeof srp_secret256);
    } else {
        ASSERT_COMPARE(secret1, length1, srp_secret512, sizeof srp_secret512);
    }

    return 1;
exit:
    psa_destroy_key(ckey);
    psa_destroy_key(skey);
    psa_destroy_key(key);
    return 0;
}

static int setup_srp_endpoint_err(psa_pake_operation_t *op,
    psa_pake_role_t role, psa_key_id_t *key, int n)
{
    uint8_t hash[64];
    uint8_t verifier[384];
    psa_key_derivation_operation_t kdf = PSA_KEY_DERIVATION_OPERATION_INIT;
    size_t hash_len = PSA_HASH_LENGTH(PSA_ALG_SHA_256);
    psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;
    psa_status_t expected = PSA_SUCCESS;
    psa_pake_cipher_suite_t suite = PSA_PAKE_CIPHER_SUITE_INIT;

    if (n == 1) { // wrong algorithm
        psa_pake_cs_set_algorithm(&suite, PSA_ALG_SHA_256);
        expected = PSA_ERROR_INVALID_ARGUMENT;
    } else {
        psa_pake_cs_set_algorithm(&suite, PSA_ALG_SRP_6(PSA_ALG_SHA_256));
    }

    if (n == 2) { // incompatible type
        psa_pake_cs_set_primitive(&suite,
            PSA_PAKE_PRIMITIVE(PSA_PAKE_PRIMITIVE_TYPE_ECC, PSA_ECC_FAMILY_SECP_R1, 256));
        expected = PSA_ERROR_INVALID_ARGUMENT;
    } else if (n == 3) { // incompatible family
        psa_pake_cs_set_primitive(&suite,
            PSA_PAKE_PRIMITIVE(PSA_PAKE_PRIMITIVE_TYPE_DH, PSA_DH_FAMILY_RFC7919, 3072));
        expected = PSA_ERROR_INVALID_ARGUMENT;
    } else if (n == 4) { // incompatible size
        psa_pake_cs_set_primitive(&suite,
            PSA_PAKE_PRIMITIVE(PSA_PAKE_PRIMITIVE_TYPE_DH, PSA_DH_FAMILY_RFC3526, 4096));
        expected = PSA_ERROR_INVALID_ARGUMENT;
    } else {
        psa_pake_cs_set_primitive(&suite,
            PSA_PAKE_PRIMITIVE(PSA_PAKE_PRIMITIVE_TYPE_DH, PSA_DH_FAMILY_RFC3526, 3072));
    }

    if (n == 5) { // incompatible confirmation
        psa_pake_cs_set_key_confirmation(&suite, PSA_PAKE_UNCONFIRMED_KEY);
        expected = PSA_ERROR_INVALID_ARGUMENT;
    }

    if (n == 6) { // incompatible usage
        psa_set_key_usage_flags(&attributes, PSA_KEY_USAGE_EXPORT);
        expected = PSA_ERROR_NOT_PERMITTED;
    } else {
        psa_set_key_usage_flags(&attributes, PSA_KEY_USAGE_DERIVE);
    }

    if (n == 7) { // incompatible algorithm
        psa_set_key_algorithm(&attributes, PSA_ALG_SRP_6(PSA_ALG_SHA_512));
        expected = PSA_ERROR_NOT_PERMITTED;
    } else {
        psa_set_key_algorithm(&attributes, PSA_ALG_SRP_6(PSA_ALG_SHA_256));
    }

    psa_set_key_bits(&attributes, 3072);

    if (role == PSA_PAKE_ROLE_CLIENT) {
        TEST_ASSERT(psa_key_derivation_setup(&kdf, PSA_ALG_SRP_PASSWORD_HASH(PSA_ALG_SHA_256)) == PSA_SUCCESS);
        TEST_ASSERT(psa_key_derivation_input_bytes(&kdf, PSA_KEY_DERIVATION_INPUT_INFO, (const uint8_t*)"alice", 5) == PSA_SUCCESS);
        TEST_ASSERT(psa_key_derivation_input_bytes(&kdf, PSA_KEY_DERIVATION_INPUT_PASSWORD, (const uint8_t*)"password123", 11) == PSA_SUCCESS);
        TEST_ASSERT(psa_key_derivation_input_bytes(&kdf, PSA_KEY_DERIVATION_INPUT_SALT, srp_salt, sizeof srp_salt) == PSA_SUCCESS);
        TEST_ASSERT(psa_key_derivation_output_bytes(&kdf, hash, hash_len) == PSA_SUCCESS);
        TEST_ASSERT(psa_key_derivation_abort(&kdf) == PSA_SUCCESS);
        psa_set_key_type(&attributes, PSA_KEY_TYPE_SRP_KEY_PAIR(PSA_DH_FAMILY_RFC3526));
        if (n == 8) { // wrong key data
            memset(hash, 0, hash_len);
            TEST_ASSERT(psa_import_key(&attributes, hash, hash_len, key) == PSA_ERROR_INVALID_ARGUMENT);
            return 1;
        } else {
            TEST_ASSERT(psa_import_key(&attributes, hash, hash_len, key) == PSA_SUCCESS);
        }
    } else {
        psa_set_key_type(&attributes, PSA_KEY_TYPE_SRP_PUBLIC_KEY(PSA_DH_FAMILY_RFC3526));
        if (n == 8) { // wrong key data
            memset(verifier, 0xFF, sizeof verifier);
            TEST_ASSERT(psa_import_key(&attributes, verifier, sizeof verifier, key) == PSA_ERROR_INVALID_ARGUMENT);
            return 1;
        } else {
            TEST_ASSERT(psa_import_key(&attributes, srp_verifier256, sizeof srp_verifier256, key) == PSA_SUCCESS);
        }
    }

    TEST_ASSERT(psa_pake_setup(op, *key, &suite) == expected);
    if (expected != PSA_SUCCESS) return 1;

    if (n == 9) { // already started
        TEST_ASSERT(psa_pake_setup(op, *key, &suite) == PSA_ERROR_BAD_STATE);
        return 1;
    }

    if (n == 10) { // set_user before set_role
        TEST_ASSERT(psa_pake_set_user(op, (const uint8_t*)"alice", 5) == PSA_ERROR_BAD_STATE);
        return 1;
    }

    if (n == 11) { // wrong role
        TEST_ASSERT(psa_pake_set_role(op, PSA_PAKE_ROLE_FIRST) == PSA_ERROR_INVALID_ARGUMENT);
        return 1;
    } else if (n == 12 && role == PSA_PAKE_ROLE_SERVER) { // incompatible role
        TEST_ASSERT(psa_pake_set_role(op, PSA_PAKE_ROLE_CLIENT) == PSA_ERROR_INVALID_ARGUMENT);
        return 1;
    } else {
        TEST_ASSERT(psa_pake_set_role(op, role) == PSA_SUCCESS);
    }

    if (n == 13) { // wrong user
        TEST_ASSERT(psa_pake_set_user(op, (const uint8_t*)"", 0) == PSA_ERROR_INVALID_ARGUMENT);
        return 1;
    } else {
        TEST_ASSERT(psa_pake_set_user(op, (const uint8_t*)"alice", 5) == PSA_SUCCESS);
    }

    if (n == 14) { // no peer id allowed
        TEST_ASSERT(psa_pake_set_peer(op, (const uint8_t*)"bob", 3) == PSA_ERROR_BAD_STATE);
        return 1;
    }

    return 1;
exit:
    return 0;
}

static int test_srp_err(int n)
{
    psa_pake_operation_t client = PSA_PAKE_OPERATION_INIT;
    psa_pake_operation_t server = PSA_PAKE_OPERATION_INIT;
    psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;
    psa_key_id_t key = 0, skey = 0, ckey = 0;
    uint8_t salt[32];
    size_t length;

    if (n <= 14) { // error in client setup
        TEST_ASSERT(setup_srp_endpoint_err(&client, PSA_PAKE_ROLE_CLIENT, &ckey, n));
        goto abort;
    } else {
        TEST_ASSERT(setup_srp_endpoint_err(&client, PSA_PAKE_ROLE_CLIENT, &ckey, 0));
    }
    if (n > 14 && n <= 28) { // error in server setup
        TEST_ASSERT(setup_srp_endpoint_err(&server, PSA_PAKE_ROLE_SERVER, &skey, n - 14));
        goto abort;
    } else {
        TEST_ASSERT(setup_srp_endpoint_err(&server, PSA_PAKE_ROLE_SERVER, &skey, 0));
    }

    psa_set_key_type(&attributes, PSA_KEY_TYPE_DERIVE);
    psa_set_key_usage_flags(&attributes, PSA_KEY_USAGE_EXPORT);
    psa_set_key_algorithm(&attributes, PSA_ALG_HKDF(PSA_ALG_SHA_256));

    switch (n) {
    case 29:
        TEST_ASSERT(send_message_err(&client, &server, PSA_PAKE_STEP_CONFIRM, 1));
        goto abort;
    case 30:
        TEST_ASSERT(send_message_err(&client, &server, PSA_PAKE_STEP_KEY_SHARE, 0));
        TEST_ASSERT(send_message_err(&server, &client, PSA_PAKE_STEP_KEY_SHARE, 0));
        TEST_ASSERT(send_message_err(&client, &server, PSA_PAKE_STEP_CONFIRM, 1));
        goto abort;
    case 31:
        TEST_ASSERT(psa_pake_input(&server, PSA_PAKE_STEP_SALT, srp_salt, sizeof srp_salt) == PSA_SUCCESS);
        TEST_ASSERT(psa_pake_input(&client, PSA_PAKE_STEP_SALT, srp_salt, sizeof srp_salt) == PSA_SUCCESS);
        TEST_ASSERT(send_message_err(&server, &client, PSA_PAKE_STEP_KEY_SHARE, 0));
        TEST_ASSERT(send_message_err(&client, &server, PSA_PAKE_STEP_CONFIRM, 1));
        goto abort;
    case 32:
        TEST_ASSERT(psa_pake_input(&server, PSA_PAKE_STEP_SALT, srp_salt, sizeof srp_salt) == PSA_SUCCESS);
        TEST_ASSERT(psa_pake_input(&client, PSA_PAKE_STEP_SALT, srp_salt, sizeof srp_salt) == PSA_SUCCESS);
        TEST_ASSERT(send_message_err(&client, &server, PSA_PAKE_STEP_KEY_SHARE, 0));
        TEST_ASSERT(send_message_err(&client, &server, PSA_PAKE_STEP_CONFIRM, 1));
        goto abort;
    case 33:
        TEST_ASSERT(send_message_err(&client, &server, PSA_PAKE_STEP_KEY_SHARE, 2));
        goto abort;
    case 34:
        TEST_ASSERT(send_message_err(&client, &server, PSA_PAKE_STEP_KEY_SHARE, 0));
        TEST_ASSERT(send_message_err(&server, &client, PSA_PAKE_STEP_KEY_SHARE, 2));
        goto abort;
    case 35:
        TEST_ASSERT(send_message_err(&client, &server, PSA_PAKE_STEP_KEY_SHARE, 0));
        TEST_ASSERT(send_message_err(&server, &client, PSA_PAKE_STEP_KEY_SHARE, 0));
        TEST_ASSERT(psa_pake_input(&server, PSA_PAKE_STEP_SALT, srp_salt, sizeof srp_salt) == PSA_SUCCESS);
        TEST_ASSERT(psa_pake_input(&client, PSA_PAKE_STEP_SALT, srp_salt, sizeof srp_salt) == PSA_SUCCESS);
        TEST_ASSERT(send_message_err(&server, &client, PSA_PAKE_STEP_CONFIRM, 1));
        goto abort;
    case 36:
        TEST_ASSERT(psa_pake_get_shared_key(&client, &attributes, &key) == PSA_ERROR_BAD_STATE);
        TEST_ASSERT(psa_pake_get_shared_key(&server, &attributes, &key) == PSA_ERROR_BAD_STATE);
        goto abort;
    case 37:
        TEST_ASSERT(send_message_err(&client, &server, PSA_PAKE_STEP_KEY_SHARE, 0));
        TEST_ASSERT(send_message_err(&server, &client, PSA_PAKE_STEP_KEY_SHARE, 0));
        TEST_ASSERT(psa_pake_get_shared_key(&client, &attributes, &key) == PSA_ERROR_BAD_STATE);
        TEST_ASSERT(psa_pake_get_shared_key(&server, &attributes, &key) == PSA_ERROR_BAD_STATE);
        goto abort;
    case 38:
        TEST_ASSERT(send_message_err(&client, &server, PSA_PAKE_STEP_KEY_SHARE, 0));
        TEST_ASSERT(send_message_err(&server, &client, PSA_PAKE_STEP_KEY_SHARE, 0));
        TEST_ASSERT(psa_pake_input(&server, PSA_PAKE_STEP_SALT, srp_salt, sizeof srp_salt) == PSA_SUCCESS);
        TEST_ASSERT(psa_pake_input(&client, PSA_PAKE_STEP_SALT, srp_salt, sizeof srp_salt) == PSA_SUCCESS);
        TEST_ASSERT(send_message_err(&client, &server, PSA_PAKE_STEP_CONFIRM, 0));
        TEST_ASSERT(psa_pake_get_shared_key(&client, &attributes, &key) == PSA_ERROR_BAD_STATE);
        TEST_ASSERT(psa_pake_get_shared_key(&server, &attributes, &key) == PSA_ERROR_BAD_STATE);
        goto abort;
    case 39: // wrong step
        TEST_ASSERT(psa_pake_input(&server, PSA_PAKE_STEP_ZK_PUBLIC, srp_salt, sizeof srp_salt) == PSA_ERROR_INVALID_ARGUMENT);
        goto abort;
    case 40: // wrong step
        TEST_ASSERT(psa_pake_output(&server, PSA_PAKE_STEP_SALT, salt, sizeof salt, &length) == PSA_ERROR_INVALID_ARGUMENT);
        goto abort;
    case 41: // wrong proof
        TEST_ASSERT(psa_pake_input(&client, PSA_PAKE_STEP_SALT, srp_salt, sizeof srp_salt) == PSA_SUCCESS);
        TEST_ASSERT(psa_pake_input(&server, PSA_PAKE_STEP_SALT, srp_salt, sizeof srp_salt) == PSA_SUCCESS);
        TEST_ASSERT(send_message_err(&server, &client, PSA_PAKE_STEP_KEY_SHARE, 0));
        TEST_ASSERT(send_message_err(&client, &server, PSA_PAKE_STEP_KEY_SHARE, 0));
        TEST_ASSERT(send_message_err(&client, &server, PSA_PAKE_STEP_CONFIRM, 4));
        goto abort;
    case 42: // wrong proof
        TEST_ASSERT(psa_pake_input(&client, PSA_PAKE_STEP_SALT, srp_salt, sizeof srp_salt) == PSA_SUCCESS);
        TEST_ASSERT(psa_pake_input(&server, PSA_PAKE_STEP_SALT, srp_salt, sizeof srp_salt) == PSA_SUCCESS);
        TEST_ASSERT(send_message_err(&server, &client, PSA_PAKE_STEP_KEY_SHARE, 0));
        TEST_ASSERT(send_message_err(&client, &server, PSA_PAKE_STEP_KEY_SHARE, 0));
        TEST_ASSERT(send_message_err(&client, &server, PSA_PAKE_STEP_CONFIRM, 0));
        TEST_ASSERT(send_message_err(&server, &client, PSA_PAKE_STEP_CONFIRM, 4));
        goto abort;
    default:
        TEST_ASSERT(psa_pake_input(&client, PSA_PAKE_STEP_SALT, srp_salt, sizeof srp_salt) == PSA_SUCCESS);
        TEST_ASSERT(psa_pake_input(&server, PSA_PAKE_STEP_SALT, srp_salt, sizeof srp_salt) == PSA_SUCCESS);
        TEST_ASSERT(send_message_err(&server, &client, PSA_PAKE_STEP_KEY_SHARE, 0));
        TEST_ASSERT(send_message_err(&client, &server, PSA_PAKE_STEP_KEY_SHARE, 0));
        TEST_ASSERT(send_message_err(&client, &server, PSA_PAKE_STEP_CONFIRM, 0));
        TEST_ASSERT(send_message_err(&server, &client, PSA_PAKE_STEP_CONFIRM, 0));
        break;
    }

    switch (n) {
    case 43: // invalid key type
        psa_set_key_type(&attributes, PSA_KEY_TYPE_RSA_PUBLIC_KEY);
        TEST_ASSERT(psa_pake_get_shared_key(&client, &attributes, &key) == PSA_ERROR_INVALID_ARGUMENT);
        TEST_ASSERT(key == 0);
        goto abort;
    case 44: // invalid key type
        psa_set_key_type(&attributes, PSA_KEY_TYPE_RSA_PUBLIC_KEY);
        TEST_ASSERT(psa_pake_get_shared_key(&server, &attributes, &key) == PSA_ERROR_INVALID_ARGUMENT);
        TEST_ASSERT(key == 0);
        goto abort;
    case 45: // key size > 0
        psa_set_key_bits(&attributes, 256);
        TEST_ASSERT(psa_pake_get_shared_key(&client, &attributes, &key) == PSA_ERROR_INVALID_ARGUMENT);
        TEST_ASSERT(key == 0);
        goto abort;
    case 46: // key size > 0
        psa_set_key_bits(&attributes, 256);
        TEST_ASSERT(psa_pake_get_shared_key(&server, &attributes, &key) == PSA_ERROR_INVALID_ARGUMENT);
        TEST_ASSERT(key == 0);
        goto abort;
    }

abort:
    TEST_ASSERT(psa_pake_abort(&client) == PSA_SUCCESS);
    TEST_ASSERT(psa_pake_abort(&server) == PSA_SUCCESS);
    TEST_ASSERT(psa_destroy_key(ckey) == PSA_SUCCESS);
    TEST_ASSERT(psa_destroy_key(skey) == PSA_SUCCESS);
    TEST_ASSERT(psa_destroy_key(key) == PSA_SUCCESS);
    return 1;
exit:
    psa_destroy_key(ckey);
    psa_destroy_key(skey);
    psa_destroy_key(key);
    return 0;
}
#endif // PSA_WANT_ALG_SRP_6

/*
 * WPA3-SAE Tests
 */
#ifdef PSA_WANT_ALG_WPA3_SAE

static const uint8_t local_mac1[6] = {0x4d, 0x3f, 0x2f, 0xff, 0xe3, 0x87};
static const uint8_t peer_mac1[6]  = {0xa5, 0xd8, 0xaa, 0x95, 0x8e, 0x3c};
static const uint8_t local_rand1[64] = {
    0x99, 0x24, 0x65, 0xfd, 0x3d, 0xaa, 0x3c, 0x60, 0xaa, 0x65, 0x65, 0xb7, 0xf6, 0x2a, 0x2a, 0x7f,
    0x2e, 0x12, 0xdd, 0x12, 0xf1, 0x98, 0xfa, 0xf4, 0xfb, 0xed, 0x89, 0xd7, 0xff, 0x1a, 0xce, 0x94,
    0x95, 0x07, 0xa9, 0x0f, 0x77, 0x7a, 0x04, 0x4d, 0x6a, 0x08, 0x30, 0xb9, 0x1e, 0xa3, 0xd5, 0xdd,
    0x70, 0xbe, 0xce, 0x44, 0xe1, 0xac, 0xff, 0xb8, 0x69, 0x83, 0xb5, 0xe1, 0xbf, 0x9f, 0xb3, 0x22};
static const uint8_t local_commit1[98] = {
    0x13, 0x00,
    0x2e, 0x2c, 0x0f, 0x0d, 0xb5, 0x24, 0x40, 0xad, 0x14, 0x6d, 0x96, 0x71, 0x14, 0xce, 0x00, 0x5c,  
    0xe1, 0xea, 0xb0, 0xaa, 0x2c, 0x2e, 0x5c, 0x28, 0x71, 0xb7, 0x74, 0xf6, 0xc2, 0x57, 0x5c, 0x65,
    0xd5, 0xad, 0x9e, 0x00, 0x82, 0x97, 0x07, 0xaa, 0x36, 0xba, 0x8b, 0x85, 0x97, 0x38, 0xfc, 0x96,
    0x1d, 0x08, 0x24, 0x35, 0x05, 0xf4, 0x7c, 0x03, 0x53, 0x76, 0xd7, 0xac, 0x4b, 0xc8, 0xd7, 0xb9,
    0x50, 0x83, 0xbf, 0x43, 0x82, 0x7d, 0x0f, 0xc3, 0x1e, 0xd7, 0x78, 0xdd, 0x36, 0x71, 0xfd, 0x21,
    0xa4, 0x6d, 0x10, 0x91, 0xd6, 0x4b, 0x6f, 0x9a, 0x1e, 0x12, 0x72, 0x62, 0x13, 0x25, 0xdb, 0xe1};
static const uint8_t peer_rand1[64] = {
    0xbe, 0xdf, 0xd9, 0xe4, 0xda, 0x33, 0xa4, 0x68, 0x77, 0x78, 0xc0, 0xe2, 0xb9, 0xb8, 0x78, 0xc7,
    0xba, 0xe6, 0xd5, 0x95, 0x79, 0xe6, 0xb6, 0xe6, 0xe0, 0xa3, 0x92, 0xe8, 0x54, 0x72, 0x59, 0xf5,
    0x9a, 0x3b, 0xbd, 0x0d, 0x5f, 0x4c, 0x14, 0xdd, 0x98, 0x8f, 0x88, 0x04, 0xfb, 0x97, 0xdb, 0x73,
    0x69, 0x20, 0xfd, 0x9b, 0x65, 0x1f, 0x7b, 0x9a, 0x5d, 0x13, 0xa5, 0xd2, 0x88, 0x7c, 0x1d, 0x7f};
static const uint8_t peer_commit1[98] = {
    0x13, 0x00,
    0x59, 0x1b, 0x96, 0xf3, 0x39, 0x7f, 0xb9, 0x45, 0x10, 0x08, 0x48, 0xe7, 0xb5, 0x50, 0x54, 0x3b,
    0x67, 0x20, 0xd8, 0x83, 0x37, 0xee, 0x93, 0xfc, 0x49, 0xfd, 0x6d, 0xf7, 0xe0, 0x8b, 0x52, 0x23,
    0xe7, 0x1b, 0x9b, 0xb0, 0x48, 0xd3, 0x87, 0x3f, 0x20, 0x55, 0x69, 0x53, 0xa9, 0x6c, 0x91, 0x53,
    0x6f, 0xd8, 0xee, 0x6c, 0xa9, 0xb4, 0xa6, 0x8a, 0x14, 0x8b, 0x05, 0x6a, 0x90, 0x9b, 0xe0, 0x3e,
    0x83, 0xae, 0x20, 0x8f, 0x60, 0xf8, 0xef, 0x55, 0x37, 0x85, 0x80, 0x74, 0xdb, 0x06, 0x68, 0x70,
    0x32, 0x39, 0x98, 0x62, 0x99, 0x9b, 0x51, 0x1e, 0x0a, 0x15, 0x52, 0xa5, 0xfe, 0xa3, 0x17, 0xc2};
static const uint8_t PMK1[32] = {
    0x4e, 0x4d, 0xfa, 0xb1, 0xa2, 0xdd, 0x8a, 0xc1, 0xa9, 0x17, 0x90, 0xf9, 0x53, 0xfa, 0xaa, 0x45,
    0x2a, 0xe5, 0xc6, 0x87, 0x3a, 0xb7, 0x5b, 0x63, 0x60, 0x5b, 0xa6, 0x63, 0xf8, 0xa7, 0xfe, 0x59};
static const uint8_t PMKID1[16] = {
    0x87, 0x47, 0xa6, 0x00, 0xee, 0xa3, 0xf9, 0xf2, 0x24, 0x75, 0xdf, 0x58, 0xca, 0x1e, 0x54, 0x98};

// h2e
static const uint8_t local_mac2[6] = {0x00, 0x09, 0x5b, 0x66, 0xec, 0x1e};
static const uint8_t peer_mac2[6]  = {0x00, 0x0b, 0x6b, 0xd9, 0x02, 0x46};
static const uint8_t pt2[64] = {
    0xb6, 0xe3, 0x8c, 0x98, 0x75, 0x0c, 0x68, 0x4b, 0x5d, 0x17, 0xc3, 0xd8, 0xc9, 0xa4, 0x10, 0x0b,
    0x39, 0x93, 0x12, 0x79, 0x18, 0x7c, 0xa6, 0xcc, 0xed, 0x5f, 0x37, 0xef, 0x46, 0xdd, 0xfa, 0x97,
    0x56, 0x87, 0xe9, 0x72, 0xe5, 0x0f, 0x73, 0xe3, 0x89, 0x88, 0x61, 0xe7, 0xed, 0xad, 0x21, 0xbe,
    0xa7, 0xd5, 0xf6, 0x22, 0xdf, 0x88, 0x24, 0x3b, 0xb8, 0x04, 0x92, 0x0a, 0xe8, 0xe6, 0x47, 0xfa};
//static const uint8_t pwe2[64] = {
//    0xc9, 0x30, 0x49, 0xb9, 0xe6, 0x40, 0x00, 0xf8, 0x48, 0x20, 0x16, 0x49, 0xe9, 0x99, 0xf2, 0xb5,
//    0xc2, 0x2d, 0xea, 0x69, 0xb5, 0x63, 0x2c, 0x9d, 0xf4, 0xd6, 0x33, 0xb8, 0xaa, 0x1f, 0x6c, 0x1e,
//    0x73, 0x63, 0x4e, 0x94, 0xb5, 0x3d, 0x82, 0xe7, 0x38, 0x3a, 0x8d, 0x25, 0x81, 0x99, 0xd9, 0xdc,
//    0x1a, 0x5e, 0xe8, 0x26, 0x9d, 0x06, 0x03, 0x82, 0xcc, 0xbf, 0x33, 0xe6, 0x14, 0xff, 0x59, 0xa0};

// Test vectors from "IEEE Std 802.11 2012", Annex M10, uses wrong kdf function !!!
static const uint8_t local_mac3[6] = {0x7b, 0x88, 0x56, 0x20, 0x2d, 0x8d};
static const uint8_t peer_mac3[6]  = {0xe2, 0x47, 0x1c, 0x0a, 0x5a, 0xcb};
//static const uint8_t pwe3[64] = {
//    0x10, 0x3a, 0x5b, 0x96, 0x88, 0x73, 0xba, 0xb0, 0xfa, 0xfc, 0x6d, 0xd8, 0xff, 0x34, 0x76, 0xff,
//    0x56, 0x48, 0x7e, 0x7f, 0x07, 0x2b, 0x38, 0xe4, 0xc9, 0x70, 0x54, 0x97, 0x1c, 0xe7, 0x2b, 0x7b,
//    0x31, 0x74, 0x2d, 0x39, 0xf3, 0x80, 0xf2, 0x47, 0x62, 0x42, 0x18, 0xe9, 0x45, 0x54, 0x30, 0x04,
//    0xd3, 0x99, 0x73, 0xa5, 0x68, 0xc5, 0xb9, 0x04, 0xb0, 0xcf, 0x5d, 0x36, 0x2d, 0x44, 0xf3, 0xbf};
static const uint8_t local_rand3[64] = {
    0xc5, 0xd7, 0x01, 0x9e, 0x76, 0x12, 0xd5, 0xf4, 0x3c, 0xf9, 0x1f, 0xe5, 0x62, 0xb4, 0x0b, 0xb8,
    0xb2, 0x64, 0x0c, 0x65, 0xc5, 0x77, 0xb9, 0xb1, 0x99, 0x94, 0xbf, 0x50, 0x6b, 0xaf, 0x28, 0x59,
    0x19, 0xd0, 0x30, 0xfe, 0x5b, 0xb1, 0x1e, 0xe4, 0xc2, 0x7c, 0x9d, 0xfc, 0x3c, 0x06, 0x52, 0x0f,
    0x8f, 0xbe, 0x92, 0x90, 0x05, 0x9b, 0x0c, 0xc5, 0x50, 0xdb, 0x0d, 0x2b, 0x9d, 0x3a, 0xc4, 0x52};
static const uint8_t local_commit3[98] = {
    0x13, 0x00,
    0xdf, 0xa7, 0x32, 0x9c, 0xd1, 0xc3, 0xf4, 0xd8, 0xff, 0x75, 0xbd, 0xe1, 0x9e, 0xba, 0x5d, 0xc8,
    0x42, 0x22, 0x9e, 0xf5, 0xcb, 0x12, 0xc6, 0x76, 0xea, 0x6f, 0xcc, 0x7c, 0x08, 0xe9, 0xec, 0xab,
    0x30, 0x08, 0xb4, 0x0e, 0x01, 0x91, 0x2b, 0xc5, 0x3b, 0x86, 0x2c, 0xd9, 0x43, 0x30, 0x5e, 0x86,
    0x46, 0xee, 0x3b, 0x3e, 0x6f, 0x74, 0x5c, 0x5b, 0xb3, 0xae, 0x8d, 0xfc, 0x2e, 0xbf, 0x65, 0x4e,
    0xd0, 0xa4, 0xe2, 0xa2, 0x8b, 0xb9, 0x8b, 0x62, 0x9a, 0x4b, 0x00, 0x84, 0x9d, 0xf9, 0x3d, 0x22,
    0x29, 0x99, 0xd0, 0x86, 0x5c, 0x9c, 0xce, 0xed, 0xa8, 0xe9, 0x0f, 0xcb, 0x53, 0xaf, 0x5a, 0xe6};
static const uint8_t peer_commit3[98] = {
    0x13, 0x00,
    0x10, 0xc1, 0xe1, 0xf1, 0xd0, 0x08, 0x71, 0x3b, 0x41, 0x98, 0x6c, 0xdd, 0x44, 0x1e, 0xb9, 0x91,
    0xbc, 0x82, 0x3b, 0x60, 0x11, 0x8a, 0x5f, 0xc9, 0xf5, 0x1b, 0x16, 0xaa, 0x00, 0x34, 0x21, 0x47,
    0x19, 0x47, 0x5f, 0x6f, 0x50, 0xdb, 0xc8, 0x7f, 0x15, 0x05, 0xc1, 0x09, 0xe4, 0x21, 0xa7, 0xe3,
    0x6b, 0x3a, 0x2e, 0x3f, 0x48, 0xbf, 0xe5, 0x2e, 0x01, 0xb7, 0x5f, 0x2b, 0xe7, 0xe5, 0xf4, 0xbc,
    0x94, 0x8f, 0xe4, 0x4c, 0x74, 0x1b, 0xd9, 0x7f, 0x51, 0x65, 0x48, 0x57, 0x7c, 0x6f, 0x32, 0x0d,
    0x0c, 0x34, 0x99, 0x39, 0x85, 0x7e, 0x0c, 0x79, 0x30, 0x91, 0x6d, 0x6f, 0x32, 0x37, 0x39, 0xd6};
static const uint8_t local_confirm3[34] = {
    0x01, 0x00,
    0x46, 0x64, 0x47, 0xab, 0x09, 0x62, 0xae, 0x78, 0x0b, 0xcc, 0x7a, 0x0a, 0xc6, 0x72, 0xa3, 0x9c,
    0x62, 0xec, 0x30, 0x09, 0xcf, 0xb2, 0x34, 0xdd, 0x19, 0x18, 0x37, 0xc7, 0x92, 0xb9, 0x54, 0x8e};
static const uint8_t peer_confirm3[34] = {
    0x01, 0x00,
    0x2d, 0xf5, 0xf6, 0x2c, 0x46, 0x10, 0x5b, 0x60, 0x6d, 0x76, 0x72, 0xb8, 0x9c, 0x3e, 0x61, 0x54,
    0x21, 0xd2, 0x6d, 0x99, 0x91, 0xda, 0xa8, 0x18, 0x37, 0x78, 0x81, 0x1d, 0x30, 0xac, 0xe3, 0xdb};
static const uint8_t PMK3[32] = {
    0xf6, 0xec, 0xb8, 0xad, 0xe3, 0xae, 0x30, 0xdf, 0xe3, 0x5d, 0x31, 0xea, 0xee, 0x04, 0x71, 0x61,
    0xb3, 0xa0, 0x0d, 0x94, 0x45, 0xc5, 0xdf, 0xd2, 0x2c, 0xd8, 0xd8, 0xfb, 0xaf, 0x83, 0xd9, 0xc7};

static const uint8_t rejected[4] = {20, 0, 21, 0}; // P384,P521

extern int sha256_prf_count_len; // test vector error fix !!!

static int setup_sae_endpoint(psa_pake_operation_t *op,
    const uint8_t *user, const uint8_t *peer,
    psa_algorithm_t alg, psa_key_id_t key)
{
    psa_pake_cipher_suite_t suite = PSA_PAKE_CIPHER_SUITE_INIT;
    psa_pake_primitive_t sae_primitive =
        PSA_PAKE_PRIMITIVE(PSA_PAKE_PRIMITIVE_TYPE_ECC, PSA_ECC_FAMILY_SECP_R1, 256);

    psa_pake_cs_set_algorithm(&suite, alg);
    psa_pake_cs_set_primitive(&suite, sae_primitive);

    TEST_ASSERT(psa_pake_setup(op, key, &suite) == PSA_SUCCESS);
    TEST_ASSERT(psa_pake_set_user(op, user, 6) == PSA_SUCCESS);
    TEST_ASSERT(psa_pake_set_peer(op, peer, 6) == PSA_SUCCESS);

    return 1;
exit:
    return 0;
}

static int test_sae(const uint8_t mac[6], const uint8_t peer_mac[6], const char *ssid, const char *pw,
                    const char *pwid, const uint8_t *salt, size_t salt_len, unsigned count, int n)
{
    psa_pake_operation_t local = PSA_PAKE_OPERATION_INIT;
    psa_pake_operation_t peer = PSA_PAKE_OPERATION_INIT;
    psa_key_derivation_operation_t kdf = PSA_KEY_DERIVATION_OPERATION_INIT;
    psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;
    psa_algorithm_t alg;
    psa_key_id_t key = 0, ekey = 0;
    uint8_t secret1[32], secret2[32], data[64], keyid[16], send_count[2];
    size_t length1, length2;
    size_t commit_size, confirm_size;
    const uint8_t *rand = NULL, *peer_rand = NULL;
    const uint8_t *commit = NULL, *peer_commit = NULL;
  //  const uint8_t *confirm = NULL, *peer_confirm = NULL;
    const uint8_t *pmk = NULL, *pmkid = NULL;

    send_count[0] = (uint8_t)count;
    send_count[1] = (uint8_t)(count >> 8);

    if (ssid == NULL || n & 1) {
        alg = PSA_ALG_WPA3_SAE_FIXED(PSA_ALG_SHA_256);
    } else {
        alg = PSA_ALG_WPA3_SAE_GDH(PSA_ALG_SHA_256);
    }

    if (n == 5) {
        sha256_prf_count_len = 1; // test vector error fix !!!
    }

    if (ssid != NULL) { // use H2E
        psa_set_key_usage_flags(&attributes, PSA_KEY_USAGE_DERIVE);
        psa_set_key_algorithm(&attributes, PSA_ALG_WPA3_SAE_H2E(PSA_ALG_SHA_256));
        psa_set_key_type(&attributes, PSA_KEY_TYPE_PASSWORD);
        TEST_ASSERT(psa_import_key(&attributes, (const uint8_t*)pw, strlen(pw), &key) == PSA_SUCCESS);

        TEST_ASSERT(psa_key_derivation_setup(&kdf, PSA_ALG_WPA3_SAE_H2E(PSA_ALG_SHA_256)) == PSA_SUCCESS);
        TEST_ASSERT(psa_key_derivation_input_bytes(&kdf, PSA_KEY_DERIVATION_INPUT_SALT, (const uint8_t*)ssid, strlen(ssid)) == PSA_SUCCESS);
        TEST_ASSERT(psa_key_derivation_input_key(&kdf, PSA_KEY_DERIVATION_INPUT_PASSWORD, key) == PSA_SUCCESS);
        if (pwid != NULL) {
            TEST_ASSERT(psa_key_derivation_input_bytes(&kdf, PSA_KEY_DERIVATION_INPUT_INFO, (const uint8_t*)pwid, strlen(pwid)) == PSA_SUCCESS);
        }
        TEST_ASSERT(psa_destroy_key(key) == PSA_SUCCESS);
        psa_set_key_usage_flags(&attributes, PSA_KEY_USAGE_DERIVE | PSA_KEY_USAGE_EXPORT);
        psa_set_key_algorithm(&attributes, alg);
        psa_set_key_bits(&attributes, 256);
        psa_set_key_type(&attributes, PSA_KEY_TYPE_WPA3_SAE_ECC_PT(PSA_ECC_FAMILY_SECP_R1));
        TEST_ASSERT(psa_key_derivation_output_key(&attributes, &kdf, &ekey) == PSA_SUCCESS);
        TEST_ASSERT(psa_export_key(ekey, data, sizeof data, &length1) == PSA_SUCCESS);
        if (n == 4) {
            ASSERT_COMPARE(data, length1, pt2, sizeof pt2);
        } else {
            // re-import key
            TEST_ASSERT(psa_destroy_key(ekey) == PSA_SUCCESS);
            TEST_ASSERT(psa_import_key(&attributes, data, length1, &ekey) == PSA_SUCCESS);
        }
    } else { // use basic SAE
        psa_set_key_usage_flags(&attributes, PSA_KEY_USAGE_DERIVE);
        psa_set_key_algorithm(&attributes, alg);
        psa_set_key_type(&attributes, PSA_KEY_TYPE_PASSWORD);
        TEST_ASSERT(psa_import_key(&attributes, (const uint8_t*)pw, strlen(pw), &ekey) == PSA_SUCCESS);
    }

    TEST_ASSERT(setup_sae_endpoint(&local, mac, peer_mac, alg, ekey));
    TEST_ASSERT(setup_sae_endpoint(&peer, peer_mac, mac, alg, ekey));

    commit_size = PSA_PAKE_OUTPUT_SIZE(alg,
        PSA_PAKE_PRIMITIVE(PSA_PAKE_PRIMITIVE_TYPE_ECC, PSA_ECC_FAMILY_SECP_R1, 256),
        PSA_PAKE_STEP_COMMIT);
    confirm_size = PSA_PAKE_OUTPUT_SIZE(alg,
        PSA_PAKE_PRIMITIVE(PSA_PAKE_PRIMITIVE_TYPE_ECC, PSA_ECC_FAMILY_SECP_R1, 256),
        PSA_PAKE_STEP_CONFIRM);
    TEST_ASSERT(PSA_PAKE_OUTPUT_SIZE(alg,
        PSA_PAKE_PRIMITIVE(PSA_PAKE_PRIMITIVE_TYPE_ECC, PSA_ECC_FAMILY_SECP_R1, 256),
        PSA_PAKE_STEP_KEYID) == 16);
    TEST_ASSERT(PSA_PAKE_INPUT_SIZE(alg,
        PSA_PAKE_PRIMITIVE(PSA_PAKE_PRIMITIVE_TYPE_ECC, PSA_ECC_FAMILY_SECP_R1, 256),
        PSA_PAKE_STEP_SEND_CONFIRM) == 2);

    if (n < 4) {
        rand = local_rand1;
        peer_rand = peer_rand1;
        commit = local_commit1;
        peer_commit = peer_commit1;
        pmk = PMK1;
        pmkid = PMKID1;
    }

    if (n == 5) {
        uint8_t data[256];
        oberon_test_drbg_setup(local_rand3, sizeof local_rand3);
        TEST_ASSERT(psa_pake_output(&local, PSA_PAKE_STEP_COMMIT, data, sizeof data, &length1) == PSA_SUCCESS);
        ASSERT_COMPARE(data, length1, local_commit3, sizeof local_commit3);
        TEST_ASSERT(psa_pake_input(&local, PSA_PAKE_STEP_COMMIT, peer_commit3, sizeof peer_commit3) == PSA_SUCCESS);

        TEST_ASSERT(psa_pake_input(&local, PSA_PAKE_STEP_SEND_CONFIRM, send_count, 2) == PSA_SUCCESS); // set send-confirm counter
        TEST_ASSERT(psa_pake_output(&local, PSA_PAKE_STEP_CONFIRM, data, sizeof data, &length1) == PSA_SUCCESS);
        ASSERT_COMPARE(data, length1, local_confirm3, sizeof local_confirm3);
        TEST_ASSERT(psa_pake_input(&local, PSA_PAKE_STEP_CONFIRM, peer_confirm3, sizeof peer_confirm3) == PSA_SUCCESS);
        pmk = PMK3;
    } else {
        if (n & 1) {
            if (rand) oberon_test_drbg_setup(rand, 64);
            TEST_ASSERT(send_message(&local, &peer, PSA_PAKE_STEP_COMMIT, commit, commit_size));
            if (peer_rand) oberon_test_drbg_setup(peer_rand, 64);
            TEST_ASSERT(send_message(&peer, &local, PSA_PAKE_STEP_COMMIT, peer_commit, commit_size));
        } else {
            if (peer_rand) oberon_test_drbg_setup(peer_rand, 64);
            TEST_ASSERT(send_message(&peer, &local, PSA_PAKE_STEP_COMMIT, peer_commit, commit_size));
            if (rand) oberon_test_drbg_setup(rand, 64);
            TEST_ASSERT(send_message(&local, &peer, PSA_PAKE_STEP_COMMIT, commit, commit_size));
        }

        if (salt_len) {
            // set salt
            TEST_ASSERT(psa_pake_input(&local, PSA_PAKE_STEP_SALT, salt, salt_len) == PSA_SUCCESS);
            TEST_ASSERT(psa_pake_input(&peer, PSA_PAKE_STEP_SALT, salt, salt_len) == PSA_SUCCESS);
        }

        // set send-confirm counter
        TEST_ASSERT(psa_pake_input(&local, PSA_PAKE_STEP_SEND_CONFIRM, send_count, 2) == PSA_SUCCESS);
        TEST_ASSERT(psa_pake_input(&peer, PSA_PAKE_STEP_SEND_CONFIRM, send_count, 2) == PSA_SUCCESS);
        if (n & 2) {
            TEST_ASSERT(send_message(&local, &peer, PSA_PAKE_STEP_CONFIRM, NULL, confirm_size));
            TEST_ASSERT(send_message(&peer, &local, PSA_PAKE_STEP_CONFIRM, NULL, confirm_size));
        } else {
            TEST_ASSERT(send_message(&peer, &local, PSA_PAKE_STEP_CONFIRM, NULL, confirm_size));
            TEST_ASSERT(send_message(&local, &peer, PSA_PAKE_STEP_CONFIRM, NULL, confirm_size));
        }
    }

    psa_set_key_type(&attributes, PSA_KEY_TYPE_DERIVE);
    psa_set_key_usage_flags(&attributes, PSA_KEY_USAGE_EXPORT);
    psa_set_key_algorithm(&attributes, PSA_ALG_HKDF(PSA_ALG_SHA_256));
    psa_set_key_bits(&attributes, 0);

    // get local secret
    if (pmkid) {
        TEST_ASSERT(psa_pake_output(&local, PSA_PAKE_STEP_KEYID, keyid, sizeof keyid, &length1) == PSA_SUCCESS);
        ASSERT_COMPARE(keyid, length1, pmkid, 16);
    }
    TEST_ASSERT(psa_pake_get_shared_key(&local, &attributes, &key) == PSA_SUCCESS);
    TEST_ASSERT(psa_pake_abort(&local) == PSA_SUCCESS);
    TEST_ASSERT(psa_export_key(key, secret1, sizeof secret1, &length1) == PSA_SUCCESS);
    TEST_ASSERT(psa_destroy_key(key) == PSA_SUCCESS);
    if (pmk) {
        ASSERT_COMPARE(secret1, length1, pmk, 32);
    }

    if (n != 5) {
        // get peer secret
        TEST_ASSERT(psa_pake_get_shared_key(&peer, &attributes, &key) == PSA_SUCCESS);
        TEST_ASSERT(psa_export_key(key, secret2, sizeof secret2, &length2) == PSA_SUCCESS);
        ASSERT_COMPARE(secret1, length1, secret2, length2);
        TEST_ASSERT(psa_destroy_key(key) == PSA_SUCCESS);
    }
    TEST_ASSERT(psa_pake_abort(&peer) == PSA_SUCCESS);
    TEST_ASSERT(psa_destroy_key(ekey) == PSA_SUCCESS);

    sha256_prf_count_len = 2; // test vector error fix !!!

    return 1;
exit:
    psa_destroy_key(ekey);
    psa_destroy_key(key);
    return 0;
}

static int setup_sae_endpoint_err(psa_pake_operation_t *op,
    const uint8_t *user, const uint8_t *peer, const char *ssid, psa_key_id_t *key, int n)
{
    uint8_t data[128];
    psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;
    psa_key_attributes_t pw_attr = PSA_KEY_ATTRIBUTES_INIT;
    psa_status_t expected = PSA_SUCCESS;
    psa_pake_cipher_suite_t suite = PSA_PAKE_CIPHER_SUITE_INIT;
    psa_key_derivation_operation_t kdf = PSA_KEY_DERIVATION_OPERATION_INIT;
    psa_key_id_t pwkey = 0;
    size_t length;

    if (n == 1) { // wrong algorithm
        psa_pake_cs_set_algorithm(&suite, PSA_ALG_SHA_256);
        expected = PSA_ERROR_INVALID_ARGUMENT;
    } else {
        psa_pake_cs_set_algorithm(&suite, PSA_ALG_WPA3_SAE_FIXED(PSA_ALG_SHA_256));
    }

    if (n == 2) { // wrong primitive type
        psa_pake_cs_set_primitive(&suite,
            PSA_PAKE_PRIMITIVE((psa_pake_primitive_type_t) 0x03, PSA_ECC_FAMILY_SECP_R1, 256));
        expected = PSA_ERROR_INVALID_ARGUMENT;
    } else {
        psa_pake_cs_set_primitive(&suite,
            PSA_PAKE_PRIMITIVE(PSA_PAKE_PRIMITIVE_TYPE_ECC, PSA_ECC_FAMILY_SECP_R1, 256));
    }

    if (n == 3) { // incompatible confirmation
        psa_pake_cs_set_key_confirmation(&suite, PSA_PAKE_UNCONFIRMED_KEY);
        expected = PSA_ERROR_INVALID_ARGUMENT;
    }

    if (n == 4) { // incompatible usage
        psa_set_key_usage_flags(&attributes, PSA_KEY_USAGE_EXPORT);
        expected = PSA_ERROR_NOT_PERMITTED;
    } else {
        psa_set_key_usage_flags(&attributes, PSA_KEY_USAGE_DERIVE);
    }

    if (n == 5) { // incompatible algorithm
        psa_set_key_algorithm(&attributes, PSA_ALG_WPA3_SAE_FIXED(PSA_ALG_SHA_512));
        expected = PSA_ERROR_NOT_PERMITTED;
    } else {
        psa_set_key_algorithm(&attributes, PSA_ALG_WPA3_SAE_FIXED(PSA_ALG_SHA_256));
    }

    if (ssid != NULL) { // use H2E
        psa_set_key_usage_flags(&pw_attr, PSA_KEY_USAGE_DERIVE);
        psa_set_key_algorithm(&pw_attr, PSA_ALG_WPA3_SAE_H2E(PSA_ALG_SHA_256));
        psa_set_key_type(&pw_attr, PSA_KEY_TYPE_PASSWORD);
        TEST_ASSERT(psa_import_key(&pw_attr, (const uint8_t*)"password", 8, &pwkey) == PSA_SUCCESS);
        TEST_ASSERT(psa_key_derivation_setup(&kdf, PSA_ALG_WPA3_SAE_H2E(PSA_ALG_SHA_256)) == PSA_SUCCESS);
        TEST_ASSERT(psa_key_derivation_input_bytes(&kdf, PSA_KEY_DERIVATION_INPUT_SALT, (const uint8_t*)ssid, strlen(ssid)) == PSA_SUCCESS);
        TEST_ASSERT(psa_key_derivation_input_key(&kdf, PSA_KEY_DERIVATION_INPUT_PASSWORD, pwkey) == PSA_SUCCESS);
        TEST_ASSERT(psa_destroy_key(pwkey) == PSA_SUCCESS);

        if (n == 6) { // wrong key type
            psa_set_key_type(&attributes, PSA_KEY_TYPE_RAW_DATA);
            expected = PSA_ERROR_INVALID_ARGUMENT;
        } else {
            psa_set_key_type(&attributes, PSA_KEY_TYPE_WPA3_SAE_ECC_PT(PSA_ECC_FAMILY_SECP_R1));
        }

        psa_set_key_bits(&attributes, 256);
        TEST_ASSERT(psa_key_derivation_output_key(&attributes, &kdf, key) == PSA_SUCCESS);
    } else {
        if (n == 6) { // wrong key type
            psa_set_key_type(&attributes, PSA_KEY_TYPE_RAW_DATA);
            expected = PSA_ERROR_INVALID_ARGUMENT;
        } else {
            psa_set_key_type(&attributes, PSA_KEY_TYPE_PASSWORD);
        }

        TEST_ASSERT(psa_import_key(&attributes, (const uint8_t*)"password", 8, key) == PSA_SUCCESS);
    }

    TEST_ASSERT(psa_pake_setup(op, *key, &suite) == expected);
    if (expected != PSA_SUCCESS) return 1;

    if (n == 7) { // already started
        TEST_ASSERT(psa_pake_setup(op, *key, &suite) == PSA_ERROR_BAD_STATE);
        return 1;
    }

    if (n == 8) { // output before set_user
        TEST_ASSERT(psa_pake_output(op, PSA_PAKE_STEP_COMMIT, data, sizeof data, &length) == PSA_ERROR_BAD_STATE);
        return 1;
    }

    if (n == 9) { // set_peer before set_user
        TEST_ASSERT(psa_pake_set_peer(op, peer, 6) == PSA_ERROR_BAD_STATE);
        return 1;
    }

    if (n == 10) { // wrong set_role
        TEST_ASSERT(psa_pake_set_role(op, PSA_PAKE_ROLE_CLIENT) == PSA_ERROR_INVALID_ARGUMENT);
        return 1;
    }

    if (n == 11) { // wrong user
        TEST_ASSERT(psa_pake_set_user(op, user, 5) == PSA_ERROR_INVALID_ARGUMENT);
        return 1;
    } else {
        TEST_ASSERT(psa_pake_set_user(op, user, 6) == PSA_SUCCESS);
    }

    if (n == 12) { // output before set_peer
        TEST_ASSERT(psa_pake_output(op, PSA_PAKE_STEP_COMMIT, data, sizeof data, &length) == PSA_ERROR_BAD_STATE);
        return 1;
    }

    if (n == 13) { // wrong peer
        TEST_ASSERT(psa_pake_set_peer(op, peer, 7) == PSA_ERROR_INVALID_ARGUMENT);
        return 1;
    } else {
        TEST_ASSERT(psa_pake_set_peer(op, peer, 6) == PSA_SUCCESS);
    }

    if (n == 14) { // wrong set_role
        TEST_ASSERT(psa_pake_set_role(op, PSA_PAKE_ROLE_CLIENT) == PSA_ERROR_INVALID_ARGUMENT);
        return 1;
    }

    return 1;
exit:
    return 0;
}

static int test_sae_err(const char *ssid, int n)
{
    psa_pake_operation_t local = PSA_PAKE_OPERATION_INIT;
    psa_pake_operation_t peer = PSA_PAKE_OPERATION_INIT;
    psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;
    psa_key_id_t key = 0, lkey = 0, pkey = 0;
    uint8_t data[256], send_count[2] = {1, 0};
    size_t length;

    if (n <= 14) { // error in local setup
        TEST_ASSERT(setup_sae_endpoint_err(&local, local_mac1, peer_mac1, ssid, &lkey, n));
        goto abort;
    } else {
        TEST_ASSERT(setup_sae_endpoint_err(&local, local_mac1, peer_mac1, ssid, &lkey, 0));
    }
    if (n > 14 && n <= 28) { // error in peer setup
        TEST_ASSERT(setup_sae_endpoint_err(&peer, peer_mac1, local_mac1, ssid, &pkey, n - 14));
        goto abort;
    } else {
        TEST_ASSERT(setup_sae_endpoint_err(&peer, peer_mac1, local_mac1, ssid, &pkey, 0));
    }

    switch (n) {
    case 29: // early set salt
        TEST_ASSERT(psa_pake_input(&local, PSA_PAKE_STEP_SALT, rejected, sizeof rejected) == PSA_ERROR_BAD_STATE);
        goto abort;
    case 30: // early send-confirm
        TEST_ASSERT(psa_pake_input(&local, PSA_PAKE_STEP_SEND_CONFIRM, send_count, 2) == PSA_ERROR_BAD_STATE);
        goto abort;
    case 31: // early confirm
        TEST_ASSERT(send_message_err(&local, &peer, PSA_PAKE_STEP_CONFIRM, 1));
        goto abort;
    case 32: // early key id
        TEST_ASSERT(psa_pake_output(&local, PSA_PAKE_STEP_KEYID, data, sizeof data, &length) == PSA_ERROR_BAD_STATE);
        goto abort;
    case 33: // wrong commit size
        TEST_ASSERT(send_message_err(&local, &peer, PSA_PAKE_STEP_COMMIT, 2));
        goto abort;
    case 34: // wrong commit data
        TEST_ASSERT(send_message_err(&local, &peer, PSA_PAKE_STEP_COMMIT, 5));
        goto abort;
    case 35: // salt output
        TEST_ASSERT(send_message_err(&local, &peer, PSA_PAKE_STEP_COMMIT, 0));
        TEST_ASSERT(send_message_err(&peer, &local, PSA_PAKE_STEP_COMMIT, 0));
        TEST_ASSERT(psa_pake_output(&local, PSA_PAKE_STEP_SALT, data, sizeof data, &length) == PSA_ERROR_INVALID_ARGUMENT);
        goto abort;
    case 36: // send-confirm output
        TEST_ASSERT(send_message_err(&local, &peer, PSA_PAKE_STEP_COMMIT, 0));
        TEST_ASSERT(send_message_err(&peer, &local, PSA_PAKE_STEP_COMMIT, 0));
        TEST_ASSERT(psa_pake_output(&local, PSA_PAKE_STEP_SEND_CONFIRM, data, sizeof data, &length) == PSA_ERROR_INVALID_ARGUMENT);
        goto abort;
    case 37: // no send-confirm
        TEST_ASSERT(send_message_err(&local, &peer, PSA_PAKE_STEP_COMMIT, 0));
        TEST_ASSERT(send_message_err(&peer, &local, PSA_PAKE_STEP_COMMIT, 0));
        TEST_ASSERT(psa_pake_output(&local, PSA_PAKE_STEP_CONFIRM, data, sizeof data, &length) == PSA_ERROR_BAD_STATE);
        goto abort;
    case 38: // no send-confirm
        TEST_ASSERT(send_message_err(&local, &peer, PSA_PAKE_STEP_COMMIT, 0));
        TEST_ASSERT(send_message_err(&peer, &local, PSA_PAKE_STEP_COMMIT, 0));
        TEST_ASSERT(psa_pake_output(&peer, PSA_PAKE_STEP_CONFIRM, data, sizeof data, &length) == PSA_ERROR_BAD_STATE);
        goto abort;
    case 39: // wrong confirm size
        TEST_ASSERT(send_message_err(&local, &peer, PSA_PAKE_STEP_COMMIT, 0));
        TEST_ASSERT(send_message_err(&peer, &local, PSA_PAKE_STEP_COMMIT, 0));
        TEST_ASSERT(psa_pake_input(&local, PSA_PAKE_STEP_SEND_CONFIRM, send_count, 2) == PSA_SUCCESS);
        TEST_ASSERT(send_message_err(&local, &peer, PSA_PAKE_STEP_CONFIRM, 3));
        goto abort;
    case 40: // wrong confirm
        TEST_ASSERT(send_message_err(&local, &peer, PSA_PAKE_STEP_COMMIT, 0));
        TEST_ASSERT(send_message_err(&peer, &local, PSA_PAKE_STEP_COMMIT, 0));
        TEST_ASSERT(psa_pake_input(&local, PSA_PAKE_STEP_SEND_CONFIRM, send_count, 2) == PSA_SUCCESS);
        TEST_ASSERT(send_message_err(&local, &peer, PSA_PAKE_STEP_CONFIRM, 4));
        goto abort;
    default:
        TEST_ASSERT(send_message_err(&local, &peer, PSA_PAKE_STEP_COMMIT, 0));
        TEST_ASSERT(send_message_err(&peer, &local, PSA_PAKE_STEP_COMMIT, 0));
        TEST_ASSERT(psa_pake_input(&local, PSA_PAKE_STEP_SEND_CONFIRM, send_count, 2) == PSA_SUCCESS);
        TEST_ASSERT(psa_pake_input(&peer, PSA_PAKE_STEP_SEND_CONFIRM, send_count, 2) == PSA_SUCCESS);
        TEST_ASSERT(send_message_err(&local, &peer, PSA_PAKE_STEP_CONFIRM, 0));
        TEST_ASSERT(send_message_err(&peer, &local, PSA_PAKE_STEP_CONFIRM, 0));
        break;
    }

    psa_set_key_type(&attributes, PSA_KEY_TYPE_DERIVE);
    psa_set_key_usage_flags(&attributes, PSA_KEY_USAGE_EXPORT);
    psa_set_key_algorithm(&attributes, PSA_ALG_HKDF(PSA_ALG_SHA_256));
    psa_set_key_bits(&attributes, 0);

    switch (n) {
    case 41: // invalid key type
        psa_set_key_type(&attributes, PSA_KEY_TYPE_RSA_PUBLIC_KEY);
        TEST_ASSERT(psa_pake_get_shared_key(&local, &attributes, &key) == PSA_ERROR_INVALID_ARGUMENT);
        TEST_ASSERT(key == 0);
        break;
    case 42: // key size > 0
        psa_set_key_bits(&attributes, 256);
        TEST_ASSERT(psa_pake_get_shared_key(&local, &attributes, &key) == PSA_ERROR_INVALID_ARGUMENT);
        TEST_ASSERT(key == 0);
        break;
    case 43: // small key id buffer
        TEST_ASSERT(psa_pake_output(&local, PSA_PAKE_STEP_KEYID, data, 12, &length) == PSA_ERROR_BUFFER_TOO_SMALL);
        break;
    }

abort:
    TEST_ASSERT(psa_pake_abort(&local) == PSA_SUCCESS);
    TEST_ASSERT(psa_pake_abort(&peer) == PSA_SUCCESS);
    TEST_ASSERT(psa_destroy_key(key) == PSA_SUCCESS);
    TEST_ASSERT(psa_destroy_key(lkey) == PSA_SUCCESS);
    TEST_ASSERT(psa_destroy_key(pkey) == PSA_SUCCESS);
    return 1;
exit:
    psa_destroy_key(key);
    psa_destroy_key(lkey);
    psa_destroy_key(pkey);
    return 0;
}

#endif // PSA_WANT_ALG_WPA3_SAE

#ifdef PSA_WANT_ALG_ML_DSA

// Test vectors from KAT/MLDSA

static const uint8_t seed[32] = {
    0xF6, 0x96, 0x48, 0x40, 0x48, 0xEC, 0x21, 0xF9, 0x6C, 0xF5, 0x0A, 0x56, 0xD0, 0x75, 0x9C, 0x44,
    0x8F, 0x37, 0x79, 0x75, 0x2F, 0x03, 0x83, 0xD3, 0x74, 0x49, 0x69, 0x06, 0x94, 0xCF, 0x7A, 0x68};
static const uint8_t rnd[32] = {
    0xdf, 0xa7, 0x32, 0x9c, 0xd1, 0xc3, 0xf4, 0xd8, 0xff, 0x75, 0xbd, 0xe1, 0x9e, 0xba, 0x5d, 0xc8,
    0x42, 0x22, 0x9e, 0xf5, 0xcb, 0x12, 0xc6, 0x76, 0xea, 0x6f, 0xcc, 0x7c, 0x08, 0xe9, 0xec, 0xab};
static const uint8_t msg[] = {
    0x6D, 0xBB, 0xC4, 0x37, 0x51, 0x36, 0xDF, 0x3B, 0x07, 0xF7, 0xC7, 0x0E, 0x63, 0x9E, 0x22, 0x3E};

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
    case 4: alg = PSA_ALG_ML_DSA; break;
    case 5: alg = PSA_ALG_HASH_ML_DSA(PSA_ALG_SHA_256); break;
    case 6: alg = PSA_ALG_HASH_ML_DSA(PSA_ALG_SHAKE128_256); break;
    case 7: alg = PSA_ALG_DETERMINISTIC_HASH_ML_DSA(PSA_ALG_SHA_256); break;
    case 8: alg = PSA_ALG_DETERMINISTIC_HASH_ML_DSA(PSA_ALG_SHAKE128_256); break;
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

    if (n == 5) {
        psa_set_key_usage_flags(&key_attr, PSA_KEY_USAGE_SIGN_MESSAGE | PSA_KEY_USAGE_SIGN_HASH);
    } else if (n == 3) {
        psa_set_key_usage_flags(&key_attr, PSA_KEY_USAGE_SIGN_MESSAGE | PSA_KEY_USAGE_VERIFY_MESSAGE);
    } else {
        psa_set_key_usage_flags(&key_attr, PSA_KEY_USAGE_SIGN_MESSAGE);
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
    TEST_ASSERT(psa_sign_message(key, alg, msg, sizeof msg, sig, sig_size, &slen) == PSA_SUCCESS);
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
        case 0: ASSERT_COMPARE(h, len, sigH_44, sizeof sigH_44); break;
        case 1: ASSERT_COMPARE(h, len, sigH_65, sizeof sigH_65); break;
        case 2: ASSERT_COMPARE(h, len, sigH_87, sizeof sigH_87); break;
        }
        break;
    case 7:
        psa_hash_compute(PSA_ALG_SHA_256, sig, sig_size, h, sizeof h, &len);
        switch (k) {
        case 0: ASSERT_COMPARE(h, len, sigHD_44, sizeof sigHD_44); break;
        case 1: ASSERT_COMPARE(h, len, sigHD_65, sizeof sigHD_65); break;
        case 2: ASSERT_COMPARE(h, len, sigHD_87, sizeof sigHD_87); break;
        }
        break;
    }

    if (n == 5) {
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

    if (n == 3) {
        TEST_ASSERT(psa_verify_message(key, alg, msg, sizeof msg, sig, slen) == PSA_SUCCESS);
    } else {
        psa_set_key_usage_flags(&key_attr, PSA_KEY_USAGE_VERIFY_MESSAGE);
        psa_set_key_type(&key_attr, PSA_KEY_TYPE_ML_DSA_PUBLIC_KEY);
        TEST_ASSERT(psa_import_key(&key_attr, pub, plen, &pkey) == PSA_SUCCESS);
        TEST_ASSERT(psa_verify_message(pkey, alg, msg, sizeof msg, sig, slen) == PSA_SUCCESS);
    }

    if (n == 5) {
        psa_set_key_usage_flags(&key_attr, PSA_KEY_USAGE_VERIFY_HASH);
        psa_set_key_type(&key_attr, PSA_KEY_TYPE_ML_DSA_PUBLIC_KEY);
        TEST_ASSERT(psa_import_key(&key_attr, pub, plen, &pkey) == PSA_SUCCESS);
        TEST_ASSERT(psa_hash_compute(PSA_ALG_SHA_256, msg, sizeof msg, h, sizeof h, &len) == PSA_SUCCESS);
        TEST_ASSERT(psa_verify_hash(pkey, alg, h, len, sig, slen) == PSA_SUCCESS);
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
    uint8_t h[32], secret1[32], secret2[32];
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
        psa_set_key_usage_flags(&key_attr, PSA_KEY_USAGE_DECRYPT);
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
        TEST_ASSERT(psa_key_encapsulate(key, PSA_ALG_ML_KEM, &key_attr, &skey, ct, ct_size, &clen) == PSA_SUCCESS);
    } else {
        TEST_ASSERT(psa_key_encapsulate(pkey, PSA_ALG_ML_KEM, &key_attr, &skey, ct, ct_size, &clen) == PSA_SUCCESS);
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
    TEST_ASSERT(psa_key_decapsulate(key, PSA_ALG_ML_KEM, ct, clen, &key_attr, &skey) == PSA_SUCCESS);
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
        TEST_ASSERT(psa_key_encapsulate(key, PSA_ALG_ML_KEM, &key_attr, &skey, ct, ct_size, &clen) == PSA_ERROR_NOT_PERMITTED);
        goto abort;
    } else if (n == 2) { // not permitted algorithm 
        TEST_ASSERT(psa_key_encapsulate(key, PSA_ALG_ML_KEM, &key_attr, &skey, ct, ct_size, &clen) == PSA_ERROR_NOT_PERMITTED);
        goto abort;
    } else if (n == 3) { // key does not permit encrypt 
        TEST_ASSERT(psa_key_encapsulate(pkey, PSA_ALG_ML_KEM, &key_attr, &skey, ct, ct_size, &clen) == PSA_ERROR_NOT_PERMITTED);
        goto abort;
    } else if (n == 4) { // not permitted algorithm 
        TEST_ASSERT(psa_key_encapsulate(pkey, PSA_ALG_ML_KEM, &key_attr, &skey, ct, ct_size, &clen) == PSA_ERROR_NOT_PERMITTED);
        goto abort;
    } else if (n == 5) { // wrong algorithm 
        TEST_ASSERT(psa_key_encapsulate(pkey, PSA_ALG_ML_DSA, &key_attr, &skey, ct, ct_size, &clen) == PSA_ERROR_INVALID_ARGUMENT);
        goto abort;
    } else if (n == 6) { // wrong output key type 
        TEST_ASSERT(psa_key_encapsulate(pkey, PSA_ALG_ML_KEM, &key_attr, &skey, ct, ct_size, &clen) == PSA_ERROR_INVALID_ARGUMENT);
        goto abort;
    } else if (n == 7) { // wrong output key size 
        TEST_ASSERT(psa_key_encapsulate(pkey, PSA_ALG_ML_KEM, &key_attr, &skey, ct, ct_size, &clen) == PSA_ERROR_INVALID_ARGUMENT);
        goto abort;
    } else if (n == 8) { // buffer too small 
        TEST_ASSERT(psa_key_encapsulate(pkey, PSA_ALG_ML_KEM, &key_attr, &skey, ct, ct_size - 1, &clen) == PSA_ERROR_BUFFER_TOO_SMALL);
        goto abort;
    } else {
        TEST_ASSERT(psa_key_encapsulate(pkey, PSA_ALG_ML_KEM, &key_attr, &skey, ct, ct_size, &clen) == PSA_SUCCESS);
    }
    TEST_ASSERT(psa_destroy_key(skey) == PSA_SUCCESS);

    if (n == 9) { // key does not permit decrypt
        TEST_ASSERT(psa_key_decapsulate(key, PSA_ALG_ML_KEM, ct, clen, &key_attr, &skey) == PSA_ERROR_NOT_PERMITTED);
        goto abort;
    } else if (n == 10) { // not permitted algorithm 
        psa_set_key_usage_flags(&attr, PSA_KEY_USAGE_ENCRYPT | PSA_KEY_USAGE_DECRYPT);
        psa_set_key_algorithm(&attr, PSA_ALG_ML_DSA);
        psa_set_key_type(&attr, PSA_KEY_TYPE_ML_KEM_KEY_PAIR);
        psa_set_key_bits(&attr, key_size);
        TEST_ASSERT(psa_import_key(&attr, kem_rnd, 64, &key) == PSA_SUCCESS);
        TEST_ASSERT(psa_key_decapsulate(key, PSA_ALG_ML_KEM, ct, clen, &key_attr, &skey) == PSA_ERROR_NOT_PERMITTED);
        goto abort;
    } else if (n == 11) { // wrong algorithm 
        TEST_ASSERT(psa_key_decapsulate(key, PSA_ALG_ML_DSA, ct, clen, &key_attr, &skey) == PSA_ERROR_INVALID_ARGUMENT);
        goto abort;
    } else if (n == 12) { // wrong output key type 
        psa_set_key_algorithm(&key_attr, PSA_ALG_RSA_PKCS1V15_CRYPT);
        psa_set_key_type(&key_attr, PSA_KEY_TYPE_RSA_KEY_PAIR);
        TEST_ASSERT(psa_key_decapsulate(key, PSA_ALG_ML_KEM, ct, clen, &key_attr, &skey) == PSA_ERROR_INVALID_ARGUMENT);
        goto abort;
    } else if (n == 13) { // wrong output key size 
        psa_set_key_bits(&key_attr, 7);
        TEST_ASSERT(psa_key_decapsulate(key, PSA_ALG_ML_KEM, ct, clen, &key_attr, &skey) == PSA_ERROR_INVALID_ARGUMENT);
        goto abort;
    } else if (n == 14) { // wrong ciphertext size 
        TEST_ASSERT(psa_key_decapsulate(key, PSA_ALG_ML_KEM, ct, clen - 1, &key_attr, &skey) == PSA_ERROR_INVALID_ARGUMENT);
        goto abort;
    } else {
        TEST_ASSERT(psa_key_decapsulate(key, PSA_ALG_ML_KEM, ct, clen, &key_attr, &skey) == PSA_SUCCESS);
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


#ifdef PSA_WANT_ECC_SECP_K1_256
#ifdef PSA_WANT_ALG_ECDH
static const uint8_t ecdh_p256k1_skey1[32] = {
    0xc2, 0xcd, 0xf0, 0xa8, 0xb0, 0xa8, 0x3b, 0x35, 0xac, 0xe5, 0x3f, 0x09, 0x7b, 0x5e, 0x6e, 0x6a,
    0x0a, 0x1f, 0x2d, 0x40, 0x53, 0x5e, 0xff, 0x1c, 0xf4, 0x34, 0xf5, 0x2a, 0x43, 0xd5, 0x9d, 0x8f};
static const uint8_t ecdh_p256k1_pkey1[65] = {
    0x04,
    0x6f, 0xcc, 0x37, 0xea, 0x5e, 0x9e, 0x09, 0xfe, 0xc6, 0xc8, 0x3e, 0x5f, 0xbd, 0x7a, 0x74, 0x5e,
    0x3e, 0xee, 0x81, 0xd1, 0x6e, 0xbd, 0x86, 0x1c, 0x9e, 0x66, 0xf5, 0x55, 0x18, 0xc1, 0x97, 0x98,
    0x4e, 0x9f, 0x11, 0x3c, 0x07, 0xf8, 0x75, 0x69, 0x1d, 0xf8, 0xaf, 0xc1, 0x02, 0x94, 0x96, 0xfc,
    0x4c, 0xb9, 0x50, 0x9b, 0x39, 0xdc, 0xd3, 0x8f, 0x25, 0x1a, 0x83, 0x35, 0x9c, 0xc8, 0xb4, 0xf7};
static const uint8_t ecdh_p256k1_skey2[32] = {
    0x88, 0xd3, 0xad, 0x12, 0x93, 0xd7, 0xce, 0x5e, 0xd6, 0x8d, 0xaf, 0xeb, 0xc0, 0xd1, 0x4d, 0xa5,
    0x8b, 0xee, 0x5e, 0x56, 0x70, 0xa1, 0x6d, 0xf7, 0xb4, 0x89, 0x21, 0x18, 0x54, 0xde, 0xab, 0x49};
static const uint8_t ecdh_p256k1_pkey2[65] = {
    0x04,
    0x57, 0xc6, 0x28, 0xc8, 0x6c, 0x52, 0x0d, 0x06, 0x9b, 0x49, 0xef, 0xc0, 0x6f, 0x91, 0xcc, 0xb3,
    0x03, 0xc8, 0x9f, 0x73, 0xf4, 0xa5, 0xf9, 0x14, 0x60, 0x0b, 0xa8, 0x15, 0x73, 0xf5, 0x5a, 0xf7,
    0x12, 0x81, 0xa8, 0x3a, 0xc4, 0xde, 0x68, 0x4a, 0xd5, 0xe5, 0xba, 0x22, 0xd9, 0x65, 0xc9, 0x42,
    0x4b, 0xaa, 0x32, 0x70, 0x56, 0x31, 0xbd, 0xd9, 0xbc, 0x37, 0xdf, 0xbe, 0xe7, 0x7f, 0xc9, 0x88};

static int test_ecdh_p256k1()
{
    psa_key_attributes_t key_attr = PSA_KEY_ATTRIBUTES_INIT;
    psa_key_id_t key1 = 0, key2 = 0;
    uint8_t pub1[65], pub2[65];
    uint8_t sec1[32], sec2[32];
    size_t len1, len2;
    int res = 0;

    psa_set_key_usage_flags(&key_attr, PSA_KEY_USAGE_DERIVE);
    psa_set_key_algorithm(&key_attr, PSA_ALG_ECDH);
    psa_set_key_type(&key_attr, PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_SECP_K1));
    TEST_ASSERT(psa_import_key(&key_attr, ecdh_p256k1_skey1, sizeof ecdh_p256k1_skey1, &key1) == PSA_SUCCESS);
    TEST_ASSERT(psa_import_key(&key_attr, ecdh_p256k1_skey2, sizeof ecdh_p256k1_skey2, &key2) == PSA_SUCCESS);

    TEST_ASSERT(psa_export_public_key(key1, pub1, sizeof pub1, &len1) == PSA_SUCCESS);
    ASSERT_COMPARE(pub1, len1, ecdh_p256k1_pkey1, sizeof ecdh_p256k1_pkey1);
    TEST_ASSERT(psa_export_public_key(key2, pub2, sizeof pub2, &len2) == PSA_SUCCESS);
    ASSERT_COMPARE(pub2, len2, ecdh_p256k1_pkey2, sizeof ecdh_p256k1_pkey2);

    TEST_ASSERT(psa_raw_key_agreement(PSA_ALG_ECDH, key1, pub2, sizeof pub2, sec1, sizeof sec1, &len1) == PSA_SUCCESS);
    TEST_ASSERT(psa_raw_key_agreement(PSA_ALG_ECDH, key2, pub1, sizeof pub1, sec2, sizeof sec2, &len2) == PSA_SUCCESS);
    ASSERT_COMPARE(sec1, len1, sec2, len2);

    res = 1;
exit:
    TEST_ASSERT(psa_destroy_key(key1) == PSA_SUCCESS);
    TEST_ASSERT(psa_destroy_key(key2) == PSA_SUCCESS);

    return res;
}
#endif // PSA_WANT_ALG_ECDH

#ifdef PSA_WANT_ALG_ECDSA
static const uint8_t ecdsa_p256k1_hash[32] = {
    0x4b, 0x68, 0x8d, 0xf4, 0x0b, 0xce, 0xdb, 0xe6, 0x41, 0xdd, 0xb1, 0x6f, 0xf0, 0xa1, 0x84, 0x2d,
    0x9c, 0x67, 0xea, 0x1c, 0x3b, 0xf6, 0x3f, 0x3e, 0x04, 0x71, 0xba, 0xa6, 0x64, 0x53, 0x1d, 0x1a};
static const uint8_t ecdsa_p256k1_key[32] = {
    0xeb, 0xb2, 0xc0, 0x82, 0xfd, 0x77, 0x27, 0x89, 0x0a, 0x28, 0xac, 0x82, 0xf6, 0xbd, 0xf9, 0x7b,
    0xad, 0x8d, 0xe9, 0xf5, 0xd7, 0xc9, 0x02, 0x86, 0x92, 0xde, 0x1a, 0x25, 0x5c, 0xad, 0x3e, 0x0f};
static const uint8_t ecdsa_p256k1_pub[65] = {
    0x04,
    0x77, 0x9d, 0xd1, 0x97, 0xa5, 0xdf, 0x97, 0x7e, 0xd2, 0xcf, 0x6c, 0xb3, 0x1d, 0x82, 0xd4, 0x33,
    0x28, 0xb7, 0x90, 0xdc, 0x6b, 0x3b, 0x7d, 0x44, 0x37, 0xa4, 0x27, 0xbd, 0x58, 0x47, 0xdf, 0xcd,
    0xe9, 0x4b, 0x72, 0x4a, 0x55, 0x5b, 0x6d, 0x01, 0x7b, 0xb7, 0x60, 0x7c, 0x3e, 0x32, 0x81, 0xda,
    0xf5, 0xb1, 0x69, 0x9d, 0x6e, 0xf4, 0x12, 0x49, 0x75, 0xc9, 0x23, 0x7b, 0x91, 0x7d, 0x42, 0x6f};
static const uint8_t ecdsa_p256k1_rnd[32] = {
    0x49, 0xa0, 0xd7, 0xb7, 0x86, 0xec, 0x9c, 0xde, 0x0d, 0x07, 0x21, 0xd7, 0x28, 0x04, 0xbe, 0xfd,
    0x06, 0x57, 0x1c, 0x97, 0x4b, 0x19, 0x1e, 0xfb, 0x42, 0xec, 0xf3, 0x22, 0xba, 0x9d, 0xdd, 0x9a};
static const uint8_t ecdsa_p256k1_sig[64] = {
    0x24, 0x10, 0x97, 0xef, 0xbf, 0x8b, 0x63, 0xbf, 0x14, 0x5c, 0x89, 0x61, 0xdb, 0xdf, 0x10, 0xc3,
    0x10, 0xef, 0xbb, 0x3b, 0x26, 0x76, 0xbb, 0xc0, 0xf8, 0xb0, 0x85, 0x05, 0xc9, 0xe2, 0xf7, 0x95,
    0x02, 0x10, 0x06, 0xb7, 0x83, 0x86, 0x09, 0x33, 0x9e, 0x8b, 0x41, 0x5a, 0x7f, 0x9a, 0xcb, 0x1b,
    0x66, 0x18, 0x28, 0x13, 0x1a, 0xef, 0x1e, 0xcb, 0xc7, 0x95, 0x5d, 0xfb, 0x01, 0xf3, 0xca, 0x0e};

static int test_ecdsa_p256k1()
{
    psa_key_attributes_t key_attr = PSA_KEY_ATTRIBUTES_INIT;
    psa_key_id_t key = 0, pkey = 0;
    uint8_t pub[65], sig[64];
    size_t len;
    int res = 0;

    psa_set_key_usage_flags(&key_attr, PSA_KEY_USAGE_SIGN_HASH);
    psa_set_key_algorithm(&key_attr, PSA_ALG_ECDSA(PSA_ALG_SHA_256));
    psa_set_key_type(&key_attr, PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_SECP_K1));
    TEST_ASSERT(psa_import_key(&key_attr, ecdsa_p256k1_key, sizeof ecdsa_p256k1_key, &key) == PSA_SUCCESS);

    TEST_ASSERT(psa_export_public_key(key, pub, sizeof pub, &len) == PSA_SUCCESS);
    ASSERT_COMPARE(pub, len, ecdsa_p256k1_pub, sizeof ecdsa_p256k1_pub);

    oberon_test_drbg_setup(ecdsa_p256k1_rnd, sizeof ecdsa_p256k1_rnd);
    TEST_ASSERT(psa_sign_hash(key, PSA_ALG_ECDSA(PSA_ALG_SHA_256), ecdsa_p256k1_hash, sizeof ecdsa_p256k1_hash, sig, sizeof sig, &len) == PSA_SUCCESS);
    ASSERT_COMPARE(sig, len, ecdsa_p256k1_sig, sizeof ecdsa_p256k1_sig);

    psa_set_key_usage_flags(&key_attr, PSA_KEY_USAGE_VERIFY_HASH);
    psa_set_key_type(&key_attr, PSA_KEY_TYPE_ECC_PUBLIC_KEY(PSA_ECC_FAMILY_SECP_K1));
    TEST_ASSERT(psa_import_key(&key_attr, ecdsa_p256k1_pub, sizeof ecdsa_p256k1_pub, &pkey) == PSA_SUCCESS);

    TEST_ASSERT(psa_verify_hash(pkey, PSA_ALG_ECDSA(PSA_ALG_SHA_256), ecdsa_p256k1_hash, sizeof ecdsa_p256k1_hash, sig, len) == PSA_SUCCESS);

    res = 1;
exit:
    TEST_ASSERT(psa_destroy_key(key) == PSA_SUCCESS);
    TEST_ASSERT(psa_destroy_key(pkey) == PSA_SUCCESS);

    return res;
}
#endif // PSA_WANT_ALG_ECDSA
#endif // PSA_WANT_ECC_SECP_K1_256


int main(void)
{
    int i, k;

    TEST_ASSERT(psa_crypto_init() == PSA_SUCCESS);

#ifdef PSA_WANT_ALG_JPAKE
    TEST_ASSERT(test_jpake(jpake_psk, sizeof jpake_psk, 1));
    TEST_ASSERT(test_jpake((const uint8_t*)"p", 1, 2));
    TEST_ASSERT(test_jpake((const uint8_t*)"p1234567890123456789012345678901", 32, 3));
    for (i = 1; i <= 88; i++) {
        TEST_ASSERT(test_jpake_err(i));
    }
#endif

#ifdef PSA_WANT_ALG_SPAKE2P_HMAC
    TEST_ASSERT(test_spake2p(PSA_ALG_SPAKE2P_HMAC(PSA_ALG_SHA_256), NULL,         NULL,     NULL,     0));
    TEST_ASSERT(test_spake2p(PSA_ALG_SPAKE2P_HMAC(PSA_ALG_SHA_256), spake2p_zero, NULL,     NULL,     0));
    TEST_ASSERT(test_spake2p(PSA_ALG_SPAKE2P_HMAC(PSA_ALG_SHA_256), spake2p_null, NULL,     NULL,     0));
    TEST_ASSERT(test_spake2p(PSA_ALG_SPAKE2P_HMAC(PSA_ALG_SHA_256), spake2p_hmac, NULL,     NULL,     0));
    TEST_ASSERT(test_spake2p(PSA_ALG_SPAKE2P_HMAC(PSA_ALG_SHA_256), NULL,         "client", "server", 2));
    TEST_ASSERT(test_spake2p(PSA_ALG_SPAKE2P_HMAC(PSA_ALG_SHA_256), spake2p_null, "client", "server", 0));
    TEST_ASSERT(test_spake2p(PSA_ALG_SPAKE2P_HMAC(PSA_ALG_SHA_256), NULL,         "client", "server", 4));
    TEST_ASSERT(test_spake2p(PSA_ALG_SPAKE2P_HMAC(PSA_ALG_SHA_256), spake2p_hmac, "client", "server", 1));
    TEST_ASSERT(test_spake2p(PSA_ALG_SPAKE2P_HMAC(PSA_ALG_SHA_512), NULL,         NULL,     NULL,     0));
    TEST_ASSERT(test_spake2p(PSA_ALG_SPAKE2P_HMAC(PSA_ALG_SHA_512), spake2p_null, NULL,     NULL,     0));
    TEST_ASSERT(test_spake2p(PSA_ALG_SPAKE2P_HMAC(PSA_ALG_SHA_512), spake2p_s512, NULL,     NULL,     0));
    TEST_ASSERT(test_spake2p(PSA_ALG_SPAKE2P_HMAC(PSA_ALG_SHA_512), NULL,         "client", "server", 0));
    TEST_ASSERT(test_spake2p(PSA_ALG_SPAKE2P_HMAC(PSA_ALG_SHA_512), spake2p_zero, "client", "server", 0));
    TEST_ASSERT(test_spake2p(PSA_ALG_SPAKE2P_HMAC(PSA_ALG_SHA_512), spake2p_s512, "client", "server", 0));
    for (i = 1; i <= 44; i++) {
        TEST_ASSERT(test_spake2p_err(i));
    }
#endif

#ifdef PSA_WANT_ALG_SPAKE2P_CMAC
    TEST_ASSERT(test_spake2p(PSA_ALG_SPAKE2P_CMAC(PSA_ALG_SHA_256), NULL,         "client", "server", 0));
    TEST_ASSERT(test_spake2p(PSA_ALG_SPAKE2P_CMAC(PSA_ALG_SHA_256), spake2p_null, "client", "server", 0));
    TEST_ASSERT(test_spake2p(PSA_ALG_SPAKE2P_CMAC(PSA_ALG_SHA_256), spake2p_cmac, "client", "server", 0));
#endif

#ifdef PSA_WANT_ALG_SPAKE2P_MATTER
    TEST_ASSERT(test_spake2p(PSA_ALG_SPAKE2P_MATTER,                spake2p_d_01, "client", "server", 6));
    TEST_ASSERT(test_spake2p(PSA_ALG_SPAKE2P_MATTER,                NULL,         "client", "server", 3));
    TEST_ASSERT(test_spake2p(PSA_ALG_SPAKE2P_MATTER,                NULL,         "client", "server", 5));
#endif

#ifdef PSA_WANT_ALG_SRP_6
    for (i = 1; i <= 6; i++) {
        TEST_ASSERT(test_srp(PSA_ALG_SHA_256, i, "alice", "password123", srp_verifier256));
        TEST_ASSERT(test_srp(PSA_ALG_SHA_512, i, "alice", "password123", srp_verifier512));
    }
    for (i = 1; i <= 46; i++) {
        TEST_ASSERT(test_srp_err(i));
    }
#endif

#ifdef PSA_WANT_ALG_WPA3_SAE
    for (i = 0; i <= 3; i++) {
        TEST_ASSERT(test_sae(local_mac1, peer_mac1, NULL, "mekmitasdigoat", NULL, NULL, 0, 1, i));
    }
    TEST_ASSERT(test_sae(local_mac2, peer_mac2, "byteme", "mekmitasdigoat", "psk4internet", NULL, 0, 1, 4));
    TEST_ASSERT(test_sae(local_mac3, peer_mac3, NULL, "thisisreallysecret", NULL, NULL, 0, 1, 5));
    for (i = 6; i <= 9; i++) {
        TEST_ASSERT(test_sae(local_mac1, peer_mac1, "byteme", "thisisreallysecret", NULL, rejected, sizeof rejected, 77, i));
    }
    for (i = 1; i <= 43; i++) {
        TEST_ASSERT(test_sae_err(NULL, i));
        TEST_ASSERT(test_sae_err("ssid", i));
    }
#endif

#ifdef PSA_WANT_ALG_ML_DSA
    for (k = 0; k < 3; k++) {
        for (i = 0; i <= 8; i++) {
            TEST_ASSERT(test_ml_dsa(i, k));
        }
        for (i = 0; i <= 6; i++) {
            TEST_ASSERT(test_ml_dsa_err(i, k));
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

#ifdef PSA_WANT_ECC_SECP_K1_256
#ifdef PSA_WANT_ALG_ECDH
    TEST_ASSERT(test_ecdh_p256k1());
#endif // PSA_WANT_ALG_ECDH
#ifdef PSA_WANT_ALG_ECDSA
    TEST_ASSERT(test_ecdsa_p256k1());
#endif // PSA_WANT_ALG_ECDSA
#endif // PSA_WANT_ECC_SECP_K1_256

    return 0;
exit:
    (void)i;
    (void)k;
    return 1;
}
