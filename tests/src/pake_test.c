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
#include "test/helpers.h"
#include <test/macros.h>
#include <test/helpers.h>
#include <string.h>

/*
 * JPAKE Tests
 */

#ifdef PSA_WANT_ALG_JPAKE
static int setup_jpake_endpoint(psa_pake_operation_t *op, const uint8_t *user, const uint8_t *peer, const uint8_t *pw, size_t pw_len)
{
    psa_pake_cipher_suite_t suite = PSA_PAKE_CIPHER_SUITE_INIT;
    psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;
    psa_key_id_t pw_key = 0;
    psa_pake_primitive_t jpake_primitive =
        PSA_PAKE_PRIMITIVE(PSA_PAKE_PRIMITIVE_TYPE_ECC, PSA_ECC_FAMILY_SECP_R1, 256);

    psa_pake_cs_set_algorithm(&suite, PSA_ALG_JPAKE);
    psa_pake_cs_set_primitive(&suite, jpake_primitive);
    psa_pake_cs_set_hash(&suite, PSA_ALG_SHA_256);

    psa_set_key_usage_flags(&attributes, PSA_KEY_USAGE_DERIVE);
    psa_set_key_algorithm(&attributes, PSA_ALG_JPAKE);
    psa_set_key_type(&attributes, PSA_KEY_TYPE_PASSWORD);
    TEST_ASSERT(psa_import_key(&attributes, pw, pw_len, &pw_key) == PSA_SUCCESS);

    TEST_ASSERT(psa_pake_setup(op, &suite) == PSA_SUCCESS);
    TEST_ASSERT(psa_pake_set_user(op, user, 6) == PSA_SUCCESS);
    TEST_ASSERT(psa_pake_set_peer(op, peer, 6) == PSA_SUCCESS);
    TEST_ASSERT(psa_pake_set_password_key(op, pw_key) == PSA_SUCCESS);
    TEST_ASSERT(psa_destroy_key(pw_key) == PSA_SUCCESS);

    return 1;
exit:
    psa_destroy_key(pw_key);
    return 0;
}

static int send_message(psa_pake_operation_t *from, psa_pake_operation_t *to, psa_pake_step_t step)
{
    uint8_t data[1024];
    size_t length;

    TEST_ASSERT(psa_pake_output(from, step, data, sizeof data, &length) == PSA_SUCCESS);
    TEST_ASSERT(psa_pake_input(to, step, data, length) == PSA_SUCCESS);

    return 1;
exit:
    return 0;
}

static const uint8_t password[] = "MyPassword";

static int test_jpake(void)
{
    psa_pake_operation_t first = PSA_PAKE_OPERATION_INIT;
    psa_pake_operation_t second = PSA_PAKE_OPERATION_INIT;
    psa_key_derivation_operation_t kdf = PSA_KEY_DERIVATION_OPERATION_INIT;
    uint8_t secret1[32], secret2[32];

    TEST_ASSERT(setup_jpake_endpoint(&first, (const uint8_t *) "client", (const uint8_t *) "server", password, sizeof password - 1));
    TEST_ASSERT(setup_jpake_endpoint(&second, (const uint8_t *) "server", (const uint8_t *) "client", password, sizeof password - 1));

    // Get g1
    TEST_ASSERT(send_message(&first, &second, PSA_PAKE_STEP_KEY_SHARE));
    // Get V1, the ZKP public key for x1
    TEST_ASSERT(send_message(&first, &second, PSA_PAKE_STEP_ZK_PUBLIC));
    // Get r1, the ZKP proof for x1
    TEST_ASSERT(send_message(&first, &second, PSA_PAKE_STEP_ZK_PROOF));
    // Get g2
    TEST_ASSERT(send_message(&first, &second, PSA_PAKE_STEP_KEY_SHARE));
    // Get V2, the ZKP public key for x2
    TEST_ASSERT(send_message(&first, &second, PSA_PAKE_STEP_ZK_PUBLIC));
    // Get r2, the ZKP proof for x2
    TEST_ASSERT(send_message(&first, &second, PSA_PAKE_STEP_ZK_PROOF));

    // Set g3
    TEST_ASSERT(send_message(&second, &first, PSA_PAKE_STEP_KEY_SHARE));
    // Set V3, the ZKP public key for x3
    TEST_ASSERT(send_message(&second, &first, PSA_PAKE_STEP_ZK_PUBLIC));
    // Set r3, the ZKP proof for x3
    TEST_ASSERT(send_message(&second, &first, PSA_PAKE_STEP_ZK_PROOF));
    // Set g4
    TEST_ASSERT(send_message(&second, &first, PSA_PAKE_STEP_KEY_SHARE));
    // Set V4, the ZKP public key for x4
    TEST_ASSERT(send_message(&second, &first, PSA_PAKE_STEP_ZK_PUBLIC));
    // Set r4, the ZKP proof for x4
    TEST_ASSERT(send_message(&second, &first, PSA_PAKE_STEP_ZK_PROOF));

    // Get A
    TEST_ASSERT(send_message(&first, &second, PSA_PAKE_STEP_KEY_SHARE));
    // Get V5, the ZKP public key for x2*s
    TEST_ASSERT(send_message(&first, &second, PSA_PAKE_STEP_ZK_PUBLIC));
    // Get r5, the ZKP proof for x2*s
    TEST_ASSERT(send_message(&first, &second, PSA_PAKE_STEP_ZK_PROOF));

    // Set B
    TEST_ASSERT(send_message(&second, &first, PSA_PAKE_STEP_KEY_SHARE));
    // Set V6, the ZKP public key for x4*s
    TEST_ASSERT(send_message(&second, &first, PSA_PAKE_STEP_ZK_PUBLIC));
    // Set r6, the ZKP proof for x4*s
    TEST_ASSERT(send_message(&second, &first, PSA_PAKE_STEP_ZK_PROOF));

    // Set up the first KDF
    TEST_ASSERT(psa_key_derivation_setup(&kdf, PSA_ALG_TLS12_ECJPAKE_TO_PMS) == PSA_SUCCESS);
    TEST_ASSERT(psa_pake_get_implicit_key(&first, &kdf) == PSA_SUCCESS);
    TEST_ASSERT(psa_key_derivation_output_bytes(&kdf, secret1, sizeof secret1) == PSA_SUCCESS);
    TEST_ASSERT(psa_key_derivation_abort(&kdf) == PSA_SUCCESS);

    // Set up the second KDF
    TEST_ASSERT(psa_key_derivation_setup(&kdf, PSA_ALG_TLS12_ECJPAKE_TO_PMS) == PSA_SUCCESS);
    TEST_ASSERT(psa_pake_get_implicit_key(&second, &kdf) == PSA_SUCCESS);
    TEST_ASSERT(psa_key_derivation_output_bytes(&kdf, secret2, sizeof secret2) == PSA_SUCCESS);
    TEST_ASSERT(psa_key_derivation_abort(&kdf) == PSA_SUCCESS);

    ASSERT_COMPARE(secret1, sizeof secret1, secret2, sizeof secret2);

    return 1;
exit:
    return 0;
}
#endif // PSA_WANT_ALG_JPAKE


/*
* SPAKE2+ Tests
*/
#ifdef PSA_WANT_ALG_SPAKE2P

static const uint8_t w01_sha256[] = {
    0xbb, 0x8e, 0x1b, 0xbc, 0xf3, 0xc4, 0x8f, 0x62, 0xc0, 0x8d, 0xb2, 0x43, 0x65, 0x2a, 0xe5, 0x5d,
    0x3e, 0x55, 0x86, 0x05, 0x3f, 0xca, 0x77, 0x10, 0x29, 0x94, 0xf2, 0x3a, 0xd9, 0x54, 0x91, 0xb3,
    0x7e, 0x94, 0x5f, 0x34, 0xd7, 0x87, 0x85, 0xb8, 0xa3, 0xef, 0x44, 0xd0, 0xdf, 0x5a, 0x1a, 0x97,
    0xd6, 0xb3, 0xb4, 0x60, 0x40, 0x9a, 0x34, 0x5c, 0xa7, 0x83, 0x03, 0x87, 0xa7, 0x4b, 0x1d, 0xba};
static const uint8_t w0L_sha256[] = {
    0xbb, 0x8e, 0x1b, 0xbc, 0xf3, 0xc4, 0x8f, 0x62, 0xc0, 0x8d, 0xb2, 0x43, 0x65, 0x2a, 0xe5, 0x5d,
    0x3e, 0x55, 0x86, 0x05, 0x3f, 0xca, 0x77, 0x10, 0x29, 0x94, 0xf2, 0x3a, 0xd9, 0x54, 0x91, 0xb3,
    0x04,
    0xeb, 0x7c, 0x9d, 0xb3, 0xd9, 0xa9, 0xeb, 0x1f, 0x8a, 0xda, 0xb8, 0x1b, 0x57, 0x94, 0xc1, 0xf1,
    0x3a, 0xe3, 0xe2, 0x25, 0xef, 0xbe, 0x91, 0xea, 0x48, 0x74, 0x25, 0x85, 0x4c, 0x7f, 0xc0, 0x0f,
    0x00, 0xbf, 0xed, 0xcb, 0xd0, 0x9b, 0x24, 0x00, 0x14, 0x2d, 0x40, 0xa1, 0x4f, 0x20, 0x64, 0xef,
    0x31, 0xdf, 0xaa, 0x90, 0x3b, 0x91, 0xd1, 0xfa, 0xea, 0x70, 0x93, 0xd8, 0x35, 0x96, 0x6e, 0xfd};


static int setup_spake2p_endpoint(psa_pake_operation_t *op,
    const uint8_t *user, const uint8_t *peer, psa_pake_role_t role,
    const uint8_t *w01, size_t w_len, psa_algorithm_t hash_alg)
{
    psa_pake_cipher_suite_t suite = PSA_PAKE_CIPHER_SUITE_INIT;
    psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;
    psa_key_id_t pw_key = 0;
    psa_pake_primitive_t spake2p_primitive =
        PSA_PAKE_PRIMITIVE(PSA_PAKE_PRIMITIVE_TYPE_ECC, PSA_ECC_FAMILY_SECP_R1, 256);

    psa_pake_cs_set_algorithm(&suite, PSA_ALG_SPAKE2P);
    psa_pake_cs_set_primitive(&suite, spake2p_primitive);
    psa_pake_cs_set_hash(&suite, hash_alg);

    psa_set_key_usage_flags(&attributes, PSA_KEY_USAGE_DERIVE);
    psa_set_key_algorithm(&attributes, PSA_ALG_SPAKE2P);
    psa_set_key_type(&attributes, PSA_KEY_TYPE_PASSWORD_HASH);
    TEST_ASSERT(psa_import_key(&attributes, w01, w_len, &pw_key) == PSA_SUCCESS);

    TEST_ASSERT(psa_pake_setup(op, &suite) == PSA_SUCCESS);
    TEST_ASSERT(psa_pake_set_role(op, role) == PSA_SUCCESS);
    if (role == PSA_PAKE_ROLE_CLIENT) {
        if (user) {
            TEST_ASSERT(psa_pake_set_user(op, user, 6) == PSA_SUCCESS);
        } else {
            TEST_ASSERT(psa_pake_set_user(op, NULL, 0) == PSA_SUCCESS);
        }
        if (peer) {
            TEST_ASSERT(psa_pake_set_peer(op, peer, 6) == PSA_SUCCESS);
        } else {
            TEST_ASSERT(psa_pake_set_peer(op, NULL, 0) == PSA_SUCCESS);
        }
    } else {
        if (peer) {
            TEST_ASSERT(psa_pake_set_peer(op, peer, 6) == PSA_SUCCESS);
        } else {
            TEST_ASSERT(psa_pake_set_peer(op, NULL, 0) == PSA_SUCCESS);
        }
        if (user) {
            TEST_ASSERT(psa_pake_set_user(op, user, 6) == PSA_SUCCESS);
        } else {
            TEST_ASSERT(psa_pake_set_user(op, NULL, 0) == PSA_SUCCESS);
        }
    }
    TEST_ASSERT(psa_pake_set_password_key(op, pw_key) == PSA_SUCCESS);
    TEST_ASSERT(psa_destroy_key(pw_key) == PSA_SUCCESS);

    return 1;
exit:
    psa_destroy_key(pw_key);
    return 0;
}

static int test_spake2p(const uint8_t *context, size_t context_len, const uint8_t *user, const uint8_t *peer)
{
    psa_pake_operation_t client = PSA_PAKE_OPERATION_INIT;
    psa_pake_operation_t server = PSA_PAKE_OPERATION_INIT;
    psa_key_derivation_operation_t kdf = PSA_KEY_DERIVATION_OPERATION_INIT;
    uint8_t secret1[32], secret2[32];

    TEST_ASSERT(setup_spake2p_endpoint(&client, user, peer, PSA_PAKE_ROLE_CLIENT, w01_sha256, sizeof w01_sha256, PSA_ALG_SHA_256));
    TEST_ASSERT(setup_spake2p_endpoint(&server, peer, user, PSA_PAKE_ROLE_SERVER, w0L_sha256, sizeof w0L_sha256, PSA_ALG_SHA_256));

    if (context) {
        TEST_ASSERT(psa_pake_input(&client, PSA_PAKE_STEP_CONTEXT, context, context_len) == PSA_SUCCESS);
        TEST_ASSERT(psa_pake_input(&server, PSA_PAKE_STEP_CONTEXT, context, context_len) == PSA_SUCCESS);
    }

    // shareP
    TEST_ASSERT(send_message(&client, &server, PSA_PAKE_STEP_KEY_SHARE));
    // shareV
    TEST_ASSERT(send_message(&server, &client, PSA_PAKE_STEP_KEY_SHARE));
    // confirmP
    TEST_ASSERT(send_message(&server, &client, PSA_PAKE_STEP_CONFIRM));
    // confirmV
    TEST_ASSERT(send_message(&client, &server, PSA_PAKE_STEP_CONFIRM));

    // Set up the first KDF
    TEST_ASSERT(psa_key_derivation_setup(&kdf, PSA_ALG_HKDF(PSA_ALG_SHA_256)) == PSA_SUCCESS);
    TEST_ASSERT(psa_key_derivation_input_bytes(&kdf, PSA_KEY_DERIVATION_INPUT_INFO, (const uint8_t *) "Info", 4) == PSA_SUCCESS);
    TEST_ASSERT(psa_pake_get_implicit_key(&client, &kdf) == PSA_SUCCESS);
    TEST_ASSERT(psa_key_derivation_output_bytes(&kdf, secret1, sizeof secret1) == PSA_SUCCESS);
    TEST_ASSERT(psa_key_derivation_abort(&kdf) == PSA_SUCCESS);

    // Set up the second KDF
    TEST_ASSERT(psa_key_derivation_setup(&kdf, PSA_ALG_HKDF(PSA_ALG_SHA_256)) == PSA_SUCCESS);
    TEST_ASSERT(psa_key_derivation_input_bytes(&kdf, PSA_KEY_DERIVATION_INPUT_INFO, (const uint8_t *) "Info", 4) == PSA_SUCCESS);
    TEST_ASSERT(psa_pake_get_implicit_key(&server, &kdf) == PSA_SUCCESS);
    TEST_ASSERT(psa_key_derivation_output_bytes(&kdf, secret2, sizeof secret2) == PSA_SUCCESS);
    TEST_ASSERT(psa_key_derivation_abort(&kdf) == PSA_SUCCESS);

    ASSERT_COMPARE(secret1, sizeof secret1, secret2, sizeof secret2);

    return 1;
exit:
    return 0;
}

static int test_spake2p_sha512(const uint8_t *context, size_t context_len, const uint8_t *user, const uint8_t *peer)
{
    psa_pake_operation_t client = PSA_PAKE_OPERATION_INIT;
    psa_pake_operation_t server = PSA_PAKE_OPERATION_INIT;
    psa_key_derivation_operation_t kdf = PSA_KEY_DERIVATION_OPERATION_INIT;
    uint8_t secret1[32], secret2[32];

    TEST_ASSERT(setup_spake2p_endpoint(&client, user, peer, PSA_PAKE_ROLE_CLIENT, w01_sha256, sizeof w01_sha256, PSA_ALG_SHA_512));
    TEST_ASSERT(setup_spake2p_endpoint(&server, peer, user, PSA_PAKE_ROLE_SERVER, w0L_sha256, sizeof w0L_sha256, PSA_ALG_SHA_512));

    if (context) {
        TEST_ASSERT(psa_pake_input(&client, PSA_PAKE_STEP_CONTEXT, context, context_len) == PSA_SUCCESS);
        TEST_ASSERT(psa_pake_input(&server, PSA_PAKE_STEP_CONTEXT, context, context_len) == PSA_SUCCESS);
    }

    // shareP
    TEST_ASSERT(send_message(&client, &server, PSA_PAKE_STEP_KEY_SHARE));
    // shareV
    TEST_ASSERT(send_message(&server, &client, PSA_PAKE_STEP_KEY_SHARE));
    // confirmP
    TEST_ASSERT(send_message(&server, &client, PSA_PAKE_STEP_CONFIRM));
    // confirmV
    TEST_ASSERT(send_message(&client, &server, PSA_PAKE_STEP_CONFIRM));

    // Set up the first KDF
    TEST_ASSERT(psa_key_derivation_setup(&kdf, PSA_ALG_HKDF(PSA_ALG_SHA_256)) == PSA_SUCCESS);
    TEST_ASSERT(psa_key_derivation_input_bytes(&kdf, PSA_KEY_DERIVATION_INPUT_INFO, (const uint8_t *) "Info", 4) == PSA_SUCCESS);
    TEST_ASSERT(psa_pake_get_implicit_key(&client, &kdf) == PSA_SUCCESS);
    TEST_ASSERT(psa_key_derivation_output_bytes(&kdf, secret1, sizeof secret1) == PSA_SUCCESS);
    TEST_ASSERT(psa_key_derivation_abort(&kdf) == PSA_SUCCESS);

    // Set up the second KDF
    TEST_ASSERT(psa_key_derivation_setup(&kdf, PSA_ALG_HKDF(PSA_ALG_SHA_256)) == PSA_SUCCESS);
    TEST_ASSERT(psa_key_derivation_input_bytes(&kdf, PSA_KEY_DERIVATION_INPUT_INFO, (const uint8_t *) "Info", 4) == PSA_SUCCESS);
    TEST_ASSERT(psa_pake_get_implicit_key(&server, &kdf) == PSA_SUCCESS);
    TEST_ASSERT(psa_key_derivation_output_bytes(&kdf, secret2, sizeof secret2) == PSA_SUCCESS);
    TEST_ASSERT(psa_key_derivation_abort(&kdf) == PSA_SUCCESS);

    ASSERT_COMPARE(secret1, sizeof secret1, secret2, sizeof secret2);

    return 1;
exit:
    return 0;
}
#endif // PSA_WANT_ALG_SPAKE2P


/*
* SRP-6-3072-SHA512 Tests
*/

#ifdef PSA_WANT_ALG_SRP_6

// Salt (s)
static const uint8_t test_salt[16] = {
    0xBE, 0xB2, 0x53, 0x79, 0xD1, 0xA8, 0x58, 0x1E, 0xB5, 0xA7, 0x27, 0x67, 0x3A, 0x24, 0x41, 0xEE};
// Verifier (v)
static const uint8_t test_verifier[384] = {
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

static int setup_srp_endpoint(psa_pake_operation_t *op,
    psa_pake_role_t role, psa_algorithm_t hash_alg)
{
    psa_pake_cipher_suite_t suite = PSA_PAKE_CIPHER_SUITE_INIT;
    psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;
    psa_key_id_t pw_key = 0;
    psa_pake_primitive_t srp_primitive =
        PSA_PAKE_PRIMITIVE(PSA_PAKE_PRIMITIVE_TYPE_DH, PSA_DH_FAMILY_RFC3526, 3072);
    psa_hash_operation_t hash_op = PSA_HASH_OPERATION_INIT;
    uint8_t hash[64];
    size_t hash_len;

    psa_pake_cs_set_algorithm(&suite, PSA_ALG_SRP_6);
    psa_pake_cs_set_primitive(&suite, srp_primitive);
    psa_pake_cs_set_hash(&suite, hash_alg);

    psa_set_key_usage_flags(&attributes, PSA_KEY_USAGE_DERIVE);
    psa_set_key_algorithm(&attributes, PSA_ALG_SRP_6);
    psa_set_key_type(&attributes, PSA_KEY_TYPE_PASSWORD_HASH);

    if (role == PSA_PAKE_ROLE_CLIENT) {
        // h = SHA512(salt | SHA512(user | ":" | pass))
        TEST_ASSERT(psa_hash_setup(&hash_op, hash_alg) == PSA_SUCCESS);
        TEST_ASSERT(psa_hash_update(&hash_op, (const uint8_t *) "alice:password123", 17) == PSA_SUCCESS);
        TEST_ASSERT(psa_hash_finish(&hash_op, hash, sizeof hash, &hash_len) == PSA_SUCCESS);

        TEST_ASSERT(psa_hash_setup(&hash_op, hash_alg) == PSA_SUCCESS);
        TEST_ASSERT(psa_hash_update(&hash_op, test_salt, sizeof test_salt) == PSA_SUCCESS);
        TEST_ASSERT(psa_hash_update(&hash_op, hash, hash_len) == PSA_SUCCESS);
        TEST_ASSERT(psa_hash_finish(&hash_op, hash, sizeof hash, &hash_len) == PSA_SUCCESS);

        TEST_ASSERT(psa_import_key(&attributes, hash, hash_len, &pw_key) == PSA_SUCCESS);
    } else {
        TEST_ASSERT(psa_import_key(&attributes, test_verifier, sizeof test_verifier, &pw_key) == PSA_SUCCESS);
    }

    TEST_ASSERT(psa_pake_setup(op, &suite) == PSA_SUCCESS);
    TEST_ASSERT(psa_pake_set_role(op, role) == PSA_SUCCESS);
    TEST_ASSERT(psa_pake_set_user(op, (const uint8_t *) "alice", 5) == PSA_SUCCESS);
    TEST_ASSERT(psa_pake_set_password_key(op, pw_key) == PSA_SUCCESS);
    TEST_ASSERT(psa_destroy_key(pw_key) == PSA_SUCCESS);

    return 1;
exit:
    psa_destroy_key(pw_key);
    psa_hash_abort(&hash_op);
    return 0;
}

static int test_srp(int seq)
{
    psa_pake_operation_t client = PSA_PAKE_OPERATION_INIT;
    psa_pake_operation_t server = PSA_PAKE_OPERATION_INIT;
    psa_key_derivation_operation_t kdf = PSA_KEY_DERIVATION_OPERATION_INIT;
    uint8_t secret1[32], secret2[32];

    TEST_ASSERT(setup_srp_endpoint(&client, PSA_PAKE_ROLE_CLIENT, PSA_ALG_SHA_512));
    TEST_ASSERT(setup_srp_endpoint(&server, PSA_PAKE_ROLE_SERVER, PSA_ALG_SHA_512));

    TEST_ASSERT(psa_pake_input(&server, PSA_PAKE_STEP_SALT, test_salt, sizeof test_salt) == PSA_SUCCESS);

    switch (seq) {
    case 1:
        TEST_ASSERT(psa_pake_input(&client, PSA_PAKE_STEP_SALT, test_salt, sizeof test_salt) == PSA_SUCCESS);
        TEST_ASSERT(send_message(&client, &server, PSA_PAKE_STEP_KEY_SHARE)); // client key
        TEST_ASSERT(send_message(&server, &client, PSA_PAKE_STEP_KEY_SHARE)); // server key
        break;
    case 2:
        TEST_ASSERT(send_message(&client, &server, PSA_PAKE_STEP_KEY_SHARE)); // client key
        TEST_ASSERT(psa_pake_input(&client, PSA_PAKE_STEP_SALT, test_salt, sizeof test_salt) == PSA_SUCCESS);
        TEST_ASSERT(send_message(&server, &client, PSA_PAKE_STEP_KEY_SHARE)); // server key
        break;
    case 3:
        TEST_ASSERT(psa_pake_input(&client, PSA_PAKE_STEP_SALT, test_salt, sizeof test_salt) == PSA_SUCCESS);
        TEST_ASSERT(send_message(&server, &client, PSA_PAKE_STEP_KEY_SHARE)); // server key
        TEST_ASSERT(send_message(&client, &server, PSA_PAKE_STEP_KEY_SHARE)); // client key
        break;
    }

    TEST_ASSERT(send_message(&client, &server, PSA_PAKE_STEP_CONFIRM)); // client proof
    TEST_ASSERT(send_message(&server, &client, PSA_PAKE_STEP_CONFIRM)); // server proof

    // Set up the first KDF
    TEST_ASSERT(psa_key_derivation_setup(&kdf, PSA_ALG_HKDF(PSA_ALG_SHA_256)) == PSA_SUCCESS);
    TEST_ASSERT(psa_key_derivation_input_bytes(&kdf, PSA_KEY_DERIVATION_INPUT_INFO, (const uint8_t *) "Info", 4) == PSA_SUCCESS);
    TEST_ASSERT(psa_pake_get_implicit_key(&client, &kdf) == PSA_SUCCESS);
    TEST_ASSERT(psa_key_derivation_output_bytes(&kdf, secret1, sizeof secret1) == PSA_SUCCESS);
    TEST_ASSERT(psa_key_derivation_abort(&kdf) == PSA_SUCCESS);

    // Set up the second KDF
    TEST_ASSERT(psa_key_derivation_setup(&kdf, PSA_ALG_HKDF(PSA_ALG_SHA_256)) == PSA_SUCCESS);
    TEST_ASSERT(psa_key_derivation_input_bytes(&kdf, PSA_KEY_DERIVATION_INPUT_INFO, (const uint8_t *) "Info", 4) == PSA_SUCCESS);
    TEST_ASSERT(psa_pake_get_implicit_key(&server, &kdf) == PSA_SUCCESS);
    TEST_ASSERT(psa_key_derivation_output_bytes(&kdf, secret2, sizeof secret2) == PSA_SUCCESS);
    TEST_ASSERT(psa_key_derivation_abort(&kdf) == PSA_SUCCESS);

    ASSERT_COMPARE(secret1, sizeof secret1, secret2, sizeof secret2);

    return 1;
exit:
    return 0;
}
#endif // PSA_WANT_ALG_SRP_6


int main(void)
{
    TEST_ASSERT(psa_crypto_init() == PSA_SUCCESS);

#ifdef PSA_WANT_ALG_JPAKE
    TEST_ASSERT(test_jpake());
#endif

#ifdef PSA_WANT_ALG_SPAKE2P
    TEST_ASSERT(test_spake2p(NULL, 0, NULL, NULL));
    TEST_ASSERT(test_spake2p_sha512(NULL, 0, NULL, NULL));
    TEST_ASSERT(test_spake2p(NULL, 0, (const uint8_t *)"client", (const uint8_t *)"server"));
    TEST_ASSERT(test_spake2p_sha512(NULL, 0, (const uint8_t *)"client", (const uint8_t *)"server"));
    TEST_ASSERT(test_spake2p((const uint8_t *)"SPAKE2+-P256-SHA256-HKDF-HMAC-SHA256", 36, NULL, NULL));
    TEST_ASSERT(test_spake2p_sha512((const uint8_t *)"SPAKE2+-P256-SHA256-HKDF-HMAC-SHA256", 36, NULL, NULL));
    TEST_ASSERT(test_spake2p((const uint8_t *)"SPAKE2+-P256-SHA256-HKDF-HMAC-SHA256", 36, (const uint8_t *)"client", (const uint8_t *)"server"));
    TEST_ASSERT(test_spake2p_sha512((const uint8_t *)"SPAKE2+-P256-SHA256-HKDF-HMAC-SHA256", 36, (const uint8_t *)"client", (const uint8_t *)"server"));
#endif

#ifdef PSA_WANT_ALG_SRP_6
    TEST_ASSERT(test_srp(1));
    TEST_ASSERT(test_srp(2));
    TEST_ASSERT(test_srp(3));
#endif

    return 0;
exit:
    return 1;
}
