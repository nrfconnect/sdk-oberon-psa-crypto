/** @file
 * Copyright (c) 2019-2025, Arm Limited or its affiliates. All rights reserved.
 * SPDX-License-Identifier : Apache-2.0
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
**/

#include "test_crypto_common.h"

typedef struct {
    char                    test_desc[75];
    psa_key_type_t          type;
    const uint8_t          *data;
    size_t                  data_length;
    psa_key_usage_t         usage_flags;
    psa_algorithm_t         alg;
    psa_algorithm_t         setup_alg;
    const uint8_t          *input;
    size_t                  input_length;
    const uint8_t          *signature;
    size_t                  signature_length;
    psa_status_t            expected_status;
} test_data;

#if ((defined(ARCH_TEST_RSA_1024) && (defined(ARCH_TEST_RSA_PKCS1V15_SIGN) || \
      defined(ARCH_TEST_RSA_PKCS1V15_SIGN_RAW) || defined(ARCH_TEST_SHA256))) || \
      (defined(ARCH_TEST_SHA256) && (defined(ARCH_TEST_DETERMINISTIC_ECDSA) || \
      defined(ARCH_TEST_ECC_CURVE_SECP256R1))))

static const test_data check1[] = {
#ifdef ARCH_TEST_RSA_1024
#ifdef ARCH_TEST_RSA_PKCS1V15_SIGN_RAW
{
    .test_desc        = "Test psa_verify_message - RSA KEY_PAIR PKCS1V15 RAW\n",
    .type             = PSA_KEY_TYPE_RSA_KEY_PAIR,
    .data             = rsa_128_key_pair,
    .data_length      = 610,
    .usage_flags      = PSA_KEY_USAGE_VERIFY_MESSAGE,
    .alg              = PSA_ALG_RSA_PKCS1V15_SIGN_RAW,
    .input            = &hash_input,
    .input_length     = sizeof(hash_input),
    .signature        = signature_4,
    .signature_length = 128,
    .expected_status  = PSA_ERROR_INVALID_ARGUMENT
},

{
    .test_desc        = "Test psa_verify_message - RSA Public Key PKCS1V15 RAW\n",
    .type             = PSA_KEY_TYPE_RSA_PUBLIC_KEY,
    .data             = rsa_128_key_data,
    .data_length      = 140,
    .usage_flags      = PSA_KEY_USAGE_VERIFY_MESSAGE,
    .alg              = PSA_ALG_RSA_PKCS1V15_SIGN_RAW,
    .input            = &hash_input,
    .input_length     = sizeof(hash_input),
    .signature        = signature_4,
    .signature_length = 128,
    .expected_status  = PSA_ERROR_INVALID_ARGUMENT
},
#endif

#ifdef ARCH_TEST_RSA_PKCS1V15_SIGN
#ifdef ARCH_TEST_SHA256
{
    .test_desc        = "Test psa_verify_message - RSA KEY_PAIR PKCS1V15 SHA-256\n",
    .type             = PSA_KEY_TYPE_RSA_KEY_PAIR,
    .data             = rsa_128_key_pair,
    .data_length      = 610,
    .usage_flags      = PSA_KEY_USAGE_VERIFY_MESSAGE,
    .alg              = PSA_ALG_RSA_PKCS1V15_SIGN(PSA_ALG_SHA_256),
    .input            = &hash_input,
    .input_length     = sizeof(hash_input),
    .signature        = NULL,
    .signature_length = 0,
    .expected_status  = PSA_ERROR_INVALID_SIGNATURE
},
#endif
#endif
#endif

#ifdef ARCH_TEST_SHA256
#ifdef ARCH_TEST_DETERMINISTIC_ECDSA
#ifdef ARCH_TEST_ECC_CURVE_SECP256R1
{
    .test_desc        = "Test psa_verify_message - ECDSA KEY_PAIR SECP256R1 SHA-256\n",
    .type             = PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_SECP_R1),
    .data             = ec_keypair_deterministic,
    .data_length      = 32,
    .usage_flags      = PSA_KEY_USAGE_VERIFY_MESSAGE,
    .alg              = PSA_ALG_DETERMINISTIC_ECDSA(PSA_ALG_SHA_256),
    .input            = &hash_input,
    .input_length     = sizeof(hash_input),
    .signature        = signature_6,
    .signature_length = 64,
    .expected_status  = PSA_SUCCESS
},

{
    .test_desc        = "Test psa_verify_message - ECDSA Public Key SECP256R1 SHA-256\n",
    .type             = PSA_KEY_TYPE_ECC_PUBLIC_KEY(PSA_ECC_FAMILY_SECP_R1),
    .data             = ec_key_data,
    .data_length      = 65,
    .usage_flags      = PSA_KEY_USAGE_VERIFY_MESSAGE,
    .alg              = PSA_ALG_DETERMINISTIC_ECDSA(PSA_ALG_SHA_256),
    .input            = &hash_input,
    .input_length     = sizeof(hash_input),
    .signature        = signature_6,
    .signature_length = 64,
    .expected_status  = PSA_SUCCESS
},
#endif
#endif
#endif

#ifdef ARCH_TEST_RSA_1024
#ifdef ARCH_TEST_RSA_PKCS1V15_SIGN_RAW
{
    .test_desc        = "Test psa_verify_message - Small output buffer\n",
    .type             = PSA_KEY_TYPE_RSA_KEY_PAIR,
    .data             = rsa_128_key_pair,
    .data_length      = 610,
    .usage_flags      = PSA_KEY_USAGE_VERIFY_MESSAGE,
    .alg              = PSA_ALG_RSA_PKCS1V15_SIGN(PSA_ALG_SHA_256),
    .input            = &hash_input,
    .input_length     = sizeof(hash_input),
    .signature        = signature_4,
    .signature_length = 127,
    .expected_status  = PSA_ERROR_INVALID_SIGNATURE
},

#ifdef ARCH_TEST_SHA256
{
    .test_desc        = "Test psa_verify_message - Invalid algorithm\n",
    .type             = PSA_KEY_TYPE_RSA_KEY_PAIR,
    .data             = rsa_128_key_pair,
    .data_length      = 610,
    .usage_flags      = PSA_KEY_USAGE_VERIFY_MESSAGE,
    .alg              = PSA_ALG_SHA_256,
    .input            = &hash_input,
    .input_length     = sizeof(hash_input),
    .signature        = signature_4,
    .signature_length = 128,
    .expected_status  = PSA_ERROR_INVALID_ARGUMENT
},
#endif

#ifdef ARCH_TEST_AES_128
{
    .test_desc        = "Test psa_verify_message - Invalid key type (AES Key)\n",
    .type             = PSA_KEY_TYPE_AES,
    .data             = key_data,
    .data_length      = AES_16B_KEY_SIZE,
    .usage_flags      = PSA_KEY_USAGE_VERIFY_MESSAGE,
    .alg              = PSA_ALG_RSA_PKCS1V15_SIGN_RAW,
    .input            = &hash_input,
    .input_length     = sizeof(hash_input),
    .signature        = signature_4,
    .signature_length = 128,
    .expected_status  = PSA_ERROR_INVALID_ARGUMENT
},
#endif

{
    .test_desc        = "Test psa_verify_message - Invalid usage\n",
    .type             = PSA_KEY_TYPE_RSA_KEY_PAIR,
    .data             = rsa_128_key_pair,
    .data_length      = 610,
    .usage_flags      = PSA_KEY_USAGE_ENCRYPT,
    .alg              = PSA_ALG_DETERMINISTIC_ECDSA(PSA_ALG_SHA_256),
    .input            = &hash_input,
    .input_length     = sizeof(hash_input),
    .signature        = signature_4,
    .signature_length = 128,
    .expected_status  = PSA_ERROR_NOT_PERMITTED
},

{
    .test_desc        = "Test psa_verify_message - Wrong message size\n",
    .type             = PSA_KEY_TYPE_RSA_KEY_PAIR,
    .data             = rsa_128_key_pair,
    .data_length      = 610,
    .usage_flags      = PSA_KEY_USAGE_VERIFY_MESSAGE,
    .alg              = PSA_ALG_RSA_PKCS1V15_SIGN_RAW,
    .input            = &hash_input,
    .input_length     = sizeof(hash_input)-1,
    .signature        = signature_4,
    .signature_length = 128,
    .expected_status  = PSA_ERROR_INVALID_ARGUMENT
},

{
    .test_desc        = "Test psa_verify_message - Wrong signature\n",
    .type             = PSA_KEY_TYPE_RSA_KEY_PAIR,
    .data             = rsa_128_key_pair,
    .data_length      = 610,
    .usage_flags      = PSA_KEY_USAGE_VERIFY_MESSAGE,
    .alg              = PSA_ALG_RSA_PKCS1V15_SIGN(PSA_ALG_SHA_256),
    .input            = &hash_input,
    .input_length     = sizeof(hash_input),
    .signature        = signature_4_invalid,
    .signature_length = 128,
    .expected_status  = PSA_ERROR_INVALID_SIGNATURE
},

{
    .test_desc        = "Test psa_verify_message - Wrong signature size\n",
    .type             = PSA_KEY_TYPE_RSA_KEY_PAIR,
    .data             = rsa_128_key_pair,
    .data_length      = 610,
    .usage_flags      = PSA_KEY_USAGE_VERIFY_MESSAGE,
    .alg              = PSA_ALG_RSA_PKCS1V15_SIGN(PSA_ALG_SHA_256),
    .input            = &hash_input,
    .input_length     = sizeof(hash_input),
    .signature        = signature_4,
    .signature_length = 129,
    .expected_status  = PSA_ERROR_INVALID_SIGNATURE
},
#endif
#endif

#ifdef ARCH_TEST_TWISTED_EDWARDS
{
    .test_desc                 = "Test psa_verify_message - EDDSA  Ed25519\n",
    .type                      = PSA_KEY_TYPE_ECC_PUBLIC_KEY(PSA_ECC_FAMILY_TWISTED_EDWARDS),
    .data                      = eddsa_25519_pubkey,
    .data_length               = 32,
    .usage_flags               = PSA_KEY_USAGE_VERIFY_MESSAGE,
    .alg                       = PSA_ALG_PURE_EDDSA,
    .input                     = eddsa_25519_message,
    .input_length              = 1,
    .signature                 = eddsa_25519_signature,
    .signature_length          = 64,
    .expected_status           = PSA_SUCCESS
},

{
    .test_desc                 = "Test psa_verify_message - EDDSA  448PH\n",
    .type                      = PSA_KEY_TYPE_ECC_PUBLIC_KEY(PSA_ECC_FAMILY_TWISTED_EDWARDS),
    .data                      = eddsa_448_pubkey,
    .data_length               = 57,
    .usage_flags               = PSA_KEY_USAGE_VERIFY_MESSAGE,
    .alg                       = PSA_ALG_ED448PH,
    .input                     = eddsa_448_message,
    .input_length              = 3,
    .signature                 = eddsa_448_signature,
    .signature_length          = 114,
    .expected_status           = PSA_SUCCESS
},
#endif

};
#endif
