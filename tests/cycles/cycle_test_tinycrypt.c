/*
 * Copyright (c) 2016 - 2026 Nordic Semiconductor ASA
 * Copyright (c) since 2020 Oberon microsystems AG
 *
 * SPDX-License-Identifier: LicenseRef-Nordic-5-Clause
 */


#include <string.h>
#include <tinycrypt/constants.h>
#include <tinycrypt/utils.h>
#include <tinycrypt/sha256.h>
#include <tinycrypt/sha512.h>
#include <tinycrypt/hmac.h>
#include <tinycrypt/aes.h>
#include <tinycrypt/ctr_mode.h>
#include <tinycrypt/ccm_mode.h>
#include <tinycrypt/ecc_dsa.h>
#include <tinycrypt/ecc_dh.h>

#include "test_cycles.h"
#include "psa/crypto_config.h"

static const uint8_t key_data[32] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16,
                            17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32};

static const uint8_t ecc_key_pair[] = { 
    0x04, 0x51, 0x5c, 0x3d, 0x6e, 0xb9, 0xe3, 0x96, 0xb9, 0x04, 0xd3, 0xfe, 0xca, 0x7f, 0x54, 0xfd, 
    0xcd, 0x0c, 0xc1, 0xe9, 0x97, 0xbf, 0x37, 0x5d, 0xca, 0x51, 0x5a, 0xd0, 0xa6, 0xc3, 0xb4, 0x03, 
    0x5f, 0x45, 0x36, 0xbe, 0x3a, 0x50, 0xf3, 0x18, 0xfb, 0xf9, 0xa5, 0x47, 0x59, 0x02, 0xa2, 0x21, 
    0x50, 0x2b, 0xef, 0x0d, 0x57, 0xe0, 0x8c, 0x53, 0xb2, 0xcc, 0x0a, 0x56, 0xf1, 0x7d, 0x9f, 0x93, 
    0x54};
	
static const uint8_t ecc_sig[] = { 
    0xf2, 0x6a, 0xe0, 0xa2, 0x8c, 0xf5, 0x0c, 0x6c, 0x25, 0x82, 0xff, 0x1b, 0xac, 0x23, 0x10, 0xe1, 
    0x98, 0xbb, 0x38, 0x12, 0x0b, 0x30, 0xb0, 0xdd, 0x6c, 0x54, 0x7e, 0xde, 0x9a, 0x28, 0xc0, 0x1e, 
    0x9f, 0x1f, 0xc7, 0x85, 0x7a, 0xa7, 0x20, 0xe2, 0x02, 0x4b, 0x3c, 0x81, 0x80, 0xe5, 0xf2, 0x7c, 
    0x19, 0x92, 0xbc, 0x29, 0x30, 0xa9, 0xd5, 0x14, 0xa0, 0x5d, 0x0c, 0xb2, 0xf3, 0xe1, 0x68, 0x73};

static const uint8_t msg_data[1024] = "the brown fox jumps over the dog" 
                                        "the brown fox jumps over the dog"
                                        "the brown fox jumps over the dog"
                                        "the brown fox jumps over the dog"
                                        "the brown fox jumps over the dog"
                                        "the brown fox jumps over the dog"
                                        "the brown fox jumps over the dog"
                                        "the brown fox jumps over the dog"
                                        "the brown fox jumps over the dog"
                                        "the brown fox jumps over the dog"
                                        "the brown fox jumps over the dog"
                                        "the brown fox jumps over the dog"
                                        "the brown fox jumps over the dog"
                                        "the brown fox jumps over the dog"
                                        "the brown fox jumps over the dog"
                                        "the brown fox jumps over the dog"
                                        "the brown fox jumps over the dog"
                                        "the brown fox jumps over the dog"
                                        "the brown fox jumps over the dog"
                                        "the brown fox jumps over the dog"
                                        "the brown fox jumps over the dog"
                                        "the brown fox jumps over the dog"
                                        "the brown fox jumps over the dog"
                                        "the brown fox jumps over the dog"
                                        "the brown fox jumps over the dog"
                                        "the brown fox jumps over the dog"
                                        "the brown fox jumps over the dog"
                                        "the brown fox jumps over the dog"
                                        "the brown fox jumps over the dog"
                                        "the brown fox jumps over the dog"
                                        "the brown fox jumps over the dog"
                                        "the brown fox jumps over the dog";

static const uint8_t ecc_key1[] = { 
    0x79, 0xb5, 0x56, 0x2e, 0x8f, 0xe6, 0x54, 0xf9, 0x40, 0x78, 0xb1, 0x12, 0xe8, 0xa9, 0x8b, 0xa7, 
    0x90, 0x1f, 0x85, 0x3a, 0xe6, 0x95, 0xbe, 0xd7, 0xe0, 0xe3, 0x91, 0x0b, 0xad, 0x04, 0x96, 0x64};

static const uint8_t ecc_sig1[] = { 
    0x8c, 0x82, 0xc8, 0x7b, 0x21, 0x48, 0x48, 0xbc, 0x02, 0x28, 0x81, 0x52, 0xec, 0x91, 0x05, 0xfb, 
    0x9d, 0xab, 0x65, 0xb0, 0x2a, 0x55, 0x67, 0xaf, 0xf6, 0x90, 0xcf, 0xc7, 0x3a, 0x56, 0x5e, 0xd4, 
    0x0b, 0xb1, 0x45, 0x65, 0x2b, 0x51, 0x87, 0x17, 0xa5, 0x38, 0xb8, 0xa6, 0x31, 0x26, 0x30, 0xe8, 
    0xff, 0x8a, 0x55, 0xd1, 0x25, 0x96, 0xdf, 0xf4, 0xad, 0x35, 0xcc, 0x38, 0x05, 0xc6, 0x7b, 0x0b};


int main(void)
{
    int tc_error;
    uint64_t t0, t1;
    uint8_t data[1024], pk[300], sig[256], tag[16], ccm_data_with_mac[1032];

    uint8_t output[1024];
    size_t length;

    struct tc_sha256_state_struct tc_sha256_state_ctx;
    struct tc_sha512_state_struct tc_sha512_state_ctx;

    struct tc_hmac_state_struct	tc_hmac_state_ctx;
    struct tc_aes_key_sched_struct tc_aes_key_sched_ctx;

    uint8_t counter;
    uint32_t blk_off;
  
    printf("Speed tests (cycles)                 TinyCrypt\r\n");

    printf("SHA-256 (1024 bytes):                ");
#if defined(PSA_WANT_ALG_SHA_256)
    t0 = cpucycles();
    tc_sha256_init(&tc_sha256_state_ctx);
    tc_sha256_update(&tc_sha256_state_ctx, data, sizeof data);
    tc_error = tc_sha256_final(output, &tc_sha256_state_ctx);
    if (tc_error != TC_CRYPTO_SUCCESS) goto error;
    t1 = cpucycles();
    printf("%lld\r\n", t1 - t0);
#else
    printf("skipped\r\n");
#endif

    printf("SHA-512 (1024 bytes):                ");
#if defined(PSA_WANT_ALG_SHA_512)
    t0 = cpucycles();
    tc_sha512_init(&tc_sha512_state_ctx);
    tc_sha512_update(&tc_sha512_state_ctx, data, sizeof data);
    tc_error = tc_sha512_final(output, &tc_sha512_state_ctx);
    if (tc_error != TC_CRYPTO_SUCCESS) goto error;
    t1 = cpucycles();
    printf("%lld\r\n", t1 - t0);
#else
    printf("skipped\r\n");
#endif

    printf("SHA3-256 (1024 bytes):               ");
#if defined(PSA_WANT_ALG_SHA3_256)
    printf("NS\r\n");
#else
    printf("skipped\r\n");
#endif

    printf("HMAC-SHA-256 (1024 bytes):           ");
#if defined(PSA_WANT_ALG_HMAC) && defined(PSA_WANT_ALG_SHA_256)
	tc_error = tc_hmac_set_key(&tc_hmac_state_ctx, key_data, 32);
    if (tc_error != TC_CRYPTO_SUCCESS) goto error;
    tc_error = tc_hmac_init(&tc_hmac_state_ctx);
    if (tc_error != TC_CRYPTO_SUCCESS) goto error;
    t0 = cpucycles();
	tc_error = tc_hmac_update(&tc_hmac_state_ctx, data, sizeof data);
    if (tc_error != TC_CRYPTO_SUCCESS) goto error;
	tc_error = tc_hmac_final(data, 32, &tc_hmac_state_ctx);
    if (tc_error != TC_CRYPTO_SUCCESS) goto error;
    t1 = cpucycles();
    printf("%lld\r\n", t1 - t0);
#else
    printf("skipped\r\n");
#endif

    printf("HMAC-SHA-512 (1024 bytes):           ");
#if defined(PSA_WANT_ALG_HMAC) && defined(PSA_WANT_ALG_SHA_512)
    printf("NS\r\n");
#else
    printf("skipped\r\n");
#endif

    printf("CMAC-AES-256 (1024 bytes):           ");
#if defined(PSA_WANT_ALG_CMAC)
    printf("NS\r\n");
#else
    printf("skipped\r\n");
#endif

    printf("HKDF-SHA-256:                        ");
#if defined(PSA_WANT_ALG_HKDF)
    printf("NS\r\n");
#else
    printf("skipped\r\n");
#endif

    printf("PBKDF2-SHA-256 (100 iterations):     ");
#if defined(PSA_WANT_ALG_PBKDF2_HMAC)
    printf("NS\r\n");
#else
    printf("skipped\r\n");
#endif

    printf("PBKDF2-CMAC-PRF128 (100 iterations): ");
#if defined(PSA_WANT_ALG_PBKDF2_AES_CMAC_PRF_128)
    printf("NS\r\n");
#else
    printf("skipped\r\n");
#endif

    printf("AES-ECB enc (1024 bytes):            ");
#if defined(PSA_WANT_ALG_ECB_NO_PADDING)
    printf("NS\r\n");
#else
    printf("skipped\r\n");
#endif

    printf("AES-ECB dec (1024 bytes):            ");
#if defined(PSA_WANT_ALG_ECB_NO_PADDING)
    printf("NS\r\n");
#else
    printf("skipped\r\n");
#endif

    printf("AES-CBC-PKCS7 enc (1024 bytes):      ");
#if defined(PSA_WANT_ALG_CBC_PKCS7)
    printf("NS\r\n");
#else
    printf("skipped\r\n");
#endif

    printf("AES-CBC-PKCS7 dec (1024 bytes):      ");
#if defined(PSA_WANT_ALG_CBC_PKCS7)
    printf("NS\r\n");
#else
    printf("skipped\r\n");
#endif

    printf("AES-CTR enc (1024 bytes):            ");
#if defined(PSA_WANT_ALG_CTR)
    t0 = cpucycles();
	tc_error = tc_aes128_set_encrypt_key(&tc_aes_key_sched_ctx, key_data);
    if (tc_error != TC_CRYPTO_SUCCESS) goto error;
    counter = 0;
    blk_off = 0;
	tc_error = tc_ctr_mode(data, sizeof data, data, sizeof data, &counter, &blk_off, &tc_aes_key_sched_ctx);
    if (tc_error != TC_CRYPTO_SUCCESS) goto error;
    t1 = cpucycles();
    printf("%lld\r\n", t1 - t0);
#else
    printf("skipped\r\n");
#endif

    printf("AES-CTR dec (1024 bytes):            ");
#if defined(PSA_WANT_ALG_CTR)
    t0 = cpucycles();
	tc_error = tc_aes128_set_encrypt_key(&tc_aes_key_sched_ctx, key_data);
    if (tc_error != TC_CRYPTO_SUCCESS) goto error;
    counter = 0;
    blk_off = 0;
	tc_error = tc_ctr_mode(data, sizeof data, data, sizeof data, &counter, &blk_off, &tc_aes_key_sched_ctx);
    if (tc_error != TC_CRYPTO_SUCCESS) goto error;
    t1 = cpucycles();
    printf("%lld\r\n", t1 - t0);
#else
    printf("skipped\r\n");
#endif

 	struct tc_ccm_mode_struct c;

    printf("AES-CCM enc (1024 bytes):            ");
 #if defined(PSA_WANT_ALG_CCM)
    t0 = cpucycles();
 	tc_error = tc_aes128_set_encrypt_key(&tc_aes_key_sched_ctx, key_data);
     if (tc_error != TC_CRYPTO_SUCCESS) goto error;

    tc_error = tc_ccm_config(&c, &tc_aes_key_sched_ctx, (uint8_t *) key_data, 13, 8);
    if (tc_error != TC_CRYPTO_SUCCESS) goto error;

 	tc_error = tc_ccm_generation_encryption(ccm_data_with_mac, sizeof ccm_data_with_mac, tag, sizeof tag, data, sizeof data, &c);
    if (tc_error != TC_CRYPTO_SUCCESS) goto error;
    t1 = cpucycles();
    printf("%lld\r\n", t1 - t0);
 #else
    printf("skipped\r\n");
 #endif

    printf("AES-CCM dec (1024 bytes):            ");
 #if defined(PSA_WANT_ALG_CCM)
    t0 = cpucycles();
 	tc_error = tc_aes128_set_encrypt_key(&tc_aes_key_sched_ctx, key_data);
    if (tc_error != TC_CRYPTO_SUCCESS) goto error;

    tc_error = tc_ccm_config(&c, &tc_aes_key_sched_ctx, (uint8_t *) key_data, 13, 8);
    if (tc_error != TC_CRYPTO_SUCCESS) goto error;

 	tc_error = tc_ccm_decryption_verification(data, sizeof data, tag, sizeof tag, ccm_data_with_mac, sizeof ccm_data_with_mac, &c);
     if (tc_error != TC_CRYPTO_SUCCESS) goto error;
     t1 = cpucycles();
     printf("%lld\r\n", t1 - t0);
 #else
    printf("skipped\r\n");
 #endif

    printf("AES-GCM enc (1024 bytes):            ");
#if defined(PSA_WANT_ALG_GCM)
    printf("NS\r\n");
#else
    printf("skipped\r\n");
#endif

    printf("AES-GCM dec (1024 bytes):            ");
#if defined(PSA_WANT_ALG_GCM)
    printf("NS\r\n");
#else
    printf("skipped\r\n");
#endif

    printf("CHACHA20 enc (1024 bytes):           ");
#if defined(PSA_WANT_ALG_STREAM_CIPHER) && defined(PSA_WANT_KEY_TYPE_CHACHA20)
    printf("NS\r\n");
#else
    printf("skipped\r\n");
#endif

    printf("CHACHA20 dec (1024 bytes):           ");
#if defined(PSA_WANT_ALG_STREAM_CIPHER) && defined(PSA_WANT_KEY_TYPE_CHACHA20)
    printf("NS\r\n");
#else
    printf("skipped\r\n");
#endif

    printf("Chacha20-Poly1305 enc (1024 bytes):  ");
#if defined(PSA_WANT_ALG_CHACHA20_POLY1305)
    printf("NS\r\n");
#else
    printf("skipped\r\n");
#endif

    printf("Chacha20-Poly1305 dec (1024 bytes):  ");
#if defined(PSA_WANT_ALG_CHACHA20_POLY1305)
    printf("NS\r\n");
#else
    printf("skipped\r\n");
#endif

   printf("P256 public key:                     ");
#if defined(PSA_WANT_ALG_ECDSA) && defined(PSA_WANT_ECC_SECP_R1_256) && \
   defined(PSA_WANT_KEY_TYPE_ECC_KEY_PAIR_BASIC) && \
   defined(PSA_WANT_GENERATE_RANDOM)
    printf("NS\r\n");
#else
   printf("skipped\r\n");
#endif


    printf("P256 sign hash (32 bytes):           ");
#if defined(PSA_WANT_ALG_ECDSA) && defined(PSA_WANT_ECC_SECP_R1_256) && \
    defined(PSA_WANT_KEY_TYPE_ECC_KEY_PAIR_BASIC)
    printf("NS\r\n");
#else
    printf("skipped\r\n");
#endif

    printf("P256 verify hash (32 bytes):         ");
#if defined(PSA_WANT_ALG_ECDSA) && defined(PSA_WANT_ECC_SECP_R1_256) && \
    defined(PSA_WANT_KEY_TYPE_ECC_PUBLIC_KEY)
    t0 = cpucycles();
	if (ecc_key_pair[0] != 0x04) goto error;
	tc_error = uECC_verify(&ecc_key_pair[1], msg_data, 32, ecc_sig, uECC_secp256r1());
    if (tc_error != TC_CRYPTO_SUCCESS) goto error;
    t1 = cpucycles();
    printf("%lld\r\n", t1 - t0);
#else
    printf("skipped\r\n");
#endif

    printf("ECDH P256:                           ");
#if defined(PSA_WANT_ALG_ECDH) && defined(PSA_WANT_ECC_SECP_R1_256)
    t0 = cpucycles();
	if (ecc_key_pair[0] != 0x04) goto error;
	tc_error = uECC_valid_public_key(&ecc_key_pair[1], uECC_secp256r1());
    if (tc_error != 0) goto error;
    tc_error = uECC_shared_secret(&ecc_key_pair[1], key_data, data, uECC_secp256r1());
    if (tc_error != TC_CRYPTO_SUCCESS) goto error;
    t1 = cpucycles();
    printf("%lld\r\n", t1 - t0);
#else
    printf("skipped\r\n");
#endif

    printf("Ed25519 public key:                  ");
#if defined(PSA_WANT_ECC_MONTGOMERY_255) \
    && (defined(PSA_WANT_KEY_TYPE_ECC_PUBLIC_KEY) || defined(PSA_WANT_ALG_ECDH))
    printf("NS\r\n");
#else
    printf("skipped\r\n");
#endif

    printf("Ed25519 sign (32 bytes):             ");
#if defined(PSA_WANT_ECC_TWISTED_EDWARDS_255) 
    printf("NS\r\n");
#else
    printf("skipped\r\n");
#endif

    printf("Ed25519 verify (32 bytes):           ");
#if defined(PSA_WANT_ECC_TWISTED_EDWARDS_255) &&\
    defined(PSA_WANT_KEY_TYPE_ECC_PUBLIC_KEY) &&\
    defined(PSA_WANT_ALG_PURE_EDDSA)
    printf("NS\r\n");
#else
    printf("skipped\r\n");
#endif

    printf("X25519 public key:                   ");
#if defined(PSA_WANT_ECC_MONTGOMERY_255) \
    && (defined(PSA_WANT_KEY_TYPE_ECC_PUBLIC_KEY) || defined(PSA_WANT_ALG_ECDH))
    printf("NS\r\n");
#else
    printf("skipped\r\n");
#endif

    printf("ECDH X25519:                         ");
#if defined(PSA_WANT_ECC_MONTGOMERY_255) \
    && defined(PSA_WANT_ALG_ECDH)
    printf("NS\r\n");
#else
    printf("skipped\r\n");
#endif

    printf("done\r\n");
    return 0;
error:
	printf("TinyCrypt Error %i", tc_error);
    printf("\r\n");
    return 1;
}
