# Appendix A: Supported Crypto Features

Crypto algorithms are the main features of a crypto library. For some algorithms,
different key types or key sizes can be chosen.

## Supported Crypto Algorithms and Key Types

_Oberon PSA Crypto_ supports the following algorithms out of the box, i.e., if
only the _Oberon drivers_ are used. For every algorithm, the appropriate C define
directive is given, and - where applicable - the supported key types:

| Algorithms                            | Algorithm/Class Directives                                                       | Key Type Directives         | PQC-Resistant |
|:------------------------------------- |:-------------------------------------------------------------------------------- |:--------------------------- |:------------- |
| SHA1                                  | PSA_WANT_ALG_SHA_1                                                               | -                           | 9)            |
| SHA2                                  | PSA_WANT_ALG_SHA_224/256/384/512                                                 | -                           | yes 10)       |
| SHA3                                  | PSA_WANT_ALG_SHA3_224/256/384/512                                                | -                           | yes 10)       |
| SHAKE                                 | PSA_WANT_ALG_SHAKE256-512                                                        | -                           | yes 10)       |
| HMAC                                  | PSA_WANT_ALG_HMAC                                                                | PSA_WANT_KEY_TYPE_HMAC      | yes 10)       |
| AES-CMAC                              | PSA_WANT_ALG_CMAC                                                                | PSA_WANT_KEY_TYPE_AES       | yes 11)       |
| ChaCha20                              | PSA_WANT_ALG_STREAM_CIPHER                                                       | PSA_WANT_KEY_TYPE_CHACHA20  | yes           |
| XChaCha20                             | PSA_WANT_ALG_STREAM_CIPHER                                                       | PSA_WANT_KEY_TYPE_XCHACHA20 | yes           |
| AES (cipher)                          | PSA_WANT_ALG_CTR/CCM_STAR_NO_TAG/ECB_NO_PADDING/CBC_NO_PADDING/CCM/GCM/CBC_PKCS7 | PSA_WANT_KEY_TYPE_AES       | yes 11)       |
| AES (key wrapping) 1)                 | PSA_WANT_ALG_KW/KWP                                                              | PSA_WANT_KEY_TYPE_AES       | yes 11)       |
| AES (AEAD)                            | PSA_WANT_ALG_CCM/GCM                                                             | PSA_WANT_KEY_TYPE_AES       | yes 11)       |
| ChaCha20-Poly1305                     | PSA_WANT_ALG_CHACHA20_POLY1305                                                   | PSA_WANT_KEY_TYPE_CHACHA20  | yes           |
| XChaCha20-Poly1305                    | PSA_WANT_ALG_XCHACHA20_POLY1305                                                  | PSA_WANT_KEY_TYPE_XCHACHA20 | yes           |
| HKDF                                  | PSA_WANT_ALG_HKDF/HKDF_EXTRACT/HKDF_EXPAND                                       | PSA_WANT_KEY_TYPE_DERIVE    | yes 10)       |
| TLS-1.2 PRF                           | PSA_WANT_ALG_TLS12_PRF                                                           | PSA_WANT_KEY_TYPE_DERIVE    | yes 10)       |
| TLS-1.2 PSK-to-Mastersecret           | PSA_WANT_ALG_TLS12_PSK_TO_MS                                                     | PSA_WANT_KEY_TYPE_DERIVE    | yes 10)       |
| PBKDF2-HMAC                           | PSA_WANT_ALG_PBKDF2_HMAC                                                         | PSA_WANT_KEY_TYPE_HMAC      | yes 10)       |
| PBKDF2-AES-CMAC-PRF128                | PSA_WANT_ALG_PBKDF2_AES_CMAC_PRF_128                                             | PSA_WANT_KEY_TYPE_AES       | yes 11)       |
| SP800-108-COUNTER-HMAC                | PSA_WANT_ALG_SP800_108_COUNTER_HMAC                                              | PSA_WANT_KEY_TYPE_HMAC      | yes 10)       |
| SP800-108-COUNTER-CMAC                | PSA_WANT_ALG_SP800_108_COUNTER_CMAC                                              | PSA_WANT_KEY_TYPE_AES       | yes 11)       |
| RSA (encryption)                      | PSA_WANT_ALG_RSA_PKCS1V15_CRYPT/OEAP                                             | 2)                          | no            |
| ECDSA (NIST curves)                   | PSA_WANT_ALG_ECDSA                                                               | 3)                          | no            |
| Deterministic ECDSA (NIST curves)     | PSA_WANT_ALG_DETERMINISTIC_ECDSA                                                 | 3)                          | no            |
| EdDSA (Twisted Edwards curves)        | PSA_WANT_ALG_PURE_EDDSA                                                          | 3)                          | no            |
| EdDSA pre-hashed                      | PSA_WANT_ALG_ED25519PH/ED448PH                                                   | 3)                          | no            |
| RSA (signature)                       | PSA_WANT_ALG_RSA_PKCS1V15_SIGN/PSS                                               | 2)                          | no            |
| LMS/HSS (signature verification)      | PSA_WANT_ALG_LMS/HSS                                                             | 4)                          | yes           |
| XMSS/XMSS^MT (signature verification) | PSA_WANT_ALG_XMSS/XMSS_MT                                                        | 4)                          | yes           |
| ML-DSA (aka Dilithium)                | PSA_WANT_ALG_ML_DSA                                                              | 5) 12)                      | yes           |
| ECDH (NIST and Montgomery curves)     | PSA_WANT_ALG_ECDH                                                                | 3)                          | no            |
| ML-KEM (aka Kyber)                    | PSA_WANT_ALG_ML_KEM                                                              | 6) 12)                      | yes           |
| EC-JPAKE                              | PSA_WANT_ALG_JPAKE                                                               | TLS12_ECJPAKE_TO_PMS        | no            |
| SPAKE2+                               | PSA_WANT_ALG_SPAKE2P_HMAC/CMAC/MATTER                                            | 7)                          | no            |
| SRP-6                                 | PSA_WANT_ALG_SRP_6                                                               | 8)                          | no            |
| CTR_DRBG                              | PSA_WANT_GENERATE_RANDOM + PSA_USE_CTR_DRBG_DRIVER                               | -                           | n/a           |
| HMAC_DRBG                             | PSA_WANT_GENERATE_RANDOM + PSA_USE_HMAC_DRBG_DRIVER                              | -                           | n/a           |

1) AES key wrapping with/without padding is an experimental feature based on
[PSA issue 50](https://github.com/ARM-software/psa-api/issues/50#issuecomment-1772551575).
2) PSA_WANT_KEY_TYPE_RSA_KEY_PAIR_BASIC/IMPORT/EXPORT.
3) PSA_WANT_KEY_TYPE_ECC_KEY_PAIR_BASIC/IMPORT/EXPORT/GENERATE/DERIVE.
4) PSA_WANT_KEY_TYPE_LMS_PUBLIC_KEY/HSS_PUBLIC_KEY/XMSS_PUBLIC_KEY/XMSS_MT_PUBLIC_KEY for SHA256 and SHAKE256.
5) PSA_WANT_KEY_TYPE_ML_DSA_KEY_PAIR_BASIC/IMPORT/EXPORT/GENERATE/DERIVE.
6) PSA_WANT_KEY_TYPE_ML_KEM_KEY_PAIR_BASIC/IMPORT/EXPORT/GENERATE/DERIVE.
7) PSA_WANT_KEY_TYPE_SPAKE2P_KEY_PAIR_BASIC/IMPORT/EXPORT/DERIVE.
8) PSA_WANT_KEY_TYPE_SRP_KEY_PAIR_BASIC/IMPORT/EXPORT/DERIVE.
9) Considered non-secure even without quantum computers. Use only for legacy compatibility.
10) Use of SHA384/SHA512/SHA3-384/SHA3-512/SHAKE256 recommended.
11) Use of AES-256 recommended.
12) ML-DSA and ML-KEM are pure software implementations (no _driver chaining_).
They require more stack space than the other _Oberon PSA Crypto_ operations.
Worst case: signing with ML-DSA-87 requires a stack size of about 16 KB.

By defining these directives, the application developer provides the C
preprocessor with the information that is necessary to include only the wanted
code in the resulting firmware image.

_Oberon PSA Crypto_ may be extended by further crypto algorithms as defined in the
_PSA Certified Crypto API_ standard by adding appropriate _crypto drivers_.

## Supported Key Sizes

Some algorithms support different key sizes. For them, the appropriate C define
directives are given:

| Algorithm                            | Supported Key Sizes in Bits              | Directives                                               |
|:------------------------------------ |:---------------------------------------- |:-------------------------------------------------------- |
| SHA1                                 | na                                       | -                                                        |
| SHA2                                 | na                                       | -                                                        |
| SHA3                                 | na                                       | -                                                        |
| SHAKE                                | na                                       | -                                                        |
| HMAC                                 | na                                       | -                                                        |
| AES-CMAC                             | 128, 192, 256                            | PSA_WANT_AES_KEY_SIZE_128/192/256                        |
| ChaCha20 (cipher)                    | 256                                      | -                                                        |
| AES (cipher)                         | 128, 192, 256                            | PSA_WANT_AES_KEY_SIZE_128/192/256                        |
| AES (AEAD)                           | 128, 192, 256                            | PSA_WANT_AES_KEY_SIZE_128/192/256                        |
| ChaCha20-Poly1305 (AEAD)             | 256                                      | -                                                        |
| HKDF                                 | na                                       | -                                                        |
| TLS-1.2 PRF                          | na                                       | -                                                        |
| TLS-1.2 PSK-to-Mastersecret          | na                                       | -                                                        |
| PBKDF2-HMAC                          | na                                       | -                                                        |
| PBKDF2-AES-CMAC-PRF128               | 128                                      | PSA_WANT_AES_KEY_SIZE_128                                |
| SP800_108_COUNTER-HMAC               | na                                       | -                                                        |
| SP800_108_COUNTER-CMAC               | 128, 192, 256                            | PSA_WANT_AES_KEY_SIZE_128/192/256                        |
| RSA (encryption)                     | 1024, 1536, 2048, 3072, 4096, 6144, 8192 | PSA_WANT_RSA_KEY_SIZE_1024/1536/2048/3072/4096/6144/8192 |
| ECDSA (NIST curves)                  | 224, 256, 384, 521                       | PSA_WANT_ECC_SECP_R1_224/256/384/521/K1_256              |
| Deterministic ECDSA (NIST curves)    | 224, 256, 384, 521                       | PSA_WANT_ECC_SECP_R1_224/256/384/521                     |
| EdDSA (Twisted Edwards curves)       | 255, 448                                 | PSA_WANT_ECC_TWISTED_EDWARDS_255/448                     |
| RSA (signature)                      | 1024, 1536, 2048, 3072, 4096, 6144, 8192 | PSA_WANT_RSA_KEY_SIZE_1024/1536/2048/3072/4096/6144/8192 |
| LMS/HSS (signature verifiction)      | 192, 256                                 | -                                                        |
| XMSS/XMSS^MT (signature verifiction) | 192, 256                                 | -                                                        |
| ECDH (NIST curves)                   | 224, 256, 384, 521                       | PSA_WANT_ECC_SECP_R1_224/256/384/521                     |
| ECDH (Montgomery curves)             | 255, 448                                 | PSA_WANT_ECC_MONTGOMERY_255/448                          |
| EC-JPAKE                             | 256                                      | -                                                        |
| SPAKE2+                              | 256                                      | -                                                        |
| SRP-6                                | 3072                                     | -                                                        |
| CTR_DRBG                             | 256                                      | -                                                        |
| HMAC_DRBG                            | na                                       | -                                                        |

HMAC, HKDF, and PBKDF2 are hash-based and can use any available hash algorithm.
Key sizes are independent of hash sizes.

LMS/HSS and XMSS/XMSS^MT are hash-based and can use SHA256-192, SHA256-256,
SHAKE256-192, or SHAKE256-256 as hash algorithms.

## Overlap Rules

All functions comply with overlap rules as specified in
`PSA API 1.1.2, 5.4.4 Overlap between parameters`, except for `psa_cipher_update`
and `psa_aead_update`. For the latter functions, two overlap scenarios are
supported:

1. For each individual update call input and output parameters point to the same
buffer.
2. A single common buffer may be used for the whole plaintext and ciphertext, if
buffer pointers for input and output of the first call are equal and incremented
individually by the input and output size for each further call (meaning the
plaintext and ciphertext are stored contiguously in the common buffer).
