# Appendix A: Supported Crypto Features

Crypto algorithms are the main features of a crypto library. For some algorithms,
different key types or key sizes can be chosen.

## Supported Crypto Algorithms and Key Types

_Oberon PSA Crypto_ supports the following algorithms out of the box, i.e., if
only the _Oberon drivers_ are used. For every algorithm, the appropriate C define
directive is given, and - where applicable - the supported key types:

| Algorithms                          | Algorithm/Class Directives                                                       | Key Type Directives                       |
|:----------------------------------- |:-------------------------------------------------------------------------------- |:----------------------------------------- |
| SHA1                                | PSA_WANT_ALG_SHA_1                                                               | -                                         |
| SHA2                                | PSA_WANT_ALG_SHA_224/256/384/512                                                 | -                                         |
| SHA3                                | PSA_WANT_ALG_SHA3_224/256/384/512                                                | -                                         |
| SHAKE                               | PSA_WANT_ALG_SHAKE256-512                                                        | -                                         |
| HMAC                                | PSA_WANT_ALG_HMAC                                                                | PSA_WANT_KEY_TYPE_HMAC                    |
| AES-CMAC                            | PSA_WANT_ALG_CMAC                                                                | PSA_WANT_KEY_TYPE_AES                     |
| ChaCha20 (cipher)                   | PSA_WANT_ALG_STREAM_CIPHER                                                       | PSA_WANT_KEY_TYPE_CHACHA20                |
| AES (cipher)                        | PSA_WANT_ALG_CTR/CCM_STAR_NO_TAG/ECB_NO_PADDING/CBC_NO_PADDING/CCM/GCM/CBC_PKCS7 | PSA_WANT_KEY_TYPE_AES                     |
| AES (AEAD)                          | PSA_WANT_ALG_CCM/GCM                                                             | PSA_WANT_KEY_TYPE_AES                     |
| ChaCha20-Poly1305 (AEAD)            | PSA_WANT_ALG_CHACHA20_POLY1305                                                   | PSA_WANT_KEY_TYPE_CHACHA20                |
| HKDF                                | PSA_WANT_ALG_HKDF/HKDF_EXTRACT/HKDF_EXPAND                                       | PSA_WANT_KEY_TYPE_DERIVE                  |
| TLS-1.2 PRF                         | PSA_WANT_ALG_TLS12_PRF                                                           | PSA_WANT_KEY_TYPE_DERIVE                  |
| TLS-1.2 PSK-to-Mastersecret         | PSA_WANT_ALG_TLS12_PSK_TO_MS                                                     | PSA_WANT_KEY_TYPE_DERIVE                  |
| PBKDF2-HMAC                         | PSA_WANT_ALG_PBKDF2_HMAC                                                         | PSA_WANT_KEY_TYPE_HMAC                    |
| PBKDF2-AES-CMAC-PRF128              | PSA_WANT_ALG_PBKDF2_AES_CMAC_PRF_128                                             | PSA_WANT_KEY_TYPE_AES                     |
| SP800_108_COUNTER-HMAC              | PSA_WANT_ALG_SP800_108_COUNTER_HMAC                                              | PSA_WANT_KEY_TYPE_HMAC                    |
| SP800_108_COUNTER-CMAC              | PSA_WANT_ALG_SP800_108_COUNTER_CMAC                                              | PSA_WANT_KEY_TYPE_AES                     |
| RSA (encryption)                    | PSA_WANT_ALG_RSA_PKCS1V15_CRYPT/OEAP                                             | 1)                                        |
| ECDSA (NIST curves)                 | PSA_WANT_ALG_ECDSA                                                               | 2)                                        |
| Deterministic ECDSA (NIST curves)   | PSA_WANT_ALG_DETERMINISTIC_ECDSA                                                 | 2)                                        |
| EdDSA (Twisted Edwards curves)      | PSA_WANT_ALG_PURE_EDDSA                                                          | 2)                                        |
| EdDSA pre-hashed                    | PSA_WANT_ALG_ED25519PH/ED448PH                                                   | 2)                                        |
| RSA (signature)                     | PSA_WANT_ALG_RSA_PKCS1V15_SIGN/PSS                                               | 1)                                        |
| ECDH (NIST and Montgomery curves)   | PSA_WANT_ALG_ECDH                                                                | 2)                                        |
| EC-JPAKE                            | PSA_WANT_ALG_JPAKE                                                               | TLS12_ECJPAKE_TO_PMS                      |
| SPAKE2+                             | PSA_WANT_ALG_SPAKE2P                                                             | -                                         |
| SRP-6                               | PSA_WANT_ALG_SRP_6                                                               | -                                         |
| CTR-DRBG                            | PSA_WANT_GENERATE_RANDOM + PSA_USE_CTR_DRBG_DRIVER                               | -                                         |
| HMAC-DRBG                           | PSA_WANT_GENERATE_RANDOM + PSA_USE_HMAC_DRBG_DRIVER                              | -                                         |

1) PSA_WANT_KEY_TYPE_RSA_KEY_PAIR_BASIC/IMPORT/EXPORT
2) PSA_WANT_KEY_TYPE_ECC_KEY_PAIR_BASIC/IMPORT/EXPORT/GENERATE/DERIVE

By defining these directives, the application developer provides the C
preprocessor with the information that is necessary to include only the wanted
code in the resulting firmware image.

_Oberon PSA Crypto_ may be extended by further crypto algorithms as defined in the
_PSA Certified Crypto API_ standard by adding appropriate drivers.

## Supported Key Sizes

Some algorithms support different key sizes. For them, the appropriate C define
directives are given:
| Algorithm                         | Supported Key Sizes in Bits              | Directives                                               |
|:--------------------------------- |:---------------------------------------- |:-------------------------------------------------------- |
| SHA1                              | na                                       | -                                                        |
| SHA2                              | na                                       | -                                                        |
| SHA3                              | na                                       | -                                                        |
| SHAKE                             | na                                       | -                                                        |
| HMAC                              | na                                       | -                                                        |
| AES-CMAC                          | 128, 192, 256                            | PSA_WANT_AES_KEY_SIZE_128/192/256                        |
| ChaCha20 (cipher)                 | 256                                      | -                                                        |
| AES (cipher)                      | 128, 192, 256                            | PSA_WANT_AES_KEY_SIZE_128/192/256                        |
| AES (AEAD)                        | 128, 192, 256                            | PSA_WANT_AES_KEY_SIZE_128/192/256                        |
| ChaCha20-Poly1305 (AEAD)          | 256                                      | -                                                        |
| HKDF                              | na                                       | -                                                        |
| TLS-1.2 PRF                       | na                                       | -                                                        |
| TLS-1.2 PSK-to-Mastersecret       | na                                       | -                                                        |
| PBKDF2-HMAC                       | na                                       | -                                                        |
| PBKDF2-AES-CMAC-PRF128            | 128                                      | PSA_WANT_AES_KEY_SIZE_128                                |
| RSA (encryption)                  | 1024, 1536, 2048, 3072, 4096, 6144, 8192 | PSA_WANT_RSA_KEY_SIZE_1024/1536/2048/3072/4096/6144/8192 |
| ECDSA (NIST curves)               | 224, 256, 384, 521                       | PSA_WANT_ECC_SECP_R1_224/256/384/521                     |
| Deterministic ECDSA (NIST curves) | 224, 256, 384, 521                       | PSA_WANT_ECC_SECP_R1_224/256/384/521                     |
| EdDSA (Twisted Edwards curves)    | 255, 448                                 | PSA_WANT_ECC_TWISTED_EDWARDS_255/448                     |
| RSA (signature)                   | 1024, 1536, 2048, 3072, 4096, 6144, 8192 | PSA_WANT_RSA_KEY_SIZE_1024/1536/2048/3072/4096/6144/8192 |
| ECDH (NIST curves)                | 224, 256, 384, 521                       | PSA_WANT_ECC_SECP_R1_224/256/384/521                     |
| ECDH (Montgomery curves)          | 255, 448                                 | PSA_WANT_ECC_MONTGOMERY_255/448                          |
| EC-JPAKE                          | 256                                      | -                                                        |
| SPAKE2+                           | 256                                      | -                                                        |
| SRP-6                             | 3072                                     | -                                                        |
| CTR-DRBG                          | 256                                      | -                                                        |
| HMAC-DRBG                         | na                                       | -                                                        |

HMAC, HKDF and PBKDF2 are hash-based and can use any available hash algorithm.
Key sizes are independent of the hash sizes.

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
