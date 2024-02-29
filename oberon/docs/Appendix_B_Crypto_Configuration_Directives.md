# Appendix B: Crypto Configuration Directives

In this document, the syntax of C define directives used to configure dead code
elimination are described. This includes directives to be set by the _system
crypto configurator_ (`PSA_WANT_XXX`, `PSA_USE_XXX`) and internal directives that
are derived from the former.

C define directives of the form `PSA_WANT_XXX` and `PSA_USE_XXX` are defined in
system crypto configurations, see
[Crypto Configuration](Crypto_Configuration.md).

C define directives of the form `PSA_NEED_XXX` and `PSA_ACCEL_XXX` are defined
within the crypto configurations of _hardware drivers_ and _Oberon drivers_, see
[Crypto Driver Development](Crypto_Driver_Development.md).

Syntax for identifier parts (symbols) used in the chapters below:

- Terminal symbol X: X (upper case)
- Required symbol x: x (lower case)
- Optional symbol x: [x] (lower case in brackets)
- Separator within a terminal symbol: _
- Separator between symbols: __

*Note: For better readability, a separator between symbols in this document is
represented as two consecutive underscores in the syntax, but only one underscore
must be used in actual code.*

From the _Mbed TLS_ documentation:
A _PSA Crypto_ configuration symbol is a C preprocessor symbol whose name starts
with `PSA_WANT_`.

- If the symbol is not defined, the corresponding feature is not included.
- If the symbol is defined to a preprocessor expression with the value 1, the
corresponding feature is included.
- If the symbol is defined with a different value, the behavior is currently
undefined and reserved for future use.

To define a configuration feature in a C header file, a symbol like
`PSA_WANT_ALG_SPAKE2P` is defined like this:

    #define PSA_WANT_ALG_SPAKE2P                    1

In the following sections, all available define directives are listed.

## PSA_WANT Directives

These directives define what cryptographic features are "wanted" for potential
use in an application.

### Algorithms wanted by the application

Syntax: PSA_WANT_ALG__alg

Parameter _alg_: Wanted algorithm.

- PSA_WANT_ALG_`CBC_NO_PADDING`
- PSA_WANT_ALG_`CBC_PKCS7`
- PSA_WANT_ALG_`CCM`
- PSA_WANT_ALG_`CCM_STAR_NO_TAG`
- PSA_WANT_ALG_`CHACHA20_POLY1305`
- PSA_WANT_ALG_`CMAC`
- PSA_WANT_ALG_`CTR`
- PSA_WANT_ALG_`DETERMINISTIC_ECDSA`
- PSA_WANT_ALG_`ECB_NO_PADDING`
- PSA_WANT_ALG_`ECDH`
- PSA_WANT_ALG_`ECDSA`
- PSA_WANT_ALG_`ED25519PH`
- PSA_WANT_ALG_`ED448PH`
- PSA_WANT_ALG_`GCM`
- PSA_WANT_ALG_`HKDF`
- PSA_WANT_ALG_`HKDF_EXTRACT`
- PSA_WANT_ALG_`HKDF_EXPAND`
- PSA_WANT_ALG_`HMAC`
- PSA_WANT_ALG_`JPAKE`
- PSA_WANT_ALG_`PBKDF2_HMAC`
- PSA_WANT_ALG_`PBKDF2_AES_CMAC_PRF_128`
- PSA_WANT_ALG_`PURE_EDDSA`
- PSA_WANT_ALG_`RSA_OAEP`
- PSA_WANT_ALG_`RSA_PKCS1V15_CRYPT`
- PSA_WANT_ALG_`RSA_PKCS1V15_SIGN`
- PSA_WANT_ALG_`RSA_PKCS1V15_SIGN_RAW`
- PSA_WANT_ALG_`RSA_PSS`
- PSA_WANT_ALG_`SPAKE2P`
- PSA_WANT_ALG_`SRP_6`
- PSA_WANT_ALG_`STREAM_CIPHER`
- PSA_WANT_ALG_`TLS12_PRF`
- PSA_WANT_ALG_`TLS12_PSK_TO_MS`
- PSA_WANT_ALG_`TLS12_ECJPAKE_TO_PMS`

### Hash algorithms wanted by the application

Syntax: PSA_WANT_ALG__hash-alg__hash-size

Parameter _hash-alg_:  Wanted hash algorithm.

Parameter _hash-size_: Wanted hash size.

- PSA_WANT_ALG_`SHA_1`
- PSA_WANT_ALG_`SHA_224`
- PSA_WANT_ALG_`SHA_256`
- PSA_WANT_ALG_`SHA_384`
- PSA_WANT_ALG_`SHA_512`
- PSA_WANT_ALG_`SHA3_224`
- PSA_WANT_ALG_`SHA3_256`
- PSA_WANT_ALG_`SHA3_384`
- PSA_WANT_ALG_`SHA3_512`
- PSA_WANT_ALG_`SHAKE256-512`

### Elliptic curve families wanted by the application

Syntax: PSA_WANT_ECC__family__key-size

Parameter _family_:   Wanted crypto family.

Parameter _key-size_: Wanted key size of curve.

- PSA_WANT_ECC_`MONTGOMERY_255`
- PSA_WANT_ECC_`MONTGOMERY_448`
- PSA_WANT_ECC_`TWISTED_EDWARDS_255`
- PSA_WANT_ECC_`TWISTED_EDWARDS_448`
- PSA_WANT_ECC_`SECP_R1_224`
- PSA_WANT_ECC_`SECP_R1_256`
- PSA_WANT_ECC_`SECP_R1_384`
- PSA_WANT_ECC_`SECP_R1_521`

### Key types wanted by the application

Syntax: PSA_WANT_KEY_TYPE__key-type

Parameter _key-type_: Wanted key type.

- PSA_WANT_KEY_TYPE_`DERIVE`
- PSA_WANT_KEY_TYPE_`HMAC`
- PSA_WANT_KEY_TYPE_`AES`
- PSA_WANT_KEY_TYPE_`CHACHA20`

- PSA_WANT_KEY_TYPE_`ECC_PUBLIC_KEY`
- PSA_WANT_KEY_TYPE_`ECC_KEY_PAIR_BASIC`
- PSA_WANT_KEY_TYPE_`ECC_KEY_PAIR_IMPORT`
- PSA_WANT_KEY_TYPE_`ECC_KEY_PAIR_EXPORT`
- PSA_WANT_KEY_TYPE_`ECC_KEY_PAIR_GENERATE`
- PSA_WANT_KEY_TYPE_`ECC_KEY_PAIR_DERIVE`

- PSA_WANT_KEY_TYPE_`RSA_PUBLIC_KEY`
- PSA_WANT_KEY_TYPE_`RSA_KEY_PAIR_BASIC`
- PSA_WANT_KEY_TYPE_`RSA_KEY_PAIR_IMPORT`
- PSA_WANT_KEY_TYPE_`RSA_KEY_PAIR_EXPORT`

### Key sizes wanted by the application for specific key types

These are additional configuration options introduced by _Oberon microsystems_.

Syntax: PSA_WANT__family__KEY_SIZE__key-size

Parameter _family_: Wanted key family.

Parameter _key-size_: Wanted key size for this key family.

- PSA_WANT_`AES`_KEY_SIZE_`128`
- PSA_WANT_`AES`_KEY_SIZE_`192`
- PSA_WANT_`AES`_KEY_SIZE_`256`

- PSA_WANT_`RSA`_KEY_SIZE_`1024`
- PSA_WANT_`RSA`_KEY_SIZE_`1536`
- PSA_WANT_`RSA`_KEY_SIZE_`2048`
- PSA_WANT_`RSA`_KEY_SIZE_`3072`
- PSA_WANT_`RSA`_KEY_SIZE_`4096`
- PSA_WANT_`RSA`_KEY_SIZE_`6144`
- PSA_WANT_`RSA`_KEY_SIZE_`8192`

### Whether random number generation is wanted by the application

This is an additional configuration option introduced by _Oberon microsystems_.

- PSA_WANT_`GENERATE_RANDOM`

## PSA_USE Directives

These directives define what cryptographic features are supported by the _target
platform_ through _hardware drivers_ and may therefore be used by an application
(the _Oberon drivers_ provided in software as fallbacks do not provide
`PSA_USE_XXX` directives and are used by default if no _hardware drivers_ are
availalbe. An exception are the provided DRBG drivers, see below).

### DRBG crypto drivers that may be provided by the target platform

These are additional configuration options introduced by _Oberon microsystems_.

They are DRBG _crypto drivers_ that may be provided by the _target platform_
and depend on an entropy driver from the _target platform_.

Syntax: PSA_USE__drbg__DRIVER

Parameter _drbg_: Provided DRBG implementation.

- PSA_USE_`CTR_DRBG`_DRIVER
- PSA_USE_`HMAC_DRBG`_DRIVER

### Crypto driver groups that may be provided by the target platform

Syntax: PSA_USE__driver-id__function-group__DRIVER

Parameter _driver-id_:      Provided driver.

Parameter _function-group_: Provided function group.

These are directives for hypothetical _hardware drivers_ for CryptoCell 310
hardware accelerators.

- PSA_USE_`CC310_HASH`_DRIVER
- PSA_USE_`CC310_AEAD`_DRIVER
- PSA_USE_`CC310_CIPHER`_DRIVER
- PSA_USE_`CC310_MAC`_DRIVER
- PSA_USE_`CC310_KEY_AGREEMENT`_DRIVER
- PSA_USE_`CC310_ASYMMETRIC_SIGNATURE`_DRIVER
- PSA_USE_`CC310_ASYMMETRIC_ENCRYPTION`_DRIVER
- PSA_USE_`CC310_KEY_MANAGEMENT`_DRIVER
- PSA_USE_`CC310_ENTROPY`_DRIVER

These are mock demo drivers provided by _Oberon microsystems_:

- PSA_USE_`DEMO_HARDWARE`_DRIVER
- PSA_USE_`DEMO_ENTROPY`_DRIVER
- PSA_USE_`DEMO_OPAQUE`_DRIVER

## PSA_NEED Directives

These directives define what code cannot be eliminated in the _driver wrappers_
and _Oberon drivers_. They are derived automatically and therefore need not be
configured explicitly.

### Needed crypto drivers for the application on the target platform

Syntax: PSA_NEED_OBERON__function-group__DRIVER

Parameter _function-group_: Needed function group.

- PSA_NEED_OBERON_`HASH`_DRIVER
- PSA_NEED_OBERON_`AEAD`_DRIVER
- PSA_NEED_OBERON_`CIPHER`_DRIVER
- PSA_NEED_OBERON_`MAC`_DRIVER
- PSA_NEED_OBERON_`KEY_AGREEMENT`_DRIVER
- PSA_NEED_OBERON_`ASYMMETRIC_SIGNATURE`_DRIVER
- PSA_NEED_OBERON_`ASYMMETRIC_ENCRYPTION`_DRIVER
- PSA_NEED_OBERON_`KEY_MANAGEMENT`_DRIVER
- PSA_NEED_OBERON_`KEY_DERIVATION`_DRIVER
- PSA_NEED_OBERON_`PAKE`_DRIVER
- PSA_NEED_OBERON_`CTR_DRBG`_DRIVER
- PSA_NEED_OBERON_`HMAC_DRBG`_DRIVER

### Needed algorithms for the application on the target platform (1)

Syntax: PSA_NEED_OBERON__alg

Parameter _alg_: Needed crypto algorithm.

- PSA_NEED_OBERON_`SHA_1`
- PSA_NEED_OBERON_`SHA_224`
- PSA_NEED_OBERON_`SHA_256`
- PSA_NEED_OBERON_`SHA_384`
- PSA_NEED_OBERON_`SHA_512`
- PSA_NEED_OBERON_`SHA3_224`
- PSA_NEED_OBERON_`SHA3_256`
- PSA_NEED_OBERON_`SHA3_384`
- PSA_NEED_OBERON_`SHA3_512`
- PSA_NEED_OBERON_`SHAKE256-512`

- PSA_NEED_OBERON_`HMAC`
- PSA_NEED_OBERON_`CMAC`
- PSA_NEED_OBERON_`HKDF`
- PSA_NEED_OBERON_`HKDF_EXTRACT`
- PSA_NEED_OBERON_`HKDF_EXPAND`
- PSA_NEED_OBERON_`TLS12_PRF`
- PSA_NEED_OBERON_`TLS12_PSK_TO_MS`
- PSA_NEED_OBERON_`TLS12_ECJPAKE_TO_PMS`
- PSA_NEED_OBERON_`PBKDF2_HMAC`
- PSA_NEED_OBERON_`PBKDF2_AES_CMAC_PRF_128`

### Needed algorithms for the application on the target platform (2)

Syntax: PSA_NEED_OBERON__alg__key-type

Parameter _alg_:      Needed crypto algorithm.

Parameter _key-type_: Needed key type.

- PSA_NEED_OBERON_`CCM_AES`
- PSA_NEED_OBERON_`GCM_AES`
- PSA_NEED_OBERON_`CTR_AES`
- PSA_NEED_OBERON_`CBC_PKCS7_AES`
- PSA_NEED_OBERON_`CBC_NO_PADDING_AES`
- PSA_NEED_OBERON_`ECB_NO_PADDING_AES`
- PSA_NEED_OBERON_`CCM_STAR_NO_TAG_AES`

- PSA_NEED_OBERON_`CHACHA20_POLY1305`
- PSA_NEED_OBERON_`STREAM_CIPHER_CHACHA20`

### Needed algorithms for the application on the target platform (3)

Syntax: PSA_NEED_OBERON__alg__key-type[__key-size]

Parameter _alg_:      Needed crypto algorithm.

Parameter _key-type_: Needed key type.

Parameter _key-size_: Needed key size for this key type.

- PSA_NEED_OBERON_`ECDH_SECP_R1_224`
- PSA_NEED_OBERON_`ECDH_SECP_R1_256`
- PSA_NEED_OBERON_`ECDH_SECP_R1_384`
- PSA_NEED_OBERON_`ECDH_SECP_R1_521`
- PSA_NEED_OBERON_`ECDH_MONTGOMERY_255`
- PSA_NEED_OBERON_`ECDH_MONTGOMERY_448`

- PSA_NEED_OBERON_`ECDSA_SECP_R1_224`
- PSA_NEED_OBERON_`ECDSA_SECP_R1_256`
- PSA_NEED_OBERON_`ECDSA_SECP_R1_384`
- PSA_NEED_OBERON_`ECDSA_SECP_R1_521`
- PSA_NEED_OBERON_`PURE_EDDSA_TWISTED_EDWARDS_255`
- PSA_NEED_OBERON_`PURE_EDDSA_TWISTED_EDWARDS_448`
- PSA_NEED_OBERON_`ED25519PH`
- PSA_NEED_OBERON_`ED448PH`
- PSA_NEED_OBERON_`ECDSA_DETERMINISTIC`
- PSA_NEED_OBERON_`ECDSA_RANDOMIZED`

### Needed algorithms for the application on the target platform (4)

Syntax: PSA_NEED_OBERON__ECDSA__role

Parameter _role_: SIGN or VERIFY.

- PSA_NEED_OBERON_`ECDSA_SIGN`
- PSA_NEED_OBERON_`ECDSA_VERIFY`

### Needed ECC key management for the application on the target platform

Syntax: PSA_NEED_OBERON_KEY_TYPE_ECC_KEY_PAIR__operation__[family__size]

Parameter _operation_: Needed operation.

Parameter _family_:    Needed crypto family.

Parameter _size_:      Needed key size for this crypto family.

- PSA_NEED_OBERON_KEY_TYPE_ECC_`PUBLIC_KEY`
- PSA_NEED_OBERON_KEY_TYPE_ECC_`KEY_PAIR_EXPORT`
- PSA_NEED_OBERON_KEY_TYPE_ECC_`KEY_PAIR_IMPORT`
- PSA_NEED_OBERON_KEY_TYPE_ECC_`KEY_PAIR_GENERATE`

- PSA_NEED_OBERON_KEY_TYPE_ECC_`PUBLIC_KEY_SECP_R1_224`
- PSA_NEED_OBERON_KEY_TYPE_ECC_`KEY_PAIR_EXPORT_SECP_R1_224`
- PSA_NEED_OBERON_KEY_TYPE_ECC_`KEY_PAIR_IMPORT_SECP_R1_224`
- PSA_NEED_OBERON_KEY_TYPE_ECC_`KEY_PAIR_GENERATE_SECP_R1_224`

- PSA_NEED_OBERON_KEY_TYPE_ECC_`PUBLIC_KEY_SECP_R1_256`
- PSA_NEED_OBERON_KEY_TYPE_ECC_`KEY_PAIR_EXPORT_SECP_R1_256`
- PSA_NEED_OBERON_KEY_TYPE_ECC_`KEY_PAIR_IMPORT_SECP_R1_256`
- PSA_NEED_OBERON_KEY_TYPE_ECC_`KEY_PAIR_GENERATE_SECP_R1_256`

- PSA_NEED_OBERON_KEY_TYPE_ECC_`PUBLIC_KEY_SECP_R1_384`
- PSA_NEED_OBERON_KEY_TYPE_ECC_`KEY_PAIR_EXPORT_SECP_R1_384`
- PSA_NEED_OBERON_KEY_TYPE_ECC_`KEY_PAIR_IMPORT_SECP_R1_384`
- PSA_NEED_OBERON_KEY_TYPE_ECC_`KEY_PAIR_GENERATE_SECP_R1_384`

- PSA_NEED_OBERON_KEY_TYPE_ECC_`PUBLIC_KEY_SECP_R1_521`
- PSA_NEED_OBERON_KEY_TYPE_ECC_`KEY_PAIR_EXPORT_SECP_R1_521`
- PSA_NEED_OBERON_KEY_TYPE_ECC_`KEY_PAIR_IMPORT_SECP_R1_521`
- PSA_NEED_OBERON_KEY_TYPE_ECC_`KEY_PAIR_GENERATE_SECP_R1_521`

- PSA_NEED_OBERON_KEY_TYPE_ECC_`PUBLIC_KEY_MONTGOMERY_255`
- PSA_NEED_OBERON_KEY_TYPE_ECC_`KEY_PAIR_EXPORT_MONTGOMERY_255`
- PSA_NEED_OBERON_KEY_TYPE_ECC_`KEY_PAIR_IMPORT_MONTGOMERY_255`
- PSA_NEED_OBERON_KEY_TYPE_ECC_`KEY_PAIR_GENERATE_MONTGOMERY_255`

- PSA_NEED_OBERON_KEY_TYPE_ECC_`PUBLIC_KEY_MONTGOMERY_448`
- PSA_NEED_OBERON_KEY_TYPE_ECC_`KEY_PAIR_EXPORT_MONTGOMERY_448`
- PSA_NEED_OBERON_KEY_TYPE_ECC_`KEY_PAIR_IMPORT_MONTGOMERY_448`
- PSA_NEED_OBERON_KEY_TYPE_ECC_`KEY_PAIR_GENERATE_MONTGOMERY_448`

- PSA_NEED_OBERON_KEY_TYPE_ECC_`PUBLIC_KEY_TWISTED_EDWARDS_255`
- PSA_NEED_OBERON_KEY_TYPE_ECC_`KEY_PAIR_EXPORT_TWISTED_EDWARDS_255`
- PSA_NEED_OBERON_KEY_TYPE_ECC_`KEY_PAIR_IMPORT_TWISTED_EDWARDS_255`
- PSA_NEED_OBERON_KEY_TYPE_ECC_`KEY_PAIR_GENERATE_TWISTED_EDWARDS_255`

- PSA_NEED_OBERON_KEY_TYPE_ECC_`PUBLIC_KEY_TWISTED_EDWARDS_448`
- PSA_NEED_OBERON_KEY_TYPE_ECC_`KEY_PAIR_EXPORT_TWISTED_EDWARDS_448`
- PSA_NEED_OBERON_KEY_TYPE_ECC_`KEY_PAIR_IMPORT_TWISTED_EDWARDS_448`
- PSA_NEED_OBERON_KEY_TYPE_ECC_`KEY_PAIR_GENERATE_TWISTED_EDWARDS_448`

### Needed RSA key management for the application on the target platform

Syntax: PSA_NEED_OBERON_KEY_TYPE_RSA__operation

Parameter _operation_: Needed operation.

- PSA_NEED_OBERON_KEY_TYPE_RSA_`PUBLIC_KEY`
- PSA_NEED_OBERON_KEY_TYPE_RSA_`KEY_PAIR_EXPORT`
- PSA_NEED_OBERON_KEY_TYPE_RSA_`KEY_PAIR_IMPORT`

### Needed PAKE support for the application on the target platform

Syntax: PSA_NEED_OBERON__alg[__family]

Parameter _alg_:    Needed crypto algorithm.

Parameter _family_: Needed crypto family.

- PSA_NEED_OBERON_`ECJPAKE`
- PSA_NEED_OBERON_`SPAKE2P`
- PSA_NEED_OBERON_`SRP_6`

- PSA_NEED_OBERON_`RSA_PSS`
- PSA_NEED_OBERON_`RSA_OAEP`
- PSA_NEED_OBERON_`RSA_PKCS1V15_SIGN`
- PSA_NEED_OBERON_`RSA_PKCS1V15_CRYPT`

- PSA_NEED_OBERON_`RSA_ANY_SIGN`
- PSA_NEED_OBERON_`RSA_ANY_VERIFY`
- PSA_NEED_OBERON_`RSA_ANY_CRYPT`

### Needed key sizes for the application on the target platform

Syntax: PSA_NEED_OBERON__key-type__KEY_SIZE__key-size

Parameter _key-type_: Needed key type.

Parameter _size_:     Needed key size for this key type.

- PSA_NEED_OBERON_`RSA`_KEY_SIZE_`1024`
- PSA_NEED_OBERON_`RSA`_KEY_SIZE_`1536`
- PSA_NEED_OBERON_`RSA`_KEY_SIZE_`2048`
- PSA_NEED_OBERON_`RSA`_KEY_SIZE_`3072`
- PSA_NEED_OBERON_`RSA`_KEY_SIZE_`4096`
- PSA_NEED_OBERON_`RSA`_KEY_SIZE_`6144`
- PSA_NEED_OBERON_`RSA`_KEY_SIZE_`8192`

## PSA_ACCEL Directives

These directives define, sometimes with fine granularity, what (combinations of)
crypto features are hardware-accelerated, and available through _hardware
drivers_.

### Accelerated crypto functionality (1)

Syntax: PSA_ACCEL__alg[__key-type][__key-size]

Parameter _alg_:      Accelerated crypto algorithm.

Parameter _key-type_: Accelerated key type.

Parameter _key-size_: Accelerated key size for this key type.

- PSA_ACCEL_`CCM_AES_128`
- PSA_ACCEL_`CCM_AES_192`
- PSA_ACCEL_`CCM_AES_256`
- PSA_ACCEL_`GCM_AES_128`
- PSA_ACCEL_`GCM_AES_192`
- PSA_ACCEL_`GCM_AES_256`
- PSA_ACCEL_`CTR_AES_128`
- PSA_ACCEL_`CTR_AES_192`
- PSA_ACCEL_`CTR_AES_256`
- PSA_ACCEL_`CBC_PKCS7_AES_128`
- PSA_ACCEL_`CBC_PKCS7_AES_192`
- PSA_ACCEL_`CBC_PKCS7_AES_256`
- PSA_ACCEL_`CBC_NO_PADDING_AES_128`
- PSA_ACCEL_`CBC_NO_PADDING_AES_192`
- PSA_ACCEL_`CBC_NO_PADDING_AES_256`
- PSA_ACCEL_`ECB_NO_PADDING_AES_128`
- PSA_ACCEL_`ECB_NO_PADDING_AES_192`
- PSA_ACCEL_`ECB_NO_PADDING_AES_256`
- PSA_ACCEL_`CCM_STAR_NO_TAG_AES_128`
- PSA_ACCEL_`CCM_STAR_NO_TAG_AES_192`
- PSA_ACCEL_`CCM_STAR_NO_TAG_AES_256`
- PSA_ACCEL_`CHACHA20_POLY1305`
- PSA_ACCEL_`STREAM_CIPHER_CHACHA20`

### Accelerated crypto functionality (2)

Syntax: PSA_ACCEL__alg__family__size[__hash-alg__hash-size]

Parameter _alg_:       Accelerated key type.

Parameter _family_:    Accelerated crypto family.

Parameter _size_:      Accelerated key size for this crypto family.

Parameter _hash-alg_:  Accelerated hash algorithm.

Parameter _hash-size_: Accelerated hash size.

- PSA_ACCEL_`ECDH_SECP_R1_224`
- PSA_ACCEL_`ECDH_SECP_R1_256`
- PSA_ACCEL_`ECDH_SECP_R1_384`
- PSA_ACCEL_`ECDH_SECP_R1_521`
- PSA_ACCEL_`ECDH_MONTGOMERY_255`
- PSA_ACCEL_`ECDH_MONTGOMERY_448`

- PSA_ACCEL_`ECDSA_SECP_R1_224_SHA_1`
- PSA_ACCEL_`ECDSA_SECP_R1_224_SHA_224`
- PSA_ACCEL_`ECDSA_SECP_R1_224_SHA_256`
- PSA_ACCEL_`ECDSA_SECP_R1_224_SHA_384`
- PSA_ACCEL_`ECDSA_SECP_R1_224_SHA_512`
- PSA_ACCEL_`ECDSA_SECP_R1_256_SHA_1`
- PSA_ACCEL_`ECDSA_SECP_R1_256_SHA_224`
- PSA_ACCEL_`ECDSA_SECP_R1_256_SHA_256`
- PSA_ACCEL_`ECDSA_SECP_R1_256_SHA_384`
- PSA_ACCEL_`ECDSA_SECP_R1_256_SHA_512`
- PSA_ACCEL_`ECDSA_SECP_R1_384_SHA_1`
- PSA_ACCEL_`ECDSA_SECP_R1_384_SHA_224`
- PSA_ACCEL_`ECDSA_SECP_R1_384_SHA_256`
- PSA_ACCEL_`ECDSA_SECP_R1_384_SHA_384`
- PSA_ACCEL_`ECDSA_SECP_R1_384_SHA_512`
- PSA_ACCEL_`PURE_EDDSA_TWISTED_EDWARDS_255`
- PSA_ACCEL_`PURE_EDDSA_TWISTED_EDWARDS_448`

### Accelerated crypto functionality (3)

Syntax: PSA_ACCEL__hash-alg__size

Parameter _alg_:       Accelerated crypto algorithm.

Parameter _hash-size_: Accelerated hash size for this crypto algorithm.

- PSA_ACCEL_`SHA_1`
- PSA_ACCEL_`SHA_224`
- PSA_ACCEL_`SHA_256`
- PSA_ACCEL_`SHA_384`
- PSA_ACCEL_`SHA_512`
- PSA_ACCEL_`SHA3_224`
- PSA_ACCEL_`SHA3_256`
- PSA_ACCEL_`SHA3_384`
- PSA_ACCEL_`SHA3_512`
- PSA_ACCEL_`SHAKE256-512`

### Accelerated ECC key management functionality

Syntax: PSA_ACCEL__KEY_TYPE_ECC__operation[__family__key-size]

Parameter _operation_: Accelerated operation.

Parameter _family_: Accelerated crypto family.

Parameter _key-size_:  Accelerated key size for this key type.

- PSA_ACCEL_KEY_TYPE_ECC_`PUBLIC_KEY_SECP_R1_224`
- PSA_ACCEL_KEY_TYPE_ECC_`KEY_PAIR_IMPORT_SECP_R1_224`
- PSA_ACCEL_KEY_TYPE_ECC_`KEY_PAIR_EXPORT_SECP_R1_224`
- PSA_ACCEL_KEY_TYPE_ECC_`KEY_PAIR_GENERATE_SECP_R1_224`

- PSA_ACCEL_KEY_TYPE_ECC_`PUBLIC_KEY_SECP_R1_256`
- PSA_ACCEL_KEY_TYPE_ECC_`KEY_PAIR_IMPORT_SECP_R1_256`
- PSA_ACCEL_KEY_TYPE_ECC_`KEY_PAIR_EXPORT_SECP_R1_256`
- PSA_ACCEL_KEY_TYPE_ECC_`KEY_PAIR_GENERATE_SECP_R1_256`

- PSA_ACCEL_KEY_TYPE_ECC_`PUBLIC_KEY_SECP_R1_384`
- PSA_ACCEL_KEY_TYPE_ECC_`KEY_PAIR_IMPORT_SECP_R1_384`
- PSA_ACCEL_KEY_TYPE_ECC_`KEY_PAIR_EXPORT_SECP_R1_384`
- PSA_ACCEL_KEY_TYPE_ECC_`KEY_PAIR_GENERATE_SECP_R1_384`

- PSA_ACCEL_KEY_TYPE_ECC_`PUBLIC_KEY_SECP_R1_521`
- PSA_ACCEL_KEY_TYPE_ECC_`KEY_PAIR_IMPORT_SECP_R1_521`
- PSA_ACCEL_KEY_TYPE_ECC_`KEY_PAIR_EXPORT_SECP_R1_521`
- PSA_ACCEL_KEY_TYPE_ECC_`KEY_PAIR_GENERATE_SECP_R1_521`

- PSA_ACCEL_KEY_TYPE_ECC_`PUBLIC_KEY_MONTGOMERY_255`
- PSA_ACCEL_KEY_TYPE_ECC_`KEY_PAIR_IMPORT_MONTGOMERY_255`
- PSA_ACCEL_KEY_TYPE_ECC_`KEY_PAIR_EXPORT_MONTGOMERY_255`
- PSA_ACCEL_KEY_TYPE_ECC_`KEY_PAIR_GENERATE_MONTGOMERY_255`

- PSA_ACCEL_KEY_TYPE_ECC_`PUBLIC_KEY_MONTGOMERY_448`
- PSA_ACCEL_KEY_TYPE_ECC_`KEY_PAIR_IMPORT_MONTGOMERY_448`
- PSA_ACCEL_KEY_TYPE_ECC_`KEY_PAIR_EXPORT_MONTGOMERY_448`
- PSA_ACCEL_KEY_TYPE_ECC_`KEY_PAIR_GENERATE_MONTGOMERY_448`

- PSA_ACCEL_KEY_TYPE_ECC_`PUBLIC_KEY_TWISTED_EDWARDS_255`
- PSA_ACCEL_KEY_TYPE_ECC_`KEY_PAIR_IMPORT_TWISTED_EDWARDS_255`
- PSA_ACCEL_KEY_TYPE_ECC_`KEY_PAIR_EXPORT_TWISTED_EDWARDS_255`
- PSA_ACCEL_KEY_TYPE_ECC_`KEY_PAIR_GENERATE_TWISTED_EDWARDS_255`

- PSA_ACCEL_KEY_TYPE_ECC_`PUBLIC_KEY_TWISTED_EDWARDS_448`
- PSA_ACCEL_KEY_TYPE_ECC_`KEY_PAIR_IMPORT_TWISTED_EDWARDS_448`
- PSA_ACCEL_KEY_TYPE_ECC_`KEY_PAIR_EXPORT_TWISTED_EDWARDS_448`
- PSA_ACCEL_KEY_TYPE_ECC_`KEY_PAIR_GENERATE_TWISTED_EDWARDS_448`

### Accelerated RSA key management functionality

Syntax: PSA_ACCEL__KEY_TYPE_RSA__operation

Parameter _operation_: Accelerated operation.

- PSA_ACCEL_KEY_TYPE_RSA_`PUBLIC_KEY`
- PSA_ACCEL_KEY_TYPE_RSA_`KEY_PAIR_IMPORT`
- PSA_ACCEL_KEY_TYPE_RSA_`KEY_PAIR_EXPORT`

### Accelerated key sizes

Syntax: PSA_ACCEL__alg__key-type__key-size

Parameter _alg_:      Accelerated crypto algorithm.

Parameter _key-type_: Accelerated key type.

Parameter _key-size_: Accelerated key size for this key type.

- PSA_ACCEL_`CMAC_AES_128`
- PSA_ACCEL_`CMAC_AES_192`
- PSA_ACCEL_`CMAC_AES_256`

### Accelerated crypto functionality (4)

Syntax: PSA_ACCEL__alg[__hash-alg__hash-size]

Parameter _alg_:       Accelerated crypto algorithm.

Parameter _hash-alg_:  Accelerated hash algorithm.

Parameter _hash-size_: Accelerated hash size for this hash algorithm.

- PSA_ACCEL_`HKDF_SHA_1`
- PSA_ACCEL_`HKDF_SHA_224`
- PSA_ACCEL_`HKDF_SHA_256`
- PSA_ACCEL_`HKDF_SHA_384`
- PSA_ACCEL_`HKDF_SHA_512`
- PSA_ACCEL_`HKDF_EXTRACT_SHA_1`
- PSA_ACCEL_`HKDF_EXTRACT_SHA_224`
- PSA_ACCEL_`HKDF_EXTRACT_SHA_256`
- PSA_ACCEL_`HKDF_EXTRACT_SHA_384`
- PSA_ACCEL_`HKDF_EXTRACT_SHA_512`

- PSA_ACCEL_`HKDF_EXPAND_SHA_1`
- PSA_ACCEL_`HKDF_EXPAND_SHA_224`
- PSA_ACCEL_`HKDF_EXPAND_SHA_256`
- PSA_ACCEL_`HKDF_EXPAND_SHA_384`
- PSA_ACCEL_`HKDF_EXPAND_SHA_512`

- PSA_ACCEL_`TLS12_PRF_SHA_256`
- PSA_ACCEL_`TLS12_PRF_SHA_384`
- PSA_ACCEL_`TLS12_PSK_TO_MS_SHA_256`
- PSA_ACCEL_`TLS12_PSK_TO_MS_SHA_384`
- PSA_ACCEL_`TLS12_ECJPAKE_TO_PMS`

- PSA_ACCEL_`PBKDF2_HMAC_SHA_1`
- PSA_ACCEL_`PBKDF2_HMAC_SHA_224`
- PSA_ACCEL_`PBKDF2_HMAC_SHA_256`
- PSA_ACCEL_`PBKDF2_HMAC_SHA_384`
- PSA_ACCEL_`PBKDF2_HMAC_SHA_512`
- PSA_ACCEL_`PBKDF2_AES_CMAC_PRF_128`

### Accelerated crypto functionality (5)

Syntax: PSA_ACCEL__alg__key-type__key-size__hash-alg__hash-size

Parameter _alg_:       Accelerated crypto algorithm.

Parameter _key-type_:  Accelerated key type.

Parameter _key-size_:  Accelerated key size for this key type.

Parameter _hash-alg_:  Accelerated hash algorithm.

Parameter _hash-size_: Accelerated hash size for this hash algorithm.

- PSA_ACCEL_`ECJPAKE_SECP_R1_256_SHA_1`
- PSA_ACCEL_`ECJPAKE_SECP_R1_256_SHA_224`
- PSA_ACCEL_`ECJPAKE_SECP_R1_256_SHA_256`
- PSA_ACCEL_`ECJPAKE_SECP_R1_256_SHA_384`
- PSA_ACCEL_`ECJPAKE_SECP_R1_256_SHA_512`

- PSA_ACCEL_`SPAKE2P_SECP_R1_256_SHA_1`
- PSA_ACCEL_`SPAKE2P_SECP_R1_256_SHA_224`
- PSA_ACCEL_`SPAKE2P_SECP_R1_256_SHA_256`
- PSA_ACCEL_`SPAKE2P_SECP_R1_256_SHA_384`
- PSA_ACCEL_`SPAKE2P_SECP_R1_256_SHA_512`

- PSA_ACCEL_`SRP_6_3072_SHA_1`
- PSA_ACCEL_`SRP_6_3072_SHA_224`
- PSA_ACCEL_`SRP_6_3072_SHA_256`
- PSA_ACCEL_`SRP_6_3072_SHA_384`
- PSA_ACCEL_`SRP_6_3072_SHA_512`

### Accelerated RSA functionality

Syntax: PSA_ACCEL__alg__key-size[__hash-alg__hash-size]

Parameter _alg_:       Accelerated crypto algorithm.

Parameter _key-size_:  Accelerated key size for this key type.

Parameter _hash-alg_:  Accelerated hash algorithm.

Parameter _hash-size_: Accelerated hash size for this hash algorithm.

- PSA_ACCEL_`RSA_PSS_1024_SHA_1`
- PSA_ACCEL_`RSA_PSS_1024_SHA_224`
- PSA_ACCEL_`RSA_PSS_1024_SHA_256`
- PSA_ACCEL_`RSA_PSS_1024_SHA_384`
- PSA_ACCEL_`RSA_PSS_1024_SHA_512`

- PSA_ACCEL_`RSA_OAEP_1024_SHA_1`
- PSA_ACCEL_`RSA_OAEP_1024_SHA_224`
- PSA_ACCEL_`RSA_OAEP_1024_SHA_256`
- PSA_ACCEL_`RSA_OAEP_1024_SHA_384`
- PSA_ACCEL_`RSA_OAEP_1024_SHA_512`

- PSA_ACCEL_`RSA_PKCS1V15_SIGN_1024_SHA_1`
- PSA_ACCEL_`RSA_PKCS1V15_SIGN_1024_SHA_224`
- PSA_ACCEL_`RSA_PKCS1V15_SIGN_1024_SHA_256`
- PSA_ACCEL_`RSA_PKCS1V15_SIGN_1024_SHA_384`
- PSA_ACCEL_`RSA_PKCS1V15_SIGN_1024_SHA_512`
- PSA_ACCEL_`RSA_PKCS1V15_CRYPT_1024`

- ... same for all other RSA key sizes ...

### Accelerated RNG functionality

Syntax: PSA_ACCEL__function

Parameter _function_: Accelerated RNG-related function.

- PSA_ACCEL_`GENERATE_RANDOM`
- PSA_ACCEL_`GET_ENTROPY`
