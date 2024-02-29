# Oberon PSA Crypto change log

## Oberon PSA Crypto 1.2.1
https://github.com/oberon-microsystems/oberon-psa-crypto-nrf/releases/tag/v1.2.1

25-Jan-2024 (7462663)

Oberon crypto software drivers require _ocrypto_ version 3.5.x.

### New Features
- Add counter-mode KDF variants for HMAC and CMAC (NIST SP 800-108r1).
  - Add software crypto driver implementation.
  - Add test vectors from mbedtls/examples.
- Add functions `psa_key_derivation_verify_bytes()` and `psa_key_derivation_verify_key()`.

### Improvements
- Optimize macros `PSA_EXPORT_PUBLIC_KEY_OUTPUT_SIZE` and `PSA_EXPORT_KEY_OUTPUT_SIZE`
  for non NIST key types.
- Refine configuration for crypto primitives currently not supported in software.

### Bug Fixes
- Bug 11: RSA sign falsely requires setting `PSA_WANT_KEY_TYPE_ECC_KEY_PAIR_BASIC`.
- Bug 12: Wrong Spake2+ TT hash calculation in get key share step.

--------------------------------------------------------------------------------

## Oberon PSA Crypto 1.2.0
https://github.com/oberon-microsystems/oberon-psa-crypto-nrf/releases/tag/v1.2.0>

2-Nov-2023 (9ba9ec6)

Oberon crypto software drivers require _ocrypto_ version 3.5.x.

### New Features
- Add software drivers:
  - Twisted Edwards curve Ed448, Ed448ph (EdDSA).
  - Montgomery curve X448 (ECDH).
  - P-521 aka secp521r1 (ECDSA and ECDH).
  - Ed25519ph, i.e., Ed25519 with prehashing.
  - SHA-3 family of cryptographic hash functions
    - SHA-3 for hash sizes: 224, 256, 384, 512 (FIPS-PUB-202).
    - SHAKE256-512 (FIPS-PUB-202).
- Update SSL-test PoC for Mbed TLS 3.5.0.
- Add newly introduced PSA_WANT configuration options for dead
  code elimination of key pairs, i.e., break down `PSA_WANT_KEY_TYPE_*`
  into BASIC, IMPORT, EXPORT, GENERATE, and DERIVE.
- Add Security Vulnerability Table to Bug Tracking document.

### Breaking Changes
- Align with Mbed TLS 3.5.0.
- Require ocrypto 3.5.x.
- Avoid the need for dynamic memory allocation in the PAKE drivers by
  deviating from the Mbed TLS PSA Driver specification draft API for PAKE:
  The setup function `psa_driver_wrapper_pake_setup` is used to provide all
  buffered PAKE parameters in one go.

### Improvements
- Correct build time warning if `PSA_WANT_ECC_SECP_K1_192` set and
  `PSA_ACCEL_ECC_SECP_K1_224` not set.
- Correct experimental feature `SPAKE2P_USE_VERSION_04` to support SPAKE2+
  draft used in Matter.
- Make build time dependency to demo platform conditional.
- Adapt driver wrapper according to new functionality.
- Improve dead code elimination in driver wrapper and drivers.
- Update LICENSING text.

### Bug Fixes
- Bug 9: Dynamic memory not freed in `psa_key_derivation_output_key` when
  called with invalid ECC key size.
- Bug 10: `Macros PSA_*_MAX_SIZE` return wrong values for RSA key size greater than 4096:
  - `PSA_SIGNATURE_MAX_SIZE`
  - `PSA_ASYMMETRIC_ENCRYPT_OUTPUT_MAX_SIZE`
  - `PSA_ASYMMETRIC_DECRYPT_OUTPUT_MAX_SIZE`
  - `PSA_EXPORT_KEY_PAIR_MAX_SIZE`
  - `PSA_EXPORT_PUBLIC_KEY_MAX_SIZE`

--------------------------------------------------------------------------------

## Oberon PSA Crypto 1.1.1
https://github.com/oberon-microsystems/oberon-psa-crypto-nrf/releases/tag/v1.1.1>

26-Sep-2023 (d3c90ec)

Oberon crypto software drivers require _ocrypto_ version 3.4.x.

### Improvements
- Clarify licensing.

### Bug Fixes
- Bug 6: Fix elliptic curve key generation in case `psa_generate_random` 
  returned zero.

- Bug 7: Avoid EC-JPAKE output step failure in case `psa_generate_random` 
  returned zero or a value greater or equal to the curve's group order. 

- Bug 8: Fix CBC PKCS padding verification during encryption for (invalid) 
  paddings that have a zero as the last value. Fixed by updating ocrypto 
  dependency to version 3.4.0.

--------------------------------------------------------------------------------

## Oberon PSA Crypto 1.1.0
https://github.com/oberon-microsystems/oberon-psa-crypto-nrf/releases/tag/v1.1.0>

3-Aug-2023 (33b95ee)

_Oberon drivers_ require _ocrypto_ version 3.3.x.

### Improvements
- Rename PSA_USE/NEED/ACCEL to make the names more regular and consistent with PSA names.
- Add docu Appendix B with PSA_WANT/USE/NEED/ACCEL directives.
- Clean up markdown formatting (markdownlint).
- Allow empty user id and peer id in experimental SPAKE2P implementation, for Matter compatibility.
- Prevent more than one DRBG driver to be used at the same time.

--------------------------------------------------------------------------------

## Oberon PSA Crypto 1.0.8
https://github.com/oberon-microsystems/oberon-psa-crypto-nrf/releases/tag/v1.0.8>

20-Jul-2023 (c8ad02f)

Oberon crypto software drivers require _ocrypto_ version 3.3.x.

### Improvements
- Refactor the product's terminology and update the documentation accordingly.
- Update PSA architecture tests to V1.5.

--------------------------------------------------------------------------------

## Oberon PSA Crypto 1.0.7
4-Jul-2023 (14c40c8)

Oberon crypto software drivers require _ocrypto_ version 3.3.x.

### New Features
- Add optional SPAKE2+ context input.

### Improvements
- Add PBKDF2 tests.
- Add PAKE tests.
- Refactor CMake build.
- Clean up docu and licensing.
- Fix memory management in opaque demo driver.

### Bug Fixes
- Bug 5: Fix handling of KEY_TYPE_PEPPER and INPUT_PASSWORD in PBKDF2.

--------------------------------------------------------------------------------

## Oberon PSA Crypto 1.0.6
11-May-2023 (c3cfd8b)

Oberon crypto software drivers require _ocrypto_ version 3.3.x.

### Improvements
- Align error code in `psa_key_derivation_setup` with Mbed TLS.
- Align documentation with _PSA Certified_ naming rules.

### Bug Fixes
- Bug 2: Add overflow checks in drivers for KDF.
- Bug 3: Add overflow checks in drivers for AEAD.
- Bug 4: Handle empty salt for HKDF.

### Contributions
Part of the changes are based on the following reports contributed by Nordic:
- Bug 2: Out of memory error in `oberon_key_derivation_input_bytes` when key 
  derivation called with `PSA_KEY_DERIVATION_INPUT_LABEL`, `data_length 0xffffffff`.
- Bug 4: Calling `oberon_key_derivation_input_bytes` in HKDF with empty salt leads to 
  a failure calling setup of the MAC operation twice.
- Align with Mbed TLS: return `PSA_ERROR_NOT_SUPPORTED` if `psa_key_derivation_setup`
  is called with wrong hash algorithm.

---------------------------------------------------------------------------------

## Oberon PSA Crypto 1.0.5
9-May-2023 (e89c91a)

Oberon crypto software drivers require _ocrypto_ version 3.3.x.

### Improvements
- More robust context initialization in Oberon drivers.
- More robust `mac_abort` handling in Oberon drivers.
- Align PSA_WANT superset for all `crypto_config.h`.
- Avoid warnings.

---------------------------------------------------------------------------------

## Oberon PSA Crypto 1.0.4
27-Apr-2023 (9684ba0)

Oberon crypto software drivers require _ocrypto_ version 3.3.x.

### Improvements
- Remove blank lines at end of files.
- Add space as workaround for Doxygen issue.

---------------------------------------------------------------------------------

## Oberon PSA Crypto 1.0.3
25-Apr-2023 (d39d0ef)

Oberon crypto software drivers require _ocrypto_ version 3.3.x.

### Improvements
- Cleanup to avoid warnings.
- Fix error message of algorithms.
- Add TF-M builtin key driver. This matches changes done to mbedtls in the TF-M.
  out-of-tree patch: 0004-Add-TF-M-builtin-key-driver.patch.

### Contributions
Part of the changes are based on the following patches contributed by Nordic:
- oberon-config-error-messages.diff (49556e2)
- psa-core-tfm-builtin-key-loader.diff (29434b4)

---------------------------------------------------------------------------------

## Oberon PSA Crypto 1.0.2
30-Mar-2023 (fa92be9)

Oberon crypto software drivers require _ocrypto_ 3.3.x.

### Improvements
- Add Mbed TLS header files `memory_buffer_alloc.h` and `sha256.h` required by 
  some configurations in `mbedtls_config.h`.
- Add documentation for cycle tests: _README-CYCLES.md_.

---------------------------------------------------------------------------------

## Oberon PSA Crypto 1.0.1
21-Mar-2023 (eaaf9b7)

Oberon crypto software drivers require _ocrypto_ 3.3.x.

### Improvements
- Update _PSA Certified APIs Architecture Test Suite_ to commit hash 36268a9 of 
  https://github.com/ARM-software/psa-arch-tests/tree/main/api-tests/dev_apis
- Cleanup syntax for initializers used for operation structs.
- Add parentheses to avoid compiler warnings in boolean expressions.
- Remove path to wrapper in Oberon driver includes.

### Bug Fixes
- Bug 1: Fixed out of memory error in `psa_key_derivation_output_bytes` when using
  key derivation to generate a key pair and supplying wrong key attributes.

--------------------------------------------------------------------------------

## Oberon PSA Crypto 1.0.0
23-Feb-2023

Oberon crypto software drivers require _ocrypto_ 3.3.0.

### Features
- PSA API crypto functionality
  - Implements PSA Certified Crypto API 1.1.1 and PAKE extension 1.1 Beta 1
  - Implements PSA Crypto Driver API
  - Aligned with Mbed TLS 3.3 while maintaining Mbed TLS 3.2.1 compatibility
- PSA Key management
  - Uses PSA Certified Secure Storage API 1.0
  - Redistributes _Mbed TLS_ default implementations for 
    _Internal Trusted Storage API (ITS)_ and _Protected Storage API (PS)_
- PSA Crypto Driver implementations that target Oberon's _ocrypto_ software library
  - Message digest (hashes)
    - SHA1, SHA224, SHA256, SHA384, SHA512
  - Message authentication codes (MAC)
    - HMAC, AES-CMAC
  - Unauthenticated ciphers
    - AES CTR, CCM*, CBC, ECB
  - Authenticated encryption with associated data (AEAD)
    - AES CCM, GCM
    - AEAD-ChaCha20-Poly1305
  - Key derivation
    - HKDF
    - PKDF2-HMAC
    - PKDF2-AES-CMAC-PRF128
    - TLS-1.2 PRF
    - TLS-1.2 PSK-to-Mastersecret
    - TLS-1.2 ECJPAKE-to-PMS KDF
  - Asymmetric signature/encryption
    - RSA with 1024, 1536, 2048, 4096, 6144, and 8192 bit keys
    - RSAES PKCS-v1.5 / OAEP
    - RSASSA PKCS-v1.5 / PSS
    - ECDSA P224, P256, P384
    - Ed25519
  - Key agreement
    - ECDH P224, P256, P384
    - X25519
  - Password-authenticated key exchange (PAKE)
    - EC-JPAKE P256
    - SPAKE2+ P256 HMAC
    - SRP-6 3072 bit
  - Random number generation
    - CTR-DRBG
    - HMAC-DRBG
- Driver chaining for optimizing the mix of software and hardware crypto drivers
  - Signature → Hash
  - Deterministic signature → HMAC
  - HKDF → HMAC
  - HMAC → Hash
  - CMAC → AES
  - HMAC-DRBG → HMAC
  - CTR-DRBG → AES-ECB, AES-CMAC
  - DRBG → Entropy
  - RSA → HASH
- Dead code elimination
  - Eliminate code for non-configured algorithms and key types
  - Eliminate code for non-configured key sizes
- Tests
  - PSA Certified APIs Architecture Test Suite
  - Mbed TLS 3.3 PSA test suite
    - With minor test adaptations and corrections
  - Mbed TLS 3.3 SSL test suite
    - Use Mbed TLS 3.3 for TLS protocol
    - Use Oberon PSA Crypto for cryptographic functions
- Cycle count benchmarks
  - Keil project for M0
  - Keil project for M4F
- Documentation
  - README for overview, build and test
  - Application developer documentation
  - Driver developer documentation
  - Bug Tracking
  - Migration notes from Mbed TLS to Oberon PSA Crypto
- Platform examples
  - Demo platform
    - Configuration examples
    - Driver examples (not for use in production)
      - Entropy Driver
      - Opaque Driver
      - Hardware Driver (HASH, AES)
    - Driver Wrapper example
  - Nordic_nrf platform
    - Configuration examples
    - CryptoCell Driver Interface template for Nordic platform
    - Driver Wrapper example
- Miscellaneous
  - Allow for renaming of `psa_generate_random` function, to avoid symbol collision
    in some build systems
  - Support for non-standard RSA public key format used in Mbed TLS ssl test suite
  - CMake file to build Mbed TLS 3.3 ssl programs _ssl_client2_ and _ssl_server2_ using 
    Mbed TLS 3.3 for TLS protocol and Oberon PSA Crypto for cryptographic functions
