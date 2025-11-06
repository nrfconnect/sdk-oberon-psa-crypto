# Appendix E: Bug Tracking

This document contains a list of the known bugs in _Oberon PSA Crypto_, as well
as a list of security vulnerabilities.

## Bug Table

Bugs are tracked in the following table; bugs resulting in security
vulnerabilities are listed in a separate table below.

| Bug ID | Fixed in Release | Title                                                     | Description                                                                                                                                                |
| ------:|:---------------- |:--------------------------------------------------------- |:---------------------------------------------------------------------------------------------------------------------------------------------------------- |
|     18 | 1.5.2            | Wrong check for SRP password hashing                      | KDF driver checks for `OBERON_PBKDF2_HMAC_ALG` instead of `OBERON_SRP_PASSWORD_HASH_ALG`.                                                                  |
|     17 | 1.5.2            | Violation of PSA spec in AES-CBC buffer handling          | AES-CBC always required passing a buffer of length 16 even for blocks with padding data.                                                                   |
|     16 | 1.4.0            | Wrong buffer size calculation for Ed488                   | Wrong size of `PSA_VENDOR_ECC_MAX_CURVE_BITS`, `PSA_EXPORT_KEY_PAIR_MAX_SIZE`, `PSA_SIGNATURE_MAX_SIZE`.                                                   |
|     15 | 1.4.0            | Wrong handling of ED25519 and ED448 with pre-hashing      | Wrong handling of ED25519 and ED448 with pre-hashing when used with `psa_sign_message()` or `psa_verify_message()`.                                        |
|     14 | 1.4.0            | Incomplete checks for PSA_ALG_SP800_108 in key derivation | Key compatibility checking in key derivation incomplete for `PSA_ALG_SP800_108_COUNTER_CMAC` and `PSA_ALG_SP800_108_COUNTER_HMAC`.                         |
|     13 | 1.3.1            | MAC setup function not enabled in all cases               | MAC setup function in Oberon drivers not enabled if `PSA_ALG_IS_TLS12_PSK_TO_MS` or `PSA_ALG_IS_TLS12_PRF`.                                                |
|     12 | 1.2.1            | Wrong Spake2+ TT hash calculation                         | Wrong Spake2+ TT hash calculation in get key share step.                                                                                                   |
|     11 | 1.2.1            | RSA sign falsely depends on ECC configuration             | RSA sign falsely requires setting `PSA_WANT_KEY_TYPE_ECC_KEY_PAIR_BASIC` in crypto_config.                                                                 |
|     10 | 1.2.0            | Size macros are wrong for RSA key size greater than 4096  | Macros `PSA_*_MAX_SIZE` return wrong values for RSA key size greater than 4096.                                                                            |
|      9 | 1.2.0            | Dynamic memory not freed for invalid ECC key size         | Dynamic memory not freed in `psa_key_derivation_output_key` when called with invalid ECC key size.                                                         |
|      8 | 1.1.1            | CBC PKCS padding verification during encryption           | CBC PKCS accepts invalid paddings having zero as the last value; fixed in ocrypto 3.4.0.                                                                   |
|      7 | 1.1.1            | Avoid EC-JPAKE output step failure                        | Avoid EC-JPAKE output step failure in case `psa_generate_random` returned zero or a value greater or equal to the curve's group order.                     |
|      6 | 1.1.1            | Elliptic curve key generation for edge case               | Fix elliptic curve key generation in the theoretically possible case that `psa_generate_random` returned zero.                                             |
|      5 | 1.0.7            | Handling of KEY_TYPE_PEPPER and INPUT_PASSWORD in PBKDF2  | Fix handling of KEY_TYPE_PEPPER and INPUT_PASSWORD in PBKDF2.                                                                                              |
|      4 | 1.0.6            | Duplicate MAC operation for key derivation on empty salt  | Calling `oberon_key_derivation_input_bytes` in HKDF with empty salt leads to a failure calling setup of the MAC operation twice.                           |
|      3 | 1.0.6            | Out of memory for AEAD with huge tag length               | Out of memory error in `oberon_aead_encrypt` when AEAD encrypt called with huge tag.                                                                       |
|      2 | 1.0.6            | Out of memory for key derivation with huge data length    | Out of memory error in `oberon_key_derivation_input_bytes` when key derivation called with `PSA_KEY_DERIVATION_INPUT_LABEL`, `data_length` = `0xffffffff`. |
|      1 | 1.0.1            | Out of memory for key derivation and wrong key attributes | Out of memory error in `psa_key_derivation_output_bytes` when using key derivation to generate a key pair and supplying wrong key attributes.              |

Bugs that have been introduced in pre-release versions of the software but
fixed in the final versions of the corresponding releases are not included.
Similarly, bugs in experimental features (e.g., a PQC implementation based on a
beta API specification) are not included.

## Security Vulnerability Table

Some bugs may result in security vulnerabilities. Such vulnerabilities are
tracked separately in the following table with CVEs (Common Vulnerabilities and
Exposures):

| CVE ID         |  Affected Versions                                          | Severity | Description                                                                           |
| --------------:| :---------------------------------------------------------- |:-------- |:------------------------------------------------------------------------------------- |
| CVE-2025-9071  |  1.0.0 <= version <= 1.5.1 without `rsa_oaep_padding.patch` | low      | Insecure RSA-OAEP implementation with all-zero seed for padding in Oberon PSA Crypto. |
| CVE-2025-7383  |  1.0.0 <= version <= 1.5.0                                  | medium   | Timing side-channel vulnerability in AES-CBC decryption with PKCS#7 padding.          |

If you have found a potential vulnerability, please report it via your Slack
support channel, or via <vulnerability@oberon.ch>.
