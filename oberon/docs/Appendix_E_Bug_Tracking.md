# Appendix E: Bug Tracking

This document contains a list of the known bugs in _Oberon PSA Crypto_, as well
as a list of security vulnerabilities.

## Bug Table

Bugs that have been both introduced in pre-release versions of the software, and
fixed in the final versions of the corresponding releases, are not included in
the following table. Neither included are bugs in experimental features (e.g.,
the PAKE implementation based on beta API specifications).

| Bug ID | Fixed in Release | Title                                                     | Description                                                                                                                                                |
| ------:|:---------------- |:--------------------------------------------------------- |:---------------------------------------------------------------------------------------------------------------------------------------------------------- |
|     12 | 1.2.1            | Wrong Spake2+ TT hash calculation.                        | Wrong Spake2+ TT hash calculation in get key share step.                                                                                                   | 
|     11 | 1.2.1            | RSA sign falsely depends on ECC configuration.            | RSA sign falsely requires setting `PSA_WANT_KEY_TYPE_ECC_KEY_PAIR_BASIC` in crypto_config.                                                                 | 
|     10 | 1.2.0            | Size macros are wrong for RSA key size greater than 4096  | Macros `PSA_*_MAX_SIZE` return wrong values for RSA key size greater than 4096.                                                                            | 
|      9 | 1.2.0            | Dynamic memory not freed for invalid ECC key size         | Dynamic memory not freed in `psa_key_derivation_output_key` when called with invalid ECC key size.                                                         |
|      8 | 1.1.1            | CBC PKCS padding verification during encryption           | CBC PKCS accepts invalid paddings having zero as the last value; fixed in ocrypto 3.4.0                                                                    |
|      7 | 1.1.1            | Avoid EC-JPAKE output step failure                        | Avoid EC-JPAKE output step failure in case `psa_generate_random` returned zero or a value greater or equal to the curve's group order.                     |
|      6 | 1.1.1            | Elliptic curve key generation for edge case               | Fix elliptic curve key generation in the theoretically possible case that `psa_generate_random` returned zero.                                             |
|      5 | 1.0.7            | Handling of KEY_TYPE_PEPPER and INPUT_PASSWORD in PBKDF2  | Fix handling of KEY_TYPE_PEPPER and INPUT_PASSWORD in PBKDF2.                                                                                              |
|      4 | 1.0.6            | Duplicate MAC operation for key derivation on empty salt  | Calling `oberon_key_derivation_input_bytes` in HKDF with empty salt leads to a failure calling setup of the MAC operation twice.                           |
|      3 | 1.0.6            | Out of memory for AEAD with huge tag length               | Out of memory error in `oberon_aead_encrypt` when AEAD encrypt called with huge tag.                                                                       |
|      2 | 1.0.6            | Out of memory for key derivation with huge data length    | Out of memory error in `oberon_key_derivation_input_bytes` when key derivation called with `PSA_KEY_DERIVATION_INPUT_LABEL`, `data_length` = `0xffffffff`. |
|      1 | 1.0.1            | Out of memory for key derivation and wrong key attributes | Out of memory error in `psa_key_derivation_output_bytes` when using key derivation to generate a key pair and supplying wrong key attributes.              |

## Security Vulnerability Table

Some bugs may result in security vulnerabilities. Such vulnerabilities are
tracked in a separate table with CVEs (Common Vulnerabilities and Exposures):

| CVE ID         | Bug ID | Affected Versions | Severity | Description                                                                                             |
| --------------:| ------:|:----------------- |:-------- |:------------------------------------------------------------------------------------------------------- |
|                |        |                   |          |                                                                                                         |

So far, there are no known security vulnerabilities.

If you have found a potential vulnerability, please report it via your Slack
support channel, or via <vulnerability@oberon.ch>.
