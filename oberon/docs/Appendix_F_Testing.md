# Appendix F: Testing

The actual cryptographic functions provided by _Oberon PSA Crypto_ are
implemented in _Oberon microsystems'_ _ocrypto_ library. An extensive test suite
is run for every release of _ocrypto_, with test vectors from the official
standards, test vectors for border cases, negative tests, and random tests.

For testing _Oberon PSA Crypto_ compatibility using the _ocrypto_ implementation,
_Oberon microsystems_ uses the _PSA Certified APIs Architecture Test Suite_.

In addition, _Oberon microsystems_ also runs these PSA-related _Mbed TLS_ tests:

- `test_suite_psa_crypto`
- `test_suite_psa_crypto_attributes`
- `test_suite_psa_crypto_driver_wrappers`
- `test_suite_psa_crypto_entropy`
- `test_suite_psa_crypto_generate_key.generated`
- `test_suite_psa_crypto_hash`
- `test_suite_psa_crypto_metadata`
- `test_suite_psa_crypto_not_supported.generated`
- `test_suite_psa_crypto_not_supported.misc`
- `test_suite_psa_crypto_op_fail.misc`
- `test_suite_psa_crypto_persistent_key`
- `test_suite_psa_crypto_slot_management`
- `test_suite_psa_crypto_storage_format.current`
- `test_suite_psa_crypto_storage_format.misc`
- `test_suite_psa_crypto_storage_format.v0`
- `test_suite_psa_its`

_Driver developers_ and _platform integrators_ should run the same tests with
suitable test configurations of _Oberon PSA Crypto_. See the
[README](../../README.md)
document for more information on how to build and run the tests.
