# Appendix D: Mbed TLS

Below, two scenarios are discussed relating to _Mbed TLS_:

1. Migrate an application that uses _Mbed TLS_ cryptography functions through
the _PSA Certified Crypto API_ from the _Mbed TLS_ crypto implementation to
_Oberon PSA Crypto_.
2. Migrating an application that uses _Mbed TLS_ as a TLS stack, so that it
continues using the protocol implementation of _Mbed TLS_, but without the crypto
implementation that comes with _Mbed TLS_, using _Oberon PSA Crypto_ instead.

## Migrate an Application to _Oberon PSA Crypto_

If an application that uses the crypto part of the _Mbed TLS_ software stack via
the _PSA Certified Crypto API_, but does not use its TLS protocol part, should be
migrated to _Oberon PSA Crypto_:

1. Make sure that your application _only_ uses the _PSA Certified Crypto API_ for
all crypto calls.

2. Make sure that your application only uses the modern crypto algorithms that
_Oberon PSA Crypto_ supports, e.g., _not_ MD5. See
[Appendix A: Supported Crypto Features](Appendix_A_Supported_Crypto_Features.md)
for more information.

3. Copy your existing `mbedtls/mbedtls_config.h` configuration file to the
corresponding location in _Oberon PSA Crypto_. _Oberon PSA Crypto_ provides the
_Mbed TLS_ implementations for `MBEDTLS_PSA_CRYPTO_STORAGE_C` and
`MBEDTLS_PSA_ITS_FILE_C` by default, but can use other provided implementations
of these _PSA Storage APIs_.

4. Copy your existing `psa/crypto_config.h` file to `include/psa/crypto_config.h`
in _Oberon PSA Crypto_.

5. Make sure that the `include/psa/crypto_config.h` file defines the "wanted"
crypto features as described above.

6. In the `include/psa/crypto_config.h` file, define the "used" _hardware
drivers_ as described above.

## Use the Mbed TLS Protocol Stack Without its Crypto Implementation

If the TLS protocol part of the _Mbed TLS_ software stack is used with _Oberon
PSA Crypto_, there are settings in `include/mbedtls/mbedtls_config.h` that may
have to be configured as well.
See [README-SSL](../../programs/README-SSL.md)
for more information.
