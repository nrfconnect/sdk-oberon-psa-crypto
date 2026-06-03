# Appendix D: Mbed TLS

Below, two scenarios are discussed relating to _Mbed TLS_:

1. Migrate an application that uses _Mbed TLS_ cryptography functions through
the _PSA Certified Crypto API_ from the _TF-PSA-Crypto_ implementation
(successor project that split off the crypto implementation from _Mbed TLS_)
to _Oberon PSA Crypto_.

2. Migrating an application that uses _Mbed TLS_ as a TLS stack, so that it
continues using the protocol implementation of _Mbed TLS_, but without the
default crypto implementation _TF-PSA-Crypto_, using _Oberon PSA Crypto_
instead.

## Migrate an Application to _Oberon PSA Crypto_

To migrate an application that

a) uses the crypto part of the _Mbed TLS_ 3.x software stack via the
_PSA Certified Crypto API_, but does not use its TLS protocol part, or
b) uses _TF-PSA-Crypto_:

1. Make sure that your application _only_ uses the _PSA Certified Crypto API_
for all crypto calls.

2. Make sure that your application only uses the modern crypto algorithms that
_Oberon PSA Crypto_ supports, e.g., _not_ MD5 etc. See
[Appendix A: Supported Crypto Features](Appendix_A_Supported_Crypto_Features.md)
for more information.

3. Select a target configuration example from the `targets/acme` folder, e.g.,
`demo`.

4. Create an `include/psa/crypto_config.h` file based on the `crypto_config.h`
example in the target configuration's `dispatch/psa` folder, adapt it based on
your existing `crypto_config.h` and if you are migrating from _Mbed TLS 3.x_,
also on your `mbedtls_config.h`. 
In _TF-PSA-Crypto_ and _Oberon PSA Crypto_ since 2.0, configuration aspects
from both files are combined into `crypto_config.h`. 

5. Make sure that your new `crypto_config.h` file defines the "wanted"
crypto features as described above and add the use directives for a DRGB
driver and provide an entropy driver. _Oberon PSA Crypto_ provides the DRBG 
directives `PSA_USE_CTR_DRBG_DRIVER` and `PSA_USE_HMAC_DRBG_DRIVER` for 
production, and the entropy driver directive `PSA_USE_DEMO_ENTROPY_DRIVER` for
testing.

5. Make sure to remove the demo hardware, the demo opaque, and the demo entropy
drivers for production use. 

6. Copy the driver configuration files, i.e.,
`psa/crypto_driver_contexts_composites.h`,
`psa/crypto_driver_contexts_key_derivation.h`,
`psa/crypto_driver_contexts_primitives.h`,
`psa/crypto_driver_config.h`
from  the target configuration's `dispatch` folder to your `include` folder of
_Oberon PSA Crypto_ or make sure they can be found in the include path of your
build.

7. Copy the `psa_crypto_driver_wrappers.c` from  the target configuration's
`dispatch` folder to your `dispatch` folder and add the code file to your 
build.

8. Optionally, add your own hardware drivers and adapt the driver 
configuration files and the dispatch logic implementation accordingly.

9. _Oberon PSA Crypto_ provides the _TF-PSA-Crypto_ mock implementations for
`MBEDTLS_PSA_CRYPTO_STORAGE_C` and `MBEDTLS_PSA_ITS_FILE_C` by default. They
are handy for testing, and should be replaced by hardened implementations of
the _PSA Storage APIs_ for production use.

## Use the Mbed TLS Protocol Stack Without its Crypto Implementation

If the TLS protocol part of the _Mbed TLS_ software stack is used with _Oberon
PSA Crypto_, there are settings in `include/mbedtls/mbedtls_config.h` of the
[MbedTLS project](https://github.com/Mbed-TLS/mbedtls) that may have to be 
configured as well. See [README-SSL](../../programs/README-SSL.md) for more 
information.

## Relevant Defines

The configuration in `psa/crypto_config.h` contains genuine PSA Crypto
configuration options with a `PSA_` prefix and inherited options from former
_MBed TLS_ with an `MBEDTLS_` prefix, that can be configured.

Relevant for _Oberon PSA Crypto_:

- `MBEDTLS_THREADING_C`
- `MBEDTLS_PSA_CRYPTO_C`
- `MBEDTLS_PSA_CRYPTO_CLIENT`
- `MBEDTLS_PSA_CRYPTO_STORAGE_C`
- `MBEDTLS_PSA_CRYPTO_KEY_ID_ENCODES_OWNER`
- `MBEDTLS_PSA_CRYPTO_BUILTIN_KEYS`
- `MBEDTLS_PSA_ITS_FILE_C`
- `MBEDTLS_PSA_KEY_STORE_DYNAMIC`
- `MBEDTLS_PSA_KEY_SLOT_COUNT`
- `MBEDTLS_PSA_STATIC_KEY_SLOTS`
- `MBEDTLS_PSA_STATIC_KEY_SLOT_BUFFER_SIZE`

Should always be defined:

- `MBEDTLS_USE_PSA_CRYPTO`
- `MBEDTLS_PSA_CRYPTO_CONFIG`

Should never be defined:

- `MBEDTLS_PSA_ASSUME_EXCLUSIVE_BUFFERS`
- `MBEDTLS_PSA_CRYPTO_SPM`

This file by _Oberon microsystems_ is licensed under the
[Creative Commons Attribution-ShareAlike 4.0 License](https://creativecommons.org/licenses/by-sa/4.0/).
