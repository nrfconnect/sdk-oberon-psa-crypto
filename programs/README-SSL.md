# README-SSL

## Mbed TLS Protocol Integration (Proof of Concept)

_Oberon PSA Crypto_ implements the _PSA Certified Crypto API_.
It does not implement a TLS protocol stack.

Any TLS implementation that builds on top of the _PSA Certified Crypto API_ can
be used with _Oberon PSA Crypto_.

As a proof of concept (PoC), the `programs/ssl` directory of _Oberon PSA Crypto_
contains a CMake build file for the _Mbed TLS_ `ssl_server2` and `ssl_client2`
program examples and the SSL test suite from _Mbed TLS_.

Example programs and test suite are compiled for all `mbedtls_config.h`
variants located in `programs/ssl/inlude/mbedtls`.

_Note: The TLS protocol stack, the sample programs, and the SSL test suite are
used as is from the Mbed TLS sources._

### Mbed TLS SSL programs' documentation

The following description of the _Mbed TLS_ SSL example programs was copied from
the _Mbed TLS_ README located in its `programs` directory:

>* [`ssl/ssl_client2.c`](ssl/ssl_client2.c): an HTTPS client that sends a fixed
>  request and displays the response, with options to select TLS protocol
>  features and _Mbed TLS_ library features.
>
>* [`ssl/ssl_server2.c`](ssl/ssl_server2.c): an HTTPS server that sends a fixed
>  response, with options to select TLS protocol features and _Mbed TLS_ library
>  features.
>
> In addition to providing options for testing client-side features, the
>`ssl_client2` program has options that allow you to trigger certain behaviors
> in the server. For example, there are options to select ciphersuites, or to
> force a renegotiation. These options are useful for testing the corresponding
> features in a TLS server. Likewise, `ssl_server2` has options to activate
> certain behaviors that are useful for testing a TLS client.

### Build Prerequisites

_Mbed TLS_ contains the SSL program examples and is required to run these samples
on top of _Oberon PSA Crypto_. Download and unzip _Mbed TLS_ from the archive at
<https://github.com/Mbed-TLS/mbedtls/releases/tag/v3.5.0>
or clone_Mbed TLS_ and
check out version 3.5.0 as follows:

    cd path/to/new/folder
    git clone https://github.com/Mbed-TLS/mbedtls.git
    git checkout v3.5.0

### Build with CMake

Provide the path to _ocrypto 3.5.x_ via _-DOCRYPTO_ROOT=path/to/ocrypto_.

Provide the path to _Mbed TLS_ 3.5.0 via _-DMBEDTLS_ROOT=path/to/mbedtls_.

Build the source in a separate directory `build` from the command line:

    cd /path/to/this/repo
    cmake -B build -DOCRYPTO_ROOT=path/to/ocrypto -DMBEDTLS_ROOT=path/to/mbedtls
    cmake --build build

### Run the SSL example

_Note: In Mbed TLS 3.5.0, `ssl_server2` and `ssl_client2` fail with the default 
settings, hence they do not work in _Oberon PSA Crypto_ either. This will be 
fixed in a future version when the TLS protocol implementation is more stable._

Change the directory to the `programs/ssl` directory in the `build` directory.
Change to one of the `mbedtls_config` directories and execute `ssl_server2`:

    cd build/programs/ssl/mbedtls_config_TLS1_2
    ./ssl_server2

The server should start an initialization sequence and wait for a connection
with the following output line in the terminal:

    Waiting for a remote connection ...

Open a second terminal, change to the same directory and execute the client
`ssl_client2`:

    cd build/programs/ssl/mbedtls_config_TLS1_2
    ./ssl_client2

The client should establish a TLS connection with the server, verify the x509
certificate, issue and print an HTTP-request, and receive and print an HTTP
response.

Note that in configuration directory `mbedtls_config_TLS1_2+3`, `ssl_server2` can
be forced to use the TLS 1.3 protocol:

    cd build/programs/ssl/mbedtls_config_TLS1_2+3
    ./ssl_server2 force_version=tls13

### Run Tests

Run _PSA_ and SSL tests from same `build` directory:

    cd build
    ctest -L CONFIG_MBEDTLS_SSL_TESTS -C Debug

## Steps to replace Mbed TLS Crypto with Oberon PSA Crypto

In existing projects that use the TLS protocol implementation from _Mbed TLS_,
the crypto implementation can be replaced with the one from _Oberon PSA Crypto_.
The migration requires projects building on _Mbed TLS_ 3.5.0.

Configuration options are still limited and there are still build dependencies
to some of the _Mbed TLS_ crypto code files even though the code is not used;
this is expected to improve in future releases of _Mbed TLS_.

To use _Oberon PSA Crypto_ in an existing TLS project, perform the following
steps:

1. Add _Oberon PSA Crypto_ repo to your project in its own directory.
2. In your project build files, replace the following list of code files from
   `mbedtls` with the path to the equivalent files in _Oberon PSA Crypto_:
    * `library/platform_util.c`
    * `library/psa_crypto_client.c`
    * `library/psa_crypto_driver_wrappers.c`
    * `programs/ssl/library/psa_crypto_extra.c`
    * `programs/ssl/library/md.c`
    * `programs/ssl/library/psa_util.c`
    * `xxxxxxxxxxxxx.c`

3. Add the _Oberon PSA Crypto_ include paths in the following order and make 
   sure they are searched before the equivalent include paths in `mbedtls`:
    * `oberon-psa-crypto/programs/ssl/include`
    * `oberon-psa-crypto/include`
    * `oberon-psa-crypto/library`
    * `oberon/drivers`
    * `oberon/platform/demo/include`
    * `oberon/platform/demo/drivers`
4. Add the _ocrypto_ include paths, e.g., for the `Generic` platform:
    * `include`
    * `src`
    * `src/platforms/generic`
5. Add an entropy driver to your build, for testing the demo driver can be used:
    * `oberon/platforms/demo/drivers/demo_entropy.c`
6. Add _Oberon PSA Crypto_ sources to your build:
    * `oberon/drivers/oberon_aead.c`
    * `oberon/drivers/oberon_asymmetric_encrypt.c
    * `oberon/drivers/oberon_asymmetric_signature.c
    * `oberon/drivers/oberon_cipher.c`
    * `oberon/drivers/oberon_ctr_drbg.c`
    * `oberon/drivers/oberon_ec_keys.c`
    * `oberon/drivers/oberon_ecdh.c`
    * `oberon/drivers/oberon_ecdsa.c`
    * `oberon/drivers/oberon_hash.c`
    * `oberon/drivers/oberon_helpers.c`
    * `oberon/drivers/oberon_hmac_drbg.c`
    * `oberon/drivers/oberon_jpake.c`
    * `oberon/drivers/oberon_key_agreement.c`
    * `oberon/drivers/oberon_key_derivation.c`
    * `oberon/drivers/oberon_key_management.c`
    * `oberon/drivers/oberon_mac.c`
    * `oberon/drivers/oberon_pake.c`
    * `oberon/drivers/oberon_rsa.c`
    * `oberon/drivers/oberon_spake2p.c`
    * `oberon/drivers/oberon_srp.c`
7. Add _ocrypto_ sources to your build:
    * `ocrypto/src/ocrypto_*`
8. Add _ocrypto_ platform sources, e.g., for the `Generic` platform:
    * `ocrypto/src/platforms/Generic/ocrypto_*`
9. Adapt _system crypto configuration_ (reuse of _Oberon PSA Crypto_
   configuration recommended; make sure to define `PSA_USE_XXX` directives for
   e.g. DRBG and entropy driver and key size specific `PSA_WANT_XXX` directives
   for required crypto features)
    * `mbedtls/mbedtls_config.h`
    * `psa/crypto_config.h`

Build and you now have a TLS project with _Oberon PSA Crypto_ inside!
