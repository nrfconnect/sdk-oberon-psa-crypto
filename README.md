# README

## Oberon PSA Crypto

_Oberon PSA Crypto_ is a software product developed by _Oberon microsystems_.
It implements the _PSA Certified Crypto API_ specification, which aims at
standardizing a cryptography API for embedded systems. _Oberon PSA Crypto_
is a lightweight implementation of this API and is optimized for
resource-constrained microcontrollers: it is focused in particular on small
memory footprint and high speed - in software, hardware, and in mixed
hardware/software configurations.

The software is compatible with the _PSA Certified Crypto API_ version as
specified in
[PSA Certified Crypto API](https://arm-software.github.io/psa-api/crypto/),
and is aligned with the current version of Arm's _TF-PSA-Crypto_. For the
currently supported API version, see the _Compatibility_ section in the
[CHANGELOG](CHANGELOG.md) document.

The software consists of a portable _PSA_ _Crypto Core_ that exposes the
_PSA Certified Crypto API_. It delegates crypto processing to a number of
software _crypto drivers_ (_Oberon drivers_) that can be mixed and matched with
vendor-specific _hardware drivers_, where available.

The crypto feature set supported by the core and the software drivers is
documented in
[Appendix A: Supported Crypto Features](docs/Appendix_A_Supported_Crypto_Features.md).

The software passes the _PSA API Test Suite_ for cryptographic functions and
thereby demonstrates compliance with the standard. See the official
[PSA Certified Crypto API compliance certificate](https://www.psacertified.org/products/oberon-psa-crypto/).

The _Oberon PSA Crypto_ repo is derived from Arm's _TF-PSA-Crypto_ repo, with
most files that are not needed for _PSA Crypto_ compatibility stripped away.
_TF-PSA-Crypto_ files that have been modified by Oberon contain a _NOTICE_ line.

Some files originating from _TF-PSA-Crypto_ or _Mbed TLS_ are contained in the
following subdirectories.

Main _PSA_ components of the product:

- `include`
- `core`
- `dispatch`
- `drivers`

The following directory contains the source code of the _Oberon drivers_.
Some of them depend on the _ocrypto_ software product (which is not included in
this repo):

- `drivers/oberon`

Extra functionality that is not part of the _PSA_ standard and is provided for
_Mbed TLS_- or _TF-PSA-Crypto_-compatibility:

- `platform`
- `utilities`
- `extras`
- `legacy_sub`

Test code that can also be used as example code showing the API usage:

- `framework`
- `programs`
- `psa-arch-tests`
- `tests`

The following directory contains the documentation of _Oberon PSA Crypto_:

- `docs`

For reading the documentation, it is recommended to start with
[Documentation Overview](docs/Documentation_Overview.md).

The following directory contains sketches of target-specific _system crypto
configurations_ and mock _crypto driver_ implementations. This code is intended
as starting point useful for _system crypto configurators_, _platform
integrators_ and _crypto driver developers_. They are not intended to be used as
production code and no guarantees are given that they can be built and run as is:

- `targets/acme`

The following directory contains a copy of the
[PSA API Test Suite](https://github.com/ARM-software/psa-arch-tests/tree/main):

- `psa-arch-tests`

The following directory contains a `README-SSL` and a CMake file for building the
`ssl_server2` and `ssl_client2` examples and SSL tests from _Mbed TLS_, using
_Oberon PSA Crypto_ instead of _TF-PSA-Crypto_:

- `programs`

The following file contains the change history of _Oberon PSA Crypto_:

- `CHANGELOG.md`

For every release, the changelog gives API compatibility information regarding
the _PSA Certified Crypto API_ version that is supported.

The following file contains licensing information:

- `LICENSING.md`

The following file contains the current software version:

- `VERSION`

## Migrate from Oberon PSA Crypto 1.6.x or earlier

Some directories have moved. If you want to migrate from Oberon PSA Crypto 1.6.x
or earlier to _Oberon PSA Crypto_ 2.1.0 or later, please see
[Appendix D: Mbed TLS](docs/Appendix_D_Mbed_TLS.md).

## Migrate from TF-PSA-Crypto

If you want to migrate from _TF-PSA-Crypto_ to _Oberon PSA Crypto_, please see
[Appendix H: Directory Structure Migration](docs/Appendix_H_Directory_Structure_Migration.md).

## Build with CMake

_Oberon PSA Crypto_ can be built and tested on a host with CMake (_MacOS/clang_
or _Windows/MSVC_). _Mbed TLS_ Tests have been generated from _Mbed TLS_
and copied to `tests/generated`. Some tests contain bug fixes. The
_PSA API Test Suite_ was copied from the main branch of
<https://github.com/ARM-software/psa-arch-tests>.

### Prerequisites

_CMake_ version 3.13 or newer.

Compatible _ocrypto_ release version, see
[CHANGELOG.md](CHANGELOG.md).

*Note: _Oberon PSA Crypto_ uses _ocrypto_ for the implementation of its crypto
primitives. The provided _CMake_ files can be used for a quick test on a host
platform (Linux, Windows) and uses _ocrypto_'s platform-independent
implementation (no assembly language). When _Oberon PSA Crypto_ is used on a
microcontroller, please make sure that you use the platform-optimized code
instead! It is located in _ocrypto_ inside `src/platforms/`, e.g., folder
`src/platforms/M4F` for Cortex-M4F, instead of the default folder `Generic` for
the platform-independent code, which is far less optimized.*

Functional certification tests for the _PSA Certified Crypto API_ require Python3
and have been tested on macOS.

### Build

Provide the path to _ocrypto_ with CMake via `-DOCRYPTO_ROOT=path/to/ocrypto`
or copy _ocrypto_ sources with their `src` and `include` directories to path
`oberon/ocrypto` in the repository.

Build the source in a separate directory `build` from the command line:

    cd /path/to/this/repo
    cmake -B build -DOCRYPTO_ROOT=path/to/ocrypto 
    cmake --build build

Supported platforms with demonstration drivers, configurations, and includes
are located in path `targets/acme` and can be selected for build within CMake
via `-DPLATFORM=folder_name`.

Multi-threading support can be enabled with define `MBEDTLS_THREADING_C` in
`psa/crypto_config.h`.

The ML-DSA implementation provides a good tradeoff between speed and RAM
requirements by default. The `generate key` and `verify` operations are
considerably faster than `sign`. If you need to run a `sign` operation at
maximum speed or reduce RAM usage to a minimum, two mutually exclusive build
options are provided:

- `OBERON_ML_DSA_FAST` for max speed of the `sign` operations
- `OBERON_ML_DSA_SMALL` for min RAM usage

### Build with Tests

By default, _Oberon PSA Crypto_ is built for a set of configurations, with
PSA-related _Mbed TLS_ tests, a _PSA API Test Suite_, and in variants with and
without multi-threading support based on the POSIX mutex reference
implementation.

To select for which tests _Oberon PSA Crypto_ is built, the following CMAKE
options are provided:

- _PSA API Test Suite_:         `-DCONFIG_PSA_API_TESTS=ON/OFF`
- PSA-related _Mbed TLS_ tests: `-DCONFIG_MBEDTLS_PSA_TESTS=ON/OFF`
                                `-DCONFIG_MBEDTLS_PSA_TESTS_LONG=ON/OFF`
- Tests example configurations: `-DCONFIG_TEST_EXAMPLE_CONFIGS=ON/OFF`
- Multi-threading support:      `-DCONFIG_MBEDTLS_THREADING=ON/OFF`

### Run Tests

Run all tests from the same `build` directory:

    cd build
    ctest -C Debug

Run _Mbed TLS_ PSA tests only:

    cd build
    ctest -L CONFIG_MBEDTLS_PSA_TESTS --verbose -C Debug

Run PSA certification tests only:

    cd build
    ctest -L CONFIG_PSA_API_TESTS --verbose -C Debug

### Clean

Delete the `build` directory:

    rm -rf build

## Copyright and Licenses

See
[LICENSING.md](LICENSING.md)
file for copyright and licensing information.

## Documentation

The documentation of _Oberon PSA Crypto_ is organized as a sequence of markdown
pages. It starts with the
[Documentation Overview](docs/Documentation_Overview.md)
and can be read sequentially. A number of appendices give additional information
on special topics.

## Bug Tracking and Security Vulnerabilities

_Oberon PSA Crypto_ bugs and security vulnerabilities are tracked in document
[Bug Tracking](docs/Appendix_E_Bug_Tracking.md).

This file by _Oberon microsystems_ is licensed under the
[Creative Commons Attribution-ShareAlike 4.0 License](https://creativecommons.org/licenses/by-sa/4.0/).
