# README

## Oberon PSA Crypto Repo

_Oberon PSA Crypto_ is a software library developed by _Oberon microsystems_.
It implements the _PSA Certified Crypto API_ specification, which aims at
standardizing a cryptography API for embedded systems. _Oberon PSA Crypto_
is a lightweight implementation of this API optimized for resource-constrained
microcontrollers: it is focused in particular on small memory footprint and
high speed in software for hardware that contains only limited – or no –
hardware crypto accelerators.

The library is compatible with the _PSA Certified Crypto API_ version as
specified in
[PSA Certified Crypto API 1.1.2 and PAKE extension 1.1 Beta 1](https://arm-software.github.io/psa-api/crypto/),
and to Arm's _Mbed TLS_ 3.5.0.

The supported crypto feature set is documented in
[Appendix A: Supported Crypto Features](oberon/docs/Appendix_A_Supported_Crypto_Features.md).

The library passes the _PSA Certified APIs Architecture Test Suite_ for
cryptographic functions and thereby demonstrates compliance with the standard.
See its official
[PSA Certified Crypto API compliance certificate](https://www.psacertified.org/products/oberon-psa-crypto/).

The _Oberon PSA Crypto_ repo is a clone of Arm's _MBed TLS_ repo, with most
files that are not needed for _PSA Crypto_ compatibility stripped away.
_Mbed TLS_ files that have been modified by Oberon contain a _NOTICE_ line.

The files originating from _Mbed TLS_ are contained in the following
subdirectories:

- `include`
- `library`
- `tests`

The following directory contains the source code of the _Oberon drivers_.
They depend on the _ocrypto_ library (which is not included in this repo):

- `oberon/drivers`

The following directory contains the documentation of _Oberon PSA Crypto_:

- `oberon/docs`

For reading the documentation, it is recommended to start with
[Documentation Overview](oberon/docs/Documentation_Overview.md).

The following directory contains sketches of platform-specific _system crypto
configurations_ and mock _crypto driver_ implementations. This code is intended
as starting point useful for _system crypto configurators_, _platform
integrators_ and _crypto driver developers_. They are not intended to be used as
production code and no guarantees are given that they can be built and run as is:

- `oberon/platforms`

The following directory contains a copy of the
[PSA Certified Functional APIs Architecture Test Suite](https://github.com/ARM-software/psa-arch-tests/tree/main/api-tests):

- `api-tests`

The following directory contains incoming licenses of third-party software or
third-party specifications:

- `licenses-incoming`

You can find more information on licensing and copyrights in documents
[LICENSING](LICENSING.md) and [LICENSE](LICENSE).

The following directory contains a `README-SSL` and a CMake file for building the
`ssl_server2` and `ssl_client2` examples and SSL tests from _Mbed TLS_, using
_Oberon PSA Crypto_ instead of the cryptographic functions from _Mbed TLS_:

- `programs`

The following file contains the change history of _Oberon PSA Crypto_:

- `CHANGELOG.md`

The following file contains the current software version:

- `VERSION`

## Migrate from Mbed TLS crypto code

 If you want to migrate from _Mbed TLS_ to _Oberon PSA Crypto_, please
 see
 [Appendix D: Mbed TLS](oberon/docs/Appendix_D_Mbed_TLS.md).

## Build with CMake

_Oberon PSA Crypto_ can be built and tested on a host with CMake (_MacOS/clang_
or _Windows/MSVC_). _Mbed TLS_ Tests have been generated from _Mbed TLS_
and copied to `tests/generated`. Some tests contain bug fixes. The _PSA Certified
APIs Architecture Test Suite_ was copied from the main branch of
<https://github.com/ARM-software/psa-arch-tests>.

### Prerequisites

_CMake_ version 3.13 or newer.

Compatible _ocrypto_ release version, see
[CHANGELOG.md](CHANGELOG.md).

Functional certification tests for the _PSA Certified Crypto API_ require Python3
and have been tested on MacOS.

### Build

Provide the path to _ocrypto_ with CMake via `-DOCRYPTO_ROOT=path/to/ocrypto`
or copy _ocrypto_ sources with their `src` and `include` directories to path
`oberon/ocrypto` in the repository.

Build the source in a separate directory `build` from the command line:

    cd /path/to/this/repo
    cmake -B build -DOCRYPTO_ROOT=path/to/ocrypto 
    cmake --build build

Supported platforms with demonstration drivers, configurations, and includes
are located in path `oberon/platforms` and can be provided to CMake via
`-DPLATFORM=folder_name`.

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
[Documentation Overview](oberon/docs/Documentation_Overview.md)
and can be read sequentially. A number of appendices give additional information
on special topics.

## Bug tracking and security vulnerabilities

_Oberon PSA Crypto_ bugs and security vulnerabilities are tracked in document
[Bug Tracking](oberon/docs/Appendix_E_Bug_Tracking.md).
