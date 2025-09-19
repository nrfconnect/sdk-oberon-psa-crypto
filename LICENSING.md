# LICENSING

This document declares what licenses have been used in the construction of
_Oberon PSA Crypto_ (incoming licenses) and what licenses are provided to you
(outgoing licenses). For incoming licenses, it is distinguished whether
specifications are licensed (i.e., APIs and their documentation) or actual
software (i.e., API implementations).

Copies of incoming licenses are located in directory `licenses-incoming`.

Dependencies and contributors are also listed in this document.

See the `Compatibility` section in `CHANGELOG.md` for additional details.

## Incoming Specification Licenses

_Oberon PSA Crypto_ is based on both the high-level _PSA Certified Crypto API_
standard and the low-level _PSA Crypto Driver API_ standard proposal from
_Mbed TLS_.

### PSA Certified Crypto API

The _PSA Certfied Crypto API_ is one of the _PSA Certified API_ standards:
[PSA Certified API Standards](https://arm-software.github.io/psa-api/).

This specification is licensed under _CC SA-BY 4.0_, see here for more details:
[PSA Crypto API License](https://arm-software.github.io/psa-api/crypto/1.3/about.html#license).

### PSA Crypto Driver API

_PSA Crypto Driver API_ is a proposal by an Arm open source development team:
[Proposed PSA Crypto Driver API](https://github.com/Mbed-TLS/TF-PSA-Crypto/tree/development/docs/proposed).
The license is Apache 2.0 plus GPL-2 or later:
[PSA Crypto Driver API Proposal License](https://github.com/Mbed-TLS/TF-PSA-Crypto/blob/development/LICENSE).

_Oberon PSA Crypto_ includes _crypto driver_ *implementations* that are based on
the _PSA Crypto Driver API_ proposal and copyrighted by _Oberon microsystems_.

*Note: As of this writing, this API is an incomplete specification and not yet
formally part of the `PSA Certified API` suite of standards. A standardization
effort led by Arm and in cooperation with _Oberon microsystems_ is currently in
progress.*

## Incoming Software Licenses

### Mbed TLS

The high-level part of _Oberon PSA Crypto_ (i.e., _crypto core_) is a fork of
Arm's _Mbed TLS_:
<https://github.com/Mbed-TLS/mbedtls>

_Mbed TLS_ has been published under both an Apache and a GPL license since
release 3.5.1:
<https://github.com/Mbed-TLS/mbedtls/blob/development/LICENSE>

Some files that originate from _Mbed TLS_ have been modified by Oberon
microsystems AG. They contain the following notice:

`NOTICE: This file has been modified by Oberon microsystems AG.`

### PSA Certified APIs Architecture Test Suite

For certification testing against the _PSA Certified APIs_, _Oberon PSA Crypto_
includes the _PSA Certified APIs Architecture Test Suite_:
<https://github.com/ARM-software/psa-arch-tests>

The test suite has been published under the Apache License Version 2.0:
<https://github.com/ARM-software/psa-arch-tests/blob/main/LICENSE.md>

## Dependencies

_Oberon PSA Crypto_ has one dependency: _ocrypto_.

### ocrypto

The _Oberon drivers_ within _Oberon PSA Crypto_ use crypto primitives with file
and function prefix _ocrypto_. They originate from the _ocrypto_ library of
_Oberon microsystems_. The _ocrypto_ source code is not included in this repo.

Sources of _ocrypto_ are distributed by _Oberon microsystems_ separately and
require a separate license.

*Note: You don't need _ocrypto_ if you provide your own drivers (e.g., _hardware
drivers_) that come with their own implementations of crypto primitives. You can
still use the Apache 2 / GPL-2 licensed files (i.e., the _crypto core_ and the
_driver wrappers_ in this repo) without requiring any additional license from
_Oberon microsystems_.*

## Outgoing Licenses

All source code files that contain a header indicating that the file is licensed
as `Apache-2.0 OR GPL-2.0-or-later` are licensed to you under these licenses.

All documentation files that contain a footer indicating that the file is
licensed as `Creative Commons Attribution-ShareAlike 4.0 License` are licensed to
you under that license.

All other files are under the copyright of _Oberon microsystems_ and may not be
used except in compliance with a valid license agreement provided or referenced
in [LICENSE](LICENSE).

## Contributors

The following organizations have contributed to _Oberon PSA Crypto_ software:

- Oberon microsystems AG
- Nordic Semiconductor ASA (contributor that kindly assigned its copyright to
_Oberon microsystems_)
