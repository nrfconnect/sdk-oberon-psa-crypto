# LICENSING

This document declares what licenses have been used in the construction of this
software (incoming licenses) and what licenses are provided to you for using it
(outgoing licenses). In addition, dependencies and contributors are listed.

Contributors and dependencies are listed at the end of this document.

## Incoming Licenses

### PSA Specifications

This software is based on the following programming interfaces:

- _PSA Certified Crypto API_ (high-level interface to applications)
- _PSA Certified Crypto Driver Interface_ (low-level interface to drivers)
- _PSA Certified Secure Storage API_ (low-level interface to secure storage)

These programming interfaces are members of the _PSA Certified API_ set of
specifications:
[PSA Certified API Standards](https://arm-software.github.io/psa-api/).

They are licensed under _CC BY-SA 4.0_ (text, illustrations) and _Apache 2.0_
(code examples) licenses:
[PSA Certified Crypto API License](https://arm-software.github.io/psa-api/crypto/1.3/about.html#license).

*Note: The _PSA Certified Crypto Driver Interface_ is currently still in alpha
state.*

### Mbed TLS

The high-level part of this software (i.e., the _crypto core_) is a fork of the
crypto component of Arm's _Mbed TLS_ open source project:
[Mbed TLS](https://github.com/Mbed-TLS/mbedtls).

_Mbed TLS_ is licensed under both an `Apache-2.0` and a `GPL-2.0-or-later`
license:
[Mbed TLS Licenses](https://github.com/Mbed-TLS/mbedtls/blob/development/LICENSE).

Some files that originate from _Mbed TLS_ have been modified by Oberon
microsystems AG. They contain the following notice:

`NOTICE: This file has been modified by Oberon microsystems AG.`

*Note: In October 2025, the crypto component of _Mbed TLS_ has been factored out
into the separate _TF-PSA-Crypto_ repo that provides better _PSA Crypto_
support:*
[TF-PSA-Crypto](https://github.com/Mbed-TLS/TF-PSA-Crypto).

### PSA APIs Test Suite

For certification testing against the _PSA Certified APIs_, the
_PSA APIs Test Suite_ is included:
[PSA APIs Test Suite](https://github.com/ARM-software/psa-arch-tests).

The test suite is licensed under the _Apache 2.0_ license:
[PSA APIs Test Suite License](https://github.com/ARM-software/psa-arch-tests/blob/main/LICENSE.md).

The test suite depends on the _Arm_ test library `val_common`, which is licensed
under a BSD license (SPDX identifier `BSD-3-Clause`).

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
as `Apache-2.0 OR GPL-2.0-or-later` are licensed to you under these two licenses.
This means that you can choose the one that suits you better and ignore the other
one.

All documentation files that contain a footer indicating that the file is
licensed as `Creative Commons Attribution-ShareAlike 4.0 License` are licensed to
you under that license.

All other files are under the copyright of _Oberon microsystems_ and may not be
used except in compliance with a valid license agreement provided or referenced
in [LICENSE](LICENSE).

## Contributors

The following organizations have contributed to this software:

- Oberon microsystems AG
- Nordic Semiconductor ASA (contributor that kindly assigned its copyright to
  _Oberon microsystems_)

## Dependencies

This software has two dependencies:

- _ocrypto_
- The _target platform_'s _clib_ (implicit dependency)
