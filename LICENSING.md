# LICENSING

This document declares what licenses have been used in the construction of
_Oberon PSA Crypto_ (incoming licenses) and what license is provided to you
(outgoing license). For incoming licenses, it is distinguished whether
specifications are licensed (i.e., APIs and their documentation) or actual
software (i.e., API implementations).

Copies of incoming licenses are located in directory `licenses-incoming`.

Dependencies and contributors are also listed in this document.

## Incoming Specification Licenses

_Oberon PSA Crypto_ is based on both the high-level _PSA Certified Crypto API_
and the low-level _PSA Crypto Driver API_ standards.

### PSA Certified Crypto API

_PSA Certified Crypto API_:
<https://github.com/ARM-software/psa-api/blob/crypto-1.1.2/LICENSE.md>

This specification is licensed under _CC SA-BY 4.0_.

### PSA Crypto Driver API

_PSA Crypto Driver API_ (Arm proposal):
<https://github.com/Mbed-TLS/mbedtls/blob/v3.5.1/docs/proposed/psa-driver-interface.md>

This specification has been published as part of _Mbed TLS_ and the same licenses
apply, see below.

_Oberon PSA Crypto_ includes _crypto driver_ implementations that are based on
the _PSA Crypto Driver API_ and copyrighted by Oberon microsystems AG.

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

The _Oberon drivers_ within _Oberon PSA Crypto_ require crypto primitives with
file and function prefix _ocrypto_. They originate from the _ocrypto_ library of
Oberon microsystems AG.
_ocrypto_ is a dependency of _Oberon PSA Crypto_. Its source code is not included
in this repo.

Sources of _ocrypto_ are distributed by Oberon microsystems AG in a separate
repository and require a suitable license.

*Note: You don't need _ocrypto_ if you provide your own drivers (e.g., _hardware
drivers_) that come with their own implementations of crypto primitives.*

## Outgoing Software License

All files that are under the copyright of Oberon microsystems AG and do not
contain an Apache 2.0 header, including the markdown documentation files, may not
be used except in compliance with the license agreement provided in
[LICENSE](LICENSE).

## Contributors

The following organizations have contributed to _Oberon PSA Crypto_ software:

- Oberon microsystems AG (owner of all copyrights for _Oberon PSA Crypto_, except
for the incoming items as stated above)
- Nordic Semiconductor ASA (contributor that kindly assigned its copyright to
Oberon microsystems AG)
