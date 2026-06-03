# Appendix H: Directory Structure Migration

Since _Oberon PSA Crypto_ 2.0.0, some directories have moved to (1) align with
_TF-PSA-Crypto_ and to (2) generalize the organization of configurations for
different target products.

## The following directory contents have moved from 1.6.0 to 2.0.0

`psa-api` and `val_common` --> `psa-arch-tests`

`library` --> `core`, parts moved to `platform`

`include/psa/build_info.h` --> `include/tf-psa-crypto/`, _Oberon PSA Crypto_
version numbers have moved to a new header file:
`include/oberon-psa-crypto/build_info.h`

## The following directory contents have moved from 2.0.0 to 2.1.0

`oberon/docs` --> `docs`

`oberon/drivers` --> `drivers/oberon`

`oberon/platforms` --> `targets/acme`

Inside `oberon/platforms/<target>` the contents of the following directories
have moved for each `<target>`

`oberon/platforms/<target>/example_config`

--> `targets/acme/<target>/config_examples`

`oberon/platforms/<target>/library`

--> `targets/acme/<target>/dispatch`

`oberon/platforms/<target>/include/psa`

--> `targets/acme/<target>/dispatch/psa`

Please note that the `oberon` directory has been removed.

## Mbed TLS 4.1 and Oberon PSA Crypto 2.1

When using _Mbed TLS_ 4.1, some extra code files are required. In
_TF-PSA-Crypto_ 1.1, these are provided in directories `utilities` and `extras`.
In _Oberon PSA Crypto_ 2.1, copies of these directories are provided.

## TF-PSA-Crypto test suites

_Oberon PSA Crypto_ uses adapted versions of the _TF-PSA-Crypto_ test suite. Some
tests still have direct dependencies on _Mbed TLS_ code that is now part of the
_Mbed TLS_ crypto implementation (directory `drivers/builtin` in
_TF-PSA-Crypto_). These files were moved to `legacy_sub`.
