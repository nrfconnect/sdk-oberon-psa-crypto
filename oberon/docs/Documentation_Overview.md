# Documentation Overview

_Oberon PSA Crypto_ is a software library developed by _Oberon microsystems_.
It supports cryptographic APIs that adhere to the _PSA Certified Crypto API_
standard.

There are several developer and system integrator roles when working with _Oberon
PSA Crypto_. The most important are _application developer_, _system crypto
configurator_, _platform integrator_, and _crypto driver developer_:

- An _application developer_ typically works for a device manufacturer and writes
application code that calls cryptographic functions through the API defined by
_PSA Crypto_. For information on this _PSA Certified Crypto API_, the reader is
referred to the _PSA Crypto_ specification on the Internet (see _Developer
resources_ below).

- A _system crypto configurator_ typically also works for a device manufacturer
and determines the crypto features used by an application (algorithms, key types,
key sizes) and sets up the _system crypto configuration_ using an SDK for the
_target platform_. This configuration is necessary for selecting and building the
_crypto driver_ code that needs to be included in the final firmware image. The
_system crypto configuration_ should specify only the actually used crypto
features, to avoid cryptography-related dead code.

- A _platform integrator_ typically works for a chip vendor and creates an SDK
that includes _Oberon PSA Crypto_ together with _hardware drivers_ for
cryptographic operations, random number generation, and secure key storage.

- A _crypto driver developer_ typically works for a vendor of crypto hardware IP
and develops a _hardware driver_ for _PSA Crypto_ and a corresponding _hardware
crypto driver configuration_. For information on the _PSA Crypto Driver API_, the
reader is referred to documentation on the Internet (see _Developer resources_
below).

The documentation in this directory focuses on the _system crypto configurator_
and _platform integrator_ roles. It contains the following documentation
chapters:

- [Architecture](Architecture.md) describes the main elements of _Oberon PSA
Crypto_ and their interactions. It gives an architecture overview and introduces
the most important terms used in the rest of the documentation.

- [Crypto Configuration](Crypto_Configuration.md) introduces the mechanism that
is used for the _system crypto configuration_ and other elements of the overall
_crypto configuration_ of a system.

- [Platform Integration](Platform_Integration.md) summarizes what a _platform
integrator_ needs to do in order to provide _Oberon PSA Crypto_ support for a
_target platform_, i.e., for specific chips and real-time operation system (if
used).

- [Crypto Driver Development](Crypto_Driver_Development.md) provides some information for
_crypto driver developers_, as far as this is relevant specifically for _Oberon
PSA Crypto_.

Special topics are discussed in the following appendices:

- [Appendix A: Supported Crypto Features](Appendix_A_Supported_Crypto_Features.md)
provides a list of crypto features that are supported by _Oberon PSA Crypto_ as
software implementations, and therefore can be used even on _target platforms_
without support for hardware crypto acceleration.

- [Appendix B: Crypto Configuration Directives](Appendix_B_Crypto_Configuration_Directives.md)
provides a list of crypto configuration C directives that are supported by _Oberon PSA Crypto_.

- [Appendix C: System Crypto Configuration Examples](Appendix_C_System_Crypto_Configuration_Examples.md)
gives several examples of _system crypto configurations_.

- [Appendix D: Mbed TLS](Appendix_D_Mbed_TLS.md) gives information on how to use
the TLS stack of _Mbed TLS_, while using _Oberon PSA Crypto_ for its
size-optimized cryptography implementation.

- [Appendix E: Bug Tracking](Appendix_E_Bug_Tracking.md) tracks bugs in _Oberon
PSA Crypto_ releases.

- [Appendix F: Testing](Appendix_F_Testing.md) provides information useful for
testing _Oberon PSA Crypto_.

- [Appendix G: Glossary](Appendix_G_Glossary.md) provides a glossary that briefly
explains the most important terms used in the documentation.

Developer resources:

- _PSA Certified_ organization: <https://www.psacertified.org/what-is-psa-certified/about/>
- _PSA Certified_ APIs: <https://arm-software.github.io/psa-api/>
- _PSA Crypto Driver API_ as proposed: <https://github.com/Mbed-TLS/mbedtls/tree/development/docs/proposed>.
- _PSA Certified APIs Architecture Test Suite_: <https://github.com/ARM-software/psa-arch-tests/tree/main/api-tests/dev_apis>
- _Mbed TLS_ repo: <https://github.com/Mbed-TLS/mbedtls#psa-implementation-in-mbed-tls>
- _Mbed TLS_ test suite: <https://github.com/Mbed-TLS/mbedtls/tree/development/tests/suites>
- Random number generator test suite: <https://nvlpubs.nist.gov/nistpubs/legacy/sp/nistspecialpublication800-22r1a.pdf>

To read the documentation sequentially, continue with the architecture chapter
[Architecture](Architecture.md).
