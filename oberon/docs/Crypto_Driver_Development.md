# Crypto Driver Development

_Application developers_ normally need not be concerned with _crypto drivers_;
they simply use the high-level _PSA Certified Crypto API_ and have their _system
crypto configurators_ configure the crypto features that they want to use in
their applications. _Platform integrators_ are only concerned with these drivers
insofar as they need to configure – for the particular _target platform_ that
they support – which _hardware driver_ should be used for which crypto feature.

_Driver developers_ create the drivers. Here, mainly _hardware drivers_ are
discussed. _Driver developers_ need to have detailed know-how regarding the
hardware crypto accelerators for which they write _hardware drivers_. Their
drivers have to conform to the _PSA Crypto Driver API_. A driver implementation
consists of a C header file and an implementation file that must adhere to the
naming conventions specified by _PSA Crypto_.

Ideally, a template for how to integrate this driver into the _driver wrappers_
file is provided to _platform integrators_.

How to write actual driver code is beyond the scope of this documentation. Please
see the _PSA Crypto Driver API_ documentation on GitHub.

## Hardware Driver Crypto Configuration

In addition to the driver code, a _crypto driver developer_ should also provide a
_hardware driver crypto configuration_ file `<driver-name>_psa_config.h`. This
file contains C define directives of the form `PSA_NEED_XXX` that combine "want"
and "use" of crypto features in the sense of "if crypto feature XXX is both
wanted by the application and available in a driver for the platform, then this
driver's code and support code in the driver wrappers are needed". In other
words: the "needs" are the intersection of "wants" and "uses" and are necessary
to control dead code elimination during the build process.

The _hardware driver crypto configuration_ must also indicate whether an
algorithm / key type / key size combination is hardware-accelerated or not, by
defining `PSA_ACCEL_XXX` directives accordingly. This information is needed to
prefer _hardware drivers_ for a crypto feature over _Oberon drivers_ for the
same feature.

See the provided mock example in
[oberon/platforms/demo/drivers/demo_driver_config.h](../platforms/demo/drivers/demo_driver_config.h)
for more information.

The `PSA_NEED_XXX` and `PSA_ACCEL_XXX` directives supported by _Oberon PSA Crypto_
are listed in
[Appendix B: Crypto Configuration Directives](Appendix_B_Crypto_Configuration_Directives.md).

*Note: The JSON configuration files as defined in the _PSA Crypto_ specification
are not used by _Oberon PSA Crypto_. If a _hardware driver_ comes without a
_hardware driver crypto configuration_ header file as described above, it must
be provided by the _platform integrator_.*

## Oberon Driver Crypto Configuration

_Oberon drivers_ come preconfigured as part of _Oberon PSA Crypto_. Their
_Oberon driver crypto configuration_ file is located at:

- `oberon/drivers/oberon_config.h`

 It must not be modified.

## Entropy Driver

Most networked embedded applications use cryptographic random numbers in some way
or another. The random number generator in _PSA Crypto_ requires an _entropy
driver_ for its inputs. Please refer to the _PSA Certified Crypto API_
specification. A mock driver is provided in
`oberon/platforms/demo/drivers/demo_entropy.c`. It is not intended for
production purposes.

## Driver Chaining

This section is mainly relevant for _Oberon microsystems_ and its _Oberon
drivers_. _Oberon PSA Crypto_ supports a uniform way for _crypto drivers_ to
delegate functionality to other _crypto drivers_. For example, an HMAC _Oberon
driver_ – which is software-only – may delegate hashing operations to a SHA
_hardware driver_. This process is called _driver chaining_ and requires upcalls
to the otherwise private _driver wrappers_ API.

Some _Oberon drivers_ are simple facades for _ocrypto_ functions, while other
_Oberon drivers_ support _driver chaining_ – wherever this is appropriate. In
particular, the following driver chains are supported in _Oberon PSA Crypto_:

- Signature → Hash
- Deterministic signature → HMAC
- HKDF → HMAC
- HMAC → Hash
- CMAC → AES
- HMAC-DRBG → HMAC
- CTR-DRBG → AES-ECB, AES-CMAC
- DRBG → Entropy
- RSA → SHA

_Driver chaining_ allows to highly optimize the mix of software and hardware
implementations of cryptographic code.

*Note: _Hardware drivers_ do not need to implement _driver chaining_. Hardware
crypto accelerators implement a set of cryptographic operations completely,
i.e., without upcalls into software.*
