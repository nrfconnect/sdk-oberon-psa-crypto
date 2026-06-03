# Appendix G: Glossary

For a list of the most important external links to third-party documentation and
software, see the _Developer Resources_ section in
[Documentation Overview](Documentation_Overview.md).

_Application developer_: Developer who writes application code that calls the
_PSA Certified Crypto API_.

_Crypto configuration_: Configuration elements that determine what crypto code
ends up in the firmware image of an application. It consists of the _system
crypto configuration_, the _platform crypto configuration_, the _Oberon driver
crypto configuration_, and the _hardware driver crypto configuration_.

_Crypto core_: The component of a _PSA Crypto_ implementation that provides the
_PSA Certified Crypto API_ "at the top" and uses _crypto drivers_ "at the
bottom". It handles key management, enforces key usage policies, and (statically)
dispatches cryptographic operations to the appropriate _crypto driver_ via the
_dispatch logic_.

_Crypto driver_: A software component that implements the _PSA Crypto Driver
API_. It can be either a _hardware driver_ or an _Oberon driver_.

_Crypto driver developer_: A developer who implements a _crypto driver_ and, for
_hardware drivers_, provides a _hardware driver crypto configuration_ file.

_Dispatch logic_: A software component used by the _crypto core_ as an adaptor
to one or more _crypto drivers_. In _Oberon PSA Crypto_, its interface is also an
internal standard API that allows for _Oberon drivers_ to execute upcalls into
the _dispatch logic_, to enable _driver chaining_. The _dispatch logic_
component is implemented in the `dispatch/psa_crypto_driver_wrappers.c` file.

_Driver chaining_: Delegating part of an _Oberon driver's_ processing to another
_crypto driver_.

_Driver wrappers_: Deprecated name, see _dispatch logic_.

_Entropy driver_: A _hardware driver_ that generates entropy that is needed for
random number generation.

_Hardware driver_: A _crypto driver_ that is implemented as a software wrapper
for a hardware crypto accelerator. It must be accompanied with a corresponding
_hardware driver crypto configuration_, and possibly some additional C files
needed for _driver integration_.

_Hardware driver crypto configuration_: Part of the _crypto configuration_ that
indicates which crypto features are hardware-accelerated, and provides C
directives that are needed by _Oberon PSA Crypto_ for dead code elimination in
the _crypto core_ and in the _dispatch logic_. A simple mock example is located
in file `targets/acme/demo/drivers/demo_driver_config.h`.

_Mbed TLS_: Arm's open source implementation of the TLS protocol standard. Before
version 4.0, it contained a cryptographic part that partially supported the
_PSA Certified Crypto API_ in addition to its incompatible legacy API. Since
_Mbed TLS_ 4.0, the crypto part is provided as a separate repository with the
name _TF-PSA-Crypto_.

_Oberon driver_: A software-only _crypto driver_ that is provided as part of
_Oberon PSA Crypto_. It implements the _PSA Crypto Driver Interface_ so that it
can be treated by the _dispatch logic_ in the same way as a _hardware driver_.
It provides a fallback implementation for _target platforms_ that do not support
hardware crypto acceleration for all required algorithms, key types, or key
sizes. It may use _Oberon microsystems'_ _ocrypto_ for the actual cryptographic
functions, may implement some cryptographic functions on its own, and may
delegate part of its processing to other _crypto drivers_ through the API of
the _dispatch logic_ (see _driver chaining_).

_Oberon driver crypto configuration_: Part of the _crypto configuration_ that
configures the _Oberon drivers_. It is located in file
`drivers/oberon/oberon_driver_config.h` and must not be modified.

_Oberon microsystems_: Swiss company that has developed the _ocrypto_ software
library, and based upon _ocrypto_ the _Oberon PSA Crypto_ product.

_Oberon PSA Crypto_: A software library developed by _Oberon microsystems_ as a
derivative of the crypto component within Arm's _Mbed TLS_. It provides _PSA
Certified API Compliance_ for its software-optimized implementation of the _PSA
Certified Crypto API_.

_ocrypto_: A software library developed by _Oberon microsystems_, designed to
provide tiny footprint, high speed and resistance against common side-channel
attacks and is optimized for 32-bit microcontrollers. It is used through
_Oberon drivers_ in _Oberon PSA Crypto_ to provide a small and fast software
implementation for cryptographic functions on hardware platforms where no
complete hardware crypto acceleration is available.

_Platform crypto configuration_: A C file that contains _#include_ statements to
_hardware driver crypto configurations_ for all _hardware drivers_ supported for
the _target platform_. It is located at `include/psa/crypto_driver_config.h`.
The rest of this file must not be modified.

_Platform integration_: Adapting _Oberon PSA Crypto_ to the _target platform_.
The result is typically delivered as a software development kit (SDK) to
_application developers_ and _system crypto configurators_. The following tasks
are involved:

- Provide an implementation of the _PSA Certified Secure Storage API_ for key
storage on the _target platform_.
- Provide an implementation of an entropy driver.
- Provide _hardware drivers_ for the _target platform_, with their _hardware
driver crypto configuration_ header files.
- Adapt the _dispatch logic_ so that it calls the supported _hardware drivers_.
- Modify the _platform crypto configuration_ file to refer to the _hardware
driver crypto configurations_ for the set of supported _hardware drivers_.
- Optionally: provide a template for the "use" part of _system crypto
configuration_, so that the _system crypto configurator_ need not touch that part
of the configuration file but can fully focus on what the application "wants".
- Optionally: provide configuration tools that hide parts of the _crypto
configuration_ mechanism.

_Platform integrator_: Developer who performs _platform integration_.

_PSA_: Short for _Platform Security Architecture_. An initiative and framework
started by Arm to improve the state of security in embedded systems.

_PSA Certified_: A framework, set of industry standards, and a security
certification program that lowers the barrier for better IoT security. It is
owned by the vendor-neutral _GlobalPlatform_ organization.

_PSA Certified APIs_: A set of standardized APIs as part of _PSA_. Certification
tests and services are available for implementations of these APIs. For _Oberon
PSA Crypto_, only the _PSA Certified Crypto API_ and _PSA Certified Secure
Storage API_ are relevant.

_PSA API Test Suite_: Suite of tests for the functionality of an implementation
of _PSA Certified APIs_ against the specification of these APIs. For
_Oberon PSA Crypto_, only the cryptography-related part of the test suite is
relevant.

_PSA Certified Crypto API_: Specification of a crypto API standard that is one of
the _PSA_ APIs. It defines a high-level crypto interface for use by _application
developers_. An implementation of the _PSA Certified Crypto API_ requires a
_crypto core_ plus one or more _crypto drivers_.

_PSA Certified Secure Storage API_: Specification of a storage API standard that
is one of the _PSA_ APIs. It defines key/value storage interfaces for the
protected storage of keys and other confidential material. For a _target
platform_, an implementation of this API must be provided by the _platform
integrator_. How to develop such an implementation is outside of the scope of
_Oberon PSA Crypto_.

_PSA Crypto_: Element of the _PSA_ framework that defines a cryptography
component and API for embedded applications.

-PSA Crypto Dispatch Interface_: programming interface specification that is part
of _PSA Crypto_. It is the portable and vendor-neutral programming interface that
must be implemented by _dispatch logic_ for a given _target platform_ and
_application_. Apart from naming rules it is identical to the
_PSA Crypto Driver Interface_.

_PSA Crypto Driver Interface_: programming interface specification that is part
of _PSA Crypto_. It defines a low-level driver interface that must be implemented
by _crypto drivers_. Implementations may use hardware accelerators or be
software-only; the latter is typically the case for fallback crypto drivers.

_PSA Cryptoprocessor Driver Interface_: Deprecated name, see _PSA Crypto Driver
Interface_.

_PSA Unified Driver Interface_: Deprecated name, see
_PSA Crypto Driver Interface_.

_System crypto configuration_: Part of the _crypto configuration_ that configures
what cryptographic algorithms, key types, and key sizes an application "wants".
Furthermore, it configures what _hardware drivers_ should be used for which
crypto features that an application actually "wants". There are examples of such
configuration files in `targets/acme/demo/config_examples`.
The use of _Oberon drivers_ must not be specified, as they will be included
automatically as fallbacks - as needed if the _hardware drivers_ don't provide
all necessary algorithms, key types or key sizes.

_System crypto configurator_: Developer or systems integrator who sets up the
_system crypto configuration_ for an application. Needs insight into what crypto
features the application "wants" - through the _PSA Certified Crypto API_ - and
what _hardware drivers_ are available for the _target platform_.

_Target platform_: Hardware chip(s) or device(s), with or without a real-time
operating system, on which an application can run using _Oberon PSA Crypto_. The
hardware may or may not have hardware accelerators for cryptographic operations.

_TF-PSA-Crypto_: Formerly the crypto component of _Mbed TLS_ 3.x, now a separate
repository. _Oberon PSA Crypto_ can be used as a direct replacement of
_TF-PSA-Crypto_.

This file by _Oberon microsystems_ is licensed under the
[Creative Commons Attribution-ShareAlike 4.0 License](https://creativecommons.org/licenses/by-sa/4.0/).
