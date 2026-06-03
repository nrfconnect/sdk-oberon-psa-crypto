# Architecture

_Oberon PSA Crypto_ implements a refinement of the _PSA Crypto_ architecture,
which Arm has created initially and which has become a de-facto industry standard
managed by the _PSA Certified_ organization. This document first introduces the
generic architecture of _PSA Crypto_, followed by a description of the variant
of this architecture as implemented by _Oberon PSA Crypto_.

## PSA Crypto Architecture

To advance the state of security for embedded systems, Arm has created a
comprehensive _Platform Security Architecture_ (_PSA_). _PSA Crypto_ is the part
of _PSA_ that covers the cryptographic needs of embedded software. _Figure 1_
gives an overview of _PSA Crypto_:

![Figure 1 - Architecture of PSA Crypto](images/figure_1.png "Figure 1 - Architecture of PSA Crypto")
_Figure 1 - Architecture of PSA Crypto_

An application calls a _PSA Crypto_ implementation through the
_PSA Certified Crypto API_. Thanks to the standardization of this API, an
application can easily switch between different _PSA Crypto_ implementations that
have different quality attributes, or are optimized for different hardware
platforms. This makes it easier to reuse application code for new versions of a
product, or across different products in a product line.

For information on how to write application code that calls the _PSA Certified
Crypto API_, please consult the documentation of the _PSA Certified_
organization or take a look at the test code provided by _Oberon PSA Crypto_.

*Note: A protocol stack that uses cryptographic functions is considered part of
the application and is not discussed separately. _Mbed TLS_ is an example of a
(TLS) protocol stack that uses the _PSA Certified Crypto API_.*

A _PSA Crypto_ implementation may also support the _PSA Crypto Driver Interface_.
Through this interface, a _PSA Crypto_ implementation can delegate actual
cryptographic processing to suitable _crypto drivers_. Such a driver can take
advantage of a chip's hardware crypto accelerator where available.

For building an application and enabling dead code elimination (no unnecessary
drivers and no unnecessary code within the _PSA Crypto_ implementation), a
_crypto configuration_ must be provided for every application. On the one hand,
it defines the set of crypto algorithms called by the application. On the other
hand, it defines the set of _crypto drivers_ to be used for the given _target
platform_.

A storage module needs to be provided by a _target platform's_ _platform
integrator_. It should provide protected storage in particular for secret keys.
If the storage module implements the _PSA Secure Storage API_, it can be directly
used with _Oberon PSA Crypto_.

*Note: The _PSA Certified Crypto API_ "at the top" of a _PSA Crypto_
implementation is the relevant API for _application developers_. The _PSA Crypto
Driver Interface_ "at the bottom" is relevant for _crypto driver developers_, and
for _platform integrators_ who adapt _crypto drivers_ to their specific _target
platforms_.*

## Oberon PSA Crypto Architecture

Today, inexpensive microcontrollers usually do not provide comprehensive hardware
crypto accelerators for modern crypto algorithms. Often, they only support AES,
and only a limited number of AES modes. Therefore, no _hardware drivers_ can be
provided, and many applications will need a software fallback for some or all of
the cryptographic operations.

_Oberon PSA Crypto_ provides _Oberon drivers_ as a software fallback that is
footprint- and speed-optimized for inexpensive 32-bit microcontrollers. _Oberon
drivers_ are _crypto drivers_ that provide cryptographic functionality purely in
software, based on _Oberon microsystems'_ lightweight _ocrypto_ library. They are
genuine _crypto drivers_, as they implement the standard
_PSA Crypto Driver Interface_.

_Figure 2_ is an illustration of the _Oberon PSA Crypto_ architecture:

![Figure 2 - Architecture of Oberon PSA Crypto](images/figure_2.png "Figure 2 - Architecture of Oberon PSA Crypto")
_Figure 2 - Architecture of Oberon PSA Crypto_

For the hardware crypto accelerators of their _target platform_,
_platform integrators_ provide the _hardware drivers_. If implemented correctly,
they can be used with any _PSA Crypto_ implementation that conforms to the
_PSA Crypto Driver Interface_, not just with _Oberon PSA Crypto_.

The _Oberon drivers_ fill the gaps in crypto functionality that some
_target platforms_ do not support through _hardware drivers_.

## Taking a Closer Look

Within _Oberon PSA Crypto_, there are two major modules in addition to the
_Oberon drivers_ that have already been discussed above: the _crypto core_ and
the _dispatch logic_.

The _crypto core_ exposes the _PSA Certified Crypto API_ to applications. It
performs parameter validation, handles key management, and forwards calls to the
_dispatch logic_.

The _dispatch logic_ determine what actual _crypto driver_ is called for a given
type of cryptographic operation. For example, for a signature check, a
_hardware driver_ may be selected if available, or an _Oberon driver_ for an
implementation in software.

The _dispatch logic_ provides an internal interface whose client is the
_crypto core_. It depends on _crypto drivers_ that adhere to the upcoming
standard _PSA Crypto Driver Interface_.

_Figure 3_ is a more detailed illustration of the _Oberon PSA Crypto_
architecture:

![Figure 3 - Detailed Architecture of Oberon PSA Crypto](images/figure_3.png "Figure 3 - Detailed Architecture of Oberon PSA Crypto")
_Figure 3 - Detailed Architecture of Oberon PSA Crypto_

In _Figure 3_, the locations of the various APIs are illustrated. The upcalls of
some _Oberon drivers_ into the _dispatch logic_ will be discussed later.

Read more about how to configure _Oberon PSA Crypto_ for an application and
_target platform_, in [Crypto Configuration](Crypto_Configuration.md).

This file by _Oberon microsystems_ is licensed under the
[Creative Commons Attribution-ShareAlike 4.0 License](https://creativecommons.org/licenses/by-sa/4.0/).
