# Appendix C: System Crypto Configuration Examples

Four _system crypto configuration_ examples are given in the following directory:

- `oberon/platforms/demo/example_config/`

These example configurations are also used for certification testing.

1. [crypto_config_oberon.h](../platforms/demo/example_config/crypto_config_oberon.h).
This configuration assumes that the application uses _all_ algorithms and key
sizes that are supported by _Oberon PSA Crypto_ in _software_.
In real applications, only a subset will actually be used. Therefore, the
`PSA_WANT_XXX` directives for unnecessary features should be commented out, to
avoid dead code in the firmware image.

2. [crypto_config_min.h](../platforms/demo/example_config/crypto_config_min.h).
This configuration example assumes that the application uses a small ("minimum")
set of algorithms and key sizes. Essentially, it is the set of algorithms that is
needed for the
[_EEMBC SecureMark-TLS_ benchmark](https://www.eembc.org/securemark).

3. [crypto_config_demo.h](../platforms/demo/example_config/crypto_config_demo.h).
This configuration assumes that the application uses _all_ algorithms and key
sizes that are supported by _Oberon PSA Crypto_ in _software_.
In real applications, only a subset will actually be used. Therefore, the
`PSA_WANT_XXX` directives for unnecessary features should be commented out, to
avoid dead code in the firmware image.
For demonstration purposes, this configuration contains the C define for a mock
"hardware driver" (`PSA_USE_DEMO_HARDWARE_DRIVER`). It also contains a C define
for an opaque driver. In most configurations today, drivers are _transparent_,
meaning that keys can be seen by the application in their raw form. In contrast,
_opaque_ drivers use IDs for keys. The raw keys are hidden within secure elements
that are protected from application code.

4. [crypto_config_demo_min.h](../platforms/demo/example_config/crypto_config_demo_min.h).
This configuration example assumes that the application uses a small ("minimum")
set of algorithms and key sizes. Essentially, it is the set of algorithms that is
needed for the [_EEMBC SecureMark-TLS_ benchmark](https://www.eembc.org/securemark).
For demonstration purposes, this configuration contains the C define for a mock
"hardware driver" (`PSA_USE_DEMO_HARDWARE_DRIVER`).

*Note: All examples need an entropy driver. In real systems, this is always a
hardware-dependent driver. For the above examples, a mock driver is provided and
used through the `PSA_USE_DEMO_ENTROPY_DRIVER` C define.*
