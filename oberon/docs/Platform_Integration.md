# Platform Integration

_Platform integration_ consist of several tasks, which are discussed in this
chapter.

## Provide Template with "USE" directives for System Crypto Configuration

To make the job of a _system crypto configurator_ as easy as possible, a template
file with the appropriate "use" directives should be provided for the _target
platform_. See
[Crypto Configuration](Crypto_Configuration.md)
for more information.

## Provide Key Storage Implementation

An implementation of the _PSA_ key storage mechanism must be provided for the
_target platform_. For this purpose, the following file must be adapted:

- `library/psa_its_file.c`

This is assuming that the file-based implementation of
`library/psa_crypto_storage.c` will be used. If not, the latter needs to be
replaced by some other suitable implementation.

See the specification of the _PSA Secure Storage API_ for more information.

## Provide Mutex Implementation

If an application uses a multithreading runtime, the platform must provide an
adapter to the runtime's version of a mutex. The following items must be
provided, through implementation or forwarding to a compatible implementation:

- `oberon_mutex_type`
- `oberon_mutex_init`
- `oberon_mutex_lock`
- `oberon_mutex_unlock`
- `oberon_mutex_free`

They are located in `oberon/drivers/oberon_helpers.h`.

In order to use the provided mutex implementation, the C directive
`OBERON_USE_MUTEX` must be defined in the above file.

*Note: In the standard version of `oberon_helpers.h`, when using _Mbed TLS_ and
`MBEDTLS_THREADING_C`, forwarding to the corresponding _Mbed TLS_ abstractions
is already provided.*

## Provide Hardware Drivers

If the _target platform_ – or some of its family members if it supports an entire
family of chips – provide hardware crypto acceleration, corresponding _hardware
drivers_ should be provided. See
[Crypto Driver Development](Crypto_Driver_Development.md)
for more information. If a _hardware driver_ does not come with a _hardware
driver crypto configuration_ header file, the _platform integrator_ needs to
create one for it.

## Provide Platform Crypto Configuration

Once the set of available _hardware drivers_ for a _target platform_ is known,
the _platform crypto configuration_ file must be adapted accordingly. It is
located at:

- `include/psa/crypto_driver_config.h`

In this file, there should be one `# include` statement to the _hardware driver
crypto configuration_ file for every _hardware driver_. The rest of the file must
not be modified.

## Adapt the Driver Wrappers

To make the set of available _hardware drivers_ known to _Oberon PSA Crypto_ and
its configuration mechanism, the _driver wrappers_ C file must be adapted
accordingly. It is located in

- `library/psa_crypto_driver_wrappers.c`

See the _PSA_ documentation regarding the naming rules that must be obeyed in
this file.

These header files may need to be extended to include the context data types
(operation types):

- `psa/crypto_driver_contexts_primitives.h`
- `psa/crypto_driver_contexts_composites.h`
- `psa/crypto_driver_contexts_key_derivation.h`

## When Using Other Driver Wrappers

When using another _driver wrappers_ implementation than the one provided with
_Oberon PSA Crypto_, make sure that the situation is correctly handled where
`operation->id` is not recognized in a configuration. In such a situation:

- The `psa_driver_wrapper_*_abort` functions must return `PSA_SUCCESS`.
- All other functions (except `psa_driver_wrapper_*_setup`) must return
`PSA_ERROR_BAD_STATE`.

To learn about _driver development_, continue with chapter
[Crypto Driver Development](Crypto_Driver_Development.md).
