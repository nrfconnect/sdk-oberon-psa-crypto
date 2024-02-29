# Oberon PSA Crypto - Test Cycles
Test program to calculate the number of processor cycles required to compute 
a selection of common cryptographic functions.

Note: The `cycle_test.c` program depends on a function `cpucycles()` that 
returns the processor cycles executed. This function is declared in 
`test_cycles.h`. Example implementations for Cortex-M0 and Cortex-M4F can be
found in `Retarget.c` located in directories M0 and M4F.

**Warning:** The `retarget.c` implementation used from _CMake_ is only a stub. 
Cycle tests build with the provided `CMakeLists.txt` will run but print out 
Zero (0) cycles for every cryptographic function.

## Adapt the test cycle program to a specific platform

To build cycle tests for a specific platform, please

1. provide an implementation for the function that returns the processor cycles
   executed in `retarget.c`:

```
uint64_t cpucycles(void){ ... }
```

2. change `CMakeLists.txt` to use optimized crypto code of your platform 
   located in the _src/platforms_ directory of _ocrypto_, instead of the generic
   platform code used by default.

## Build with CMake
Cycle tests can be built and tested on a host with CMake (_MacOS/clang_
or _Windows/MSVC_). 

### Prerequisites
_CMake_ version 3.13 or newer.

_ocrypto_ release version, see [CHANGELOG.md](../../CHANGELOG.md).

### Build
Provide the path to _ocrypto_ with cmake via `-DOCRYPTO_ROOT=path/to/ocrypto`
or copy _ocrypto_ sources with their `src` and `include` directories to path
`oberon/ocrypto` in the repository.

Build the source in a separate directory `build` from the command line:

    cd tests/cycles
    cmake -B build -DOCRYPTO_ROOT=path/to/ocrypto 
    cmake --build build

### Run Tests
Run cycle tests from same `build` directory:

    cd build
    ctest -C Debug --verbose

### Clean
Delete the `build` directory:

    rm -rf build
