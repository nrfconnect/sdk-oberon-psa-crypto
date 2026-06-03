cmake_minimum_required(VERSION 3.13)
# Note: operator precedence for AND/OR differs in CMake 3.13.4 release, explicit bracketing required

# top level project for the PSA Core object libraries
project(oberon-psa-crypto-core LANGUAGES C)

# Prevent implicit installation to system default directory.
if(CMAKE_INSTALL_PREFIX_INITIALIZED_TO_DEFAULT)
    set_property(CACHE CMAKE_INSTALL_PREFIX PROPERTY VALUE "${CMAKE_SOURCE_DIR}/export")
endif()

set(PLATFORM demo CACHE STRING "Default generic 'demo' platform.")

option(CONFIG_PSA_API_TESTS          "Build PSA API Test Suite"                          ON)
option(CONFIG_MBEDTLS_PSA_TESTS      "Build Mbed TLS tests"                             OFF)
option(CONFIG_MBEDTLS_PSA_TESTS_LONG "Build Mbed TLS long running tests"                OFF)
option(CONFIG_MBEDTLS_THREADING      "Build for multi-threading"                         ON)
option(CONFIG_TESTS_FROM_EXPORT      "Build PSA API Tests from exported library"        OFF)
option(CONFIG_TEST_EXAMPLE_CONFIGS   "Test set of example configurations in platforms"  OFF)
option(CONFIG_OBERON_ML_DSA_FAST     "Optimize ML-DSA for maximum speed"                OFF)
option(CONFIG_OBERON_ML_DSA_SMALL    "Optimize ML-DSA for minimum RAM usage"            OFF)
if(CONFIG_OBERON_ML_DSA_FAST AND CONFIG_OBERON_ML_DSA_SMALL)
    message(FATAL_ERROR "CONFIG_OBERON_ML_DSA_FAST and CONFIG_OBERON_ML_DSA_SMALL are mutually exclusive")
endif()

if(MSVC)
    set(CONFIG_PSA_API_TESTS OFF)
    add_compile_options(/std:c11)
elseif(CMAKE_C_COMPILER_ID MATCHES Clang)
    add_compile_options(-Wno-logical-op-parentheses)
    add_compile_options(-Wno-bitwise-op-parentheses)
    add_compile_options(-Wno-tautological-constant-out-of-range-compare)
    add_compile_options(-Wno-gnu-folding-constant)
elseif(UNIX)
    add_compile_options(-O2 -Wall -Wextra -Werror)
endif()

# Set build and test options
message(STATUS "PLATFORM: ${PLATFORM}")
message(STATUS "Options:")
if(EXISTS ${CMAKE_SOURCE_DIR}/targets/acme/${PLATFORM}/CMakeLists.txt)
    if(CONFIG_TESTS_FROM_EXPORT)
        set(CONFIG_MBEDTLS_PSA_TESTS OFF)
        if(EXISTS ${CMAKE_SOURCE_DIR}/export)
            set(CONFIG_PSA_API_TESTS ON)
            message(STATUS " - CONFIG_TESTS_FROM_EXPORT:      ${CONFIG_TESTS_FROM_EXPORT}")
            message(STATUS "   build PSA-API tests with previously installed library in export folder,")
            message(STATUS "   other test options are ignored")
        else()
            set(CONFIG_TESTS_FROM_EXPORT OFF)
            set(CONFIG_PSA_API_TESTS OFF)
            message(STATUS " - CONFIG_TESTS_FROM_EXPORT:      SKIPPED, build and install library first!")
            message(STATUS " - CONFIG_PSA_API_TESTS:          SKIPPED")
            message(STATUS " - CONFIG_MBEDTLS_PSA_TESTS:      SKIPPED")
            message(STATUS " - CONFIG_MBEDTLS_PSA_TESTS_LONG: SKIPPED")
            message(STATUS " - CONFIG_MBEDTLS_THREADING:      ${CONFIG_MBEDTLS_THREADING}")
            message(STATUS " - CONFIG_OBERON_ML_DSA_FAST:     ${CONFIG_OBERON_ML_DSA_FAST}")
            message(STATUS " - CONFIG_OBERON_ML_DSA_SMALL:    ${CONFIG_OBERON_ML_DSA_SMALL}")
        endif()
    else()
        message(STATUS " - CONFIG_PSA_API_TESTS:          ${CONFIG_PSA_API_TESTS}")
        message(STATUS " - CONFIG_MBEDTLS_PSA_TESTS:      ${CONFIG_MBEDTLS_PSA_TESTS}")
        message(STATUS " - CONFIG_MBEDTLS_PSA_TESTS_LONG: ${CONFIG_MBEDTLS_PSA_TESTS_LONG}")
        message(STATUS " - CONFIG_MBEDTLS_THREADING:      ${CONFIG_MBEDTLS_THREADING}")
    endif()
else()
    set(CONFIG_PSA_API_TESTS OFF)
    set(CONFIG_TESTS_FROM_EXPORT OFF)
    message(STATUS " - CONFIG_PSA_API_TESTS:          SKIPPED, not available for ${PLATFORM}")
    set(CONFIG_MBEDTLS_PSA_TESTS OFF)
    message(STATUS " - CONFIG_MBEDTLS_PSA_TESTS:      SKIPPED, not available for ${PLATFORM}")
    set(CONFIG_MBEDTLS_PSA_TESTS_LONG OFF)
    message(STATUS " - CONFIG_MBEDTLS_PSA_TESTS_LONG: SKIPPED, not available for ${PLATFORM}")
endif()

if(DEFINED PSA_ARCH_TESTS)
    get_filename_component(PSA_ARCH_TESTS "${PSA_ARCH_TESTS}" REALPATH)
else()
    set(PSA_ARCH_TESTS ${CMAKE_SOURCE_DIR}/psa-arch-tests)
endif()

# skip library build if CONFIG_TESTS_FROM_EXPORT
if(NOT(CONFIG_TESTS_FROM_EXPORT))

    # Expand the ocrypto root directory, if provided, or set to default
    if(DEFINED OCRYPTO_ROOT)
        get_filename_component(OCRYPTO_ROOT "${OCRYPTO_ROOT}" REALPATH)
    else()
        set(OCRYPTO_ROOT drivers/oberon/ocrypto)
    endif()
    if(NOT EXISTS "${OCRYPTO_ROOT}/include/ocrypto_sha256.h")
        message(FATAL_ERROR
                "Path ${OCRYPTO_ROOT} does not contain valid ocrypto sources. \
                Please provide -DOCRYPTO_ROOT=path/to/ocrypto/sources or copy \
                ocrypto sources to the following path: \
                ${CMAKE_CURRENT_LIST_DIR}/oberon/ocrypto")
    endif()

    # oberon-psa-crypto core library with demo wrapper
    add_library(${PROJECT_NAME} OBJECT)

    # define sources originating from Mbed TLS, modified and unmodified
    set(TF_PSA_CRYPTO_SOURCES
            ${CMAKE_SOURCE_DIR}/core/check_crypto_config.h            # modified
            ${CMAKE_SOURCE_DIR}/core/psa_crypto.c                     # modified
            ${CMAKE_SOURCE_DIR}/core/psa_crypto_client.c              # modified
            ${CMAKE_SOURCE_DIR}/core/psa_crypto_core.h
            ${CMAKE_SOURCE_DIR}/core/psa_crypto_invasive.h
            ${CMAKE_SOURCE_DIR}/core/psa_crypto_its.h
            ${CMAKE_SOURCE_DIR}/core/psa_crypto_slot_management.h
            ${CMAKE_SOURCE_DIR}/core/psa_crypto_slot_management.c
            ${CMAKE_SOURCE_DIR}/core/psa_crypto_storage.h
            ${CMAKE_SOURCE_DIR}/core/psa_crypto_storage.c
            ${CMAKE_SOURCE_DIR}/core/psa_its_file.c
            ${CMAKE_SOURCE_DIR}/core/tf_psa_crypto_common.h
            ${CMAKE_SOURCE_DIR}/dispatch/psa_crypto_driver_wrappers.h
            ${CMAKE_SOURCE_DIR}/dispatch/psa_crypto_driver_wrappers_no_static.h
            ${CMAKE_SOURCE_DIR}/platform/platform.c
            ${CMAKE_SOURCE_DIR}/platform/platform_util.c              # modified
            ${CMAKE_SOURCE_DIR}/platform/threading.c
            ${CMAKE_SOURCE_DIR}/utilities/constant_time.c
    )

    # common sources and includes
    target_sources(${PROJECT_NAME} PRIVATE ${TF_PSA_CRYPTO_SOURCES})

    # add threading
    if(CONFIG_MBEDTLS_THREADING)
        target_compile_definitions(${PROJECT_NAME} PRIVATE MBEDTLS_THREADING_C)
        target_compile_definitions(${PROJECT_NAME} PRIVATE MBEDTLS_THREADING_PTHREAD)
        target_sources(${PROJECT_NAME} PRIVATE "${CMAKE_SOURCE_DIR}/platform/threading.c")
    endif()

    # default MBed TLS includes
    target_include_directories(${PROJECT_NAME} PRIVATE include)
    target_include_directories(${PROJECT_NAME} PRIVATE core)
    target_include_directories(${PROJECT_NAME} PRIVATE dispatch)
    target_include_directories(${PROJECT_NAME} PRIVATE platform)

    # add demo driver sources and includes
    target_include_directories(${PROJECT_NAME} PRIVATE dispatch)
    target_include_directories(${PROJECT_NAME} PRIVATE targets/acme/demo/dispatch)
    target_include_directories(${PROJECT_NAME} PRIVATE targets/acme/demo/drivers)
    target_include_directories(${PROJECT_NAME} PRIVATE drivers/oberon)


    # demo library with config and other headers from default locations
    project(oberon-psa-crypto-demo LANGUAGES C)

    # create demo library for host platform
    add_library(${PROJECT_NAME} STATIC $<TARGET_OBJECTS:ocrypto> $<TARGET_OBJECTS:oberon-psa-crypto-core>)

    # build ocrypto sources as object library
    add_subdirectory(drivers/oberon/ocrypto)

    # add Oberon drivers
    add_subdirectory(drivers/oberon)

    # default driver wrapper supporting Oberon and demo drivers
    target_sources(${PROJECT_NAME} PRIVATE ${CMAKE_SOURCE_DIR}/targets/acme/demo/dispatch/psa_crypto_driver_wrappers.c)

    # add demo driver sources and includes
    add_subdirectory(targets/acme/demo/drivers)
    target_include_directories(${PROJECT_NAME} PRIVATE ${OCRYPTO_ROOT}/include)
    target_include_directories(${PROJECT_NAME} PRIVATE drivers/oberon)
    
    # includes psa/crypto_config.h with demo entropy driver and opaque drivers
    target_include_directories(${PROJECT_NAME} PUBLIC
            $<BUILD_INTERFACE:${CMAKE_CURRENT_LIST_DIR}/include>
            $<INSTALL_INTERFACE:include>)
    target_include_directories(${PROJECT_NAME} PUBLIC
            $<BUILD_INTERFACE:${CMAKE_CURRENT_LIST_DIR}/targets/acme/demo/dispatch>
            $<INSTALL_INTERFACE:include>)

    target_include_directories(${PROJECT_NAME} PRIVATE core)
    target_include_directories(${PROJECT_NAME} PRIVATE dispatch)
    target_include_directories(${PROJECT_NAME} PRIVATE platform)
    target_include_directories(${PROJECT_NAME} PRIVATE drivers/oberon)
    target_include_directories(${PROJECT_NAME} PRIVATE targets/acme/demo/drivers)
    target_include_directories(${PROJECT_NAME} PRIVATE ${OCRYPTO_ROOT}/include)

    # export
    install(TARGETS ${PROJECT_NAME} 
            EXPORT ${PROJECT_NAME}-Targets
            DESTINATION lib
    )

    install(
        DIRECTORY "include/"
        DESTINATION "include"
        FILES_MATCHING PATTERN "*.h"
    )

    install(
        DIRECTORY "targets/acme/demo/dispatch/"
        DESTINATION "include"
        FILES_MATCHING PATTERN "*.h"
    )

    install(FILES
        "drivers/oberon/oberon_driver_config.h"
        "drivers/oberon/oberon_check_unsupported.h"
        "drivers/oberon/oberon_hash.h"
        "drivers/oberon/oberon_cipher.h"
        "drivers/oberon/oberon_aead.h"
        "drivers/oberon/oberon_lms.h"
        "drivers/oberon/oberon_mac.h"
        "drivers/oberon/oberon_key_derivation.h"
        "drivers/oberon/oberon_key_wrap.h"
        "drivers/oberon/oberon_pake.h"
        "drivers/oberon/oberon_jpake.h"
        "drivers/oberon/oberon_spake2p.h"
        "drivers/oberon/oberon_srp.h"
        "drivers/oberon/oberon_ctr_drbg.h"
        "drivers/oberon/oberon_hmac_drbg.h"
        "drivers/oberon/oberon_helpers.h"
        "drivers/oberon/oberon_wpa3_sae.h"
        "drivers/oberon/oberon_xmss.h"
        "drivers/oberon/oberon_xof.h"
        DESTINATION "include/oberon"
    )
    install(FILES
        "targets/acme/demo/drivers/demo_driver_config.h"
        "targets/acme/demo/drivers/demo_opaque.h"
        DESTINATION "include/oberon"
    )

endif()

# MBed TLS tests and Oberon tests for PSA Certified Crypto API
if (CONFIG_MBEDTLS_PSA_TESTS OR CONFIG_MBEDTLS_PSA_TESTS_LONG)
    include(CTest)

    # test suites relevant for PSA Crypto
    set(MBEDTEST_SUITES
        test_suite_psa_crypto
        test_suite_psa_crypto_attributes
        test_suite_psa_crypto.concurrent
        test_suite_psa_crypto_driver_wrappers
        # test_suite_psa_crypto_entropy                  # n.a. - tests Mbed TLS entropy /* !!OM */
        test_suite_psa_crypto_generate_key.generated
        test_suite_psa_crypto_hash
        # test_suite_psa_crypto_init # n.a. - tests Mbed TLS entropy initialization only /* !!OM */
        test_suite_psa_crypto_low_hash.generated
        test_suite_psa_crypto_memory
        test_suite_psa_crypto_metadata
        test_suite_psa_crypto_not_supported.generated
        test_suite_psa_crypto_not_supported.misc
        # test_suite_psa_crypto_op_fail.generated    # n.a. - does not work with drivers /* !!OM */
        test_suite_psa_crypto_op_fail.misc
        test_suite_psa_crypto_pake
        test_suite_psa_crypto.persistent
        test_suite_psa_crypto_persistent_key
        test_suite_psa_crypto_slot_management
        # test_suite_psa_crypto_util            # n.a. - tests Mbed TLS specific funtions /* !!OM */
        test_suite_psa_crypto_xof
    )

    # test suites relevant for PSA Crypto that run very long
    set(MBEDTEST_SUITES_LONG
        test_suite_psa_crypto.pbkdf2
        test_suite_psa_crypto_storage_format.current
        test_suite_psa_crypto_storage_format.misc
        test_suite_psa_crypto_storage_format.v0
        test_suite_psa_its
    )

    # test suites added by Oberon
    set(OBERON_TEST_SUITES
        oberon_test_pake
        oberon_test_kdf
        oberon_test_key_wrap
        oberon_test_lms
        oberon_test_ml_kem_dsa
    )

    # define Mbed TLS helper sources originating from Mbed TLS tests, modified and unmodified
    set(MBEDTEST_SOURCES
        ${CMAKE_SOURCE_DIR}/framework/tests/src/asn1_helpers.c
        ${CMAKE_SOURCE_DIR}/framework/tests/src/helpers.c
        ${CMAKE_SOURCE_DIR}/framework/tests/src/psa_crypto_helpers.c
        ${CMAKE_SOURCE_DIR}/framework/tests/src/psa_exercise_key.c
        ${CMAKE_SOURCE_DIR}/utilities/asn1parse_min.c       # forked from asn1parse.c
        ${CMAKE_SOURCE_DIR}/utilities/asn1write_min.c       # forked from asn1write.c
    )

    # add tests for selected platform
    add_subdirectory(targets/acme/${PLATFORM})
endif()

# add tests for examples
if (CONFIG_BUILD_EXAMPLES AND EXISTS examples/CMakeLists.txt AND EXISTS "${OCRYPTO_ROOT}/include/internal")
    include(CTest)
    add_subdirectory(examples)
endif()

# PSA API Test Suite; uses demo drivers for entropy and opaque
if (CONFIG_PSA_API_TESTS AND ("${PLATFORM}" STREQUAL "demo"))
    include(CTest)

    message(STATUS "CONFIG_PSA_API_TESTS:     ${CONFIG_PSA_API_TESTS}")
    message(STATUS "CONFIG_PSA_API_TESTS:     Building for ${PLATFORM}")
    message(STATUS "PSA_ARCH_TESTS-PATH:      ${PSA_ARCH_TESTS}")

    # choose between library from current build or from installation in export
    if(CONFIG_TESTS_FROM_EXPORT) 
        set(PSA_INCLUDE_PATHS_RELATIVE
            export/include/oberon/ # dependencies to context types and configuration of Oberon drivers
            export/include # use default crypto_config that uses Oberon software drivers only
        )
        set(OBERON_PSA_CRYPTO_LIB "${CMAKE_SOURCE_DIR}/export/lib/liboberon-psa-crypto-demo.a")
    else()
        set(PSA_INCLUDE_PATHS_RELATIVE
            include 
            targets/acme/${PLATFORM}/dispatch # use default crypto_config that uses Oberon software drivers only
            drivers/oberon
            targets/acme/${PLATFORM}/drivers # required for entropy and opaque drivers
        )  
        set(OBERON_PSA_CRYPTO_LIB oberon-psa-crypto-demo)
    endif()

    # cmake ../ -G"Unix Makefiles" -DTARGET=tgt_dev_apis_linux \
    #           -DTOOLCHAIN=INHERIT -DSUITE=CRYPTO -DPSA_INCLUDE_PATHS="..."

    set(TARGET tgt_dev_apis_linux)
    set(TOOLCHAIN INHERIT)
    set(SUITE CRYPTO)
    set(PSA_INCLUDE_PATHS "")
    foreach(PSA_INCLUDE_PATH ${PSA_INCLUDE_PATHS_RELATIVE})
        get_filename_component(PSA_INCLUDE_PATH "${PSA_INCLUDE_PATH}" REALPATH)
        list(APPEND PSA_INCLUDE_PATHS ${PSA_INCLUDE_PATH})
    endforeach()
    
    project("${TARGET}" LANGUAGES C ASM)

    add_subdirectory(${PSA_ARCH_TESTS}/api-tests api-tests)
    add_executable(${PROJECT_NAME} ${PSA_ARCH_TESTS}/api-tests/platform/targets/${PROJECT_NAME}/nspe/main.c)

    target_link_libraries(${TARGET} PRIVATE val_nspe)
    target_link_libraries(${TARGET} PRIVATE pal_nspe)
    target_link_libraries(${TARGET} PRIVATE test_combine)

    target_link_libraries(${TARGET} PUBLIC ${OBERON_PSA_CRYPTO_LIB})

    set_target_properties(${PROJECT_NAME} PROPERTIES
            RUNTIME_OUTPUT_DIRECTORY "${CMAKE_CURRENT_BINARY_DIR}/${TARGET}")

    add_test(NAME ${PROJECT_NAME} COMMAND "${CMAKE_CURRENT_BINARY_DIR}/${PROJECT_NAME}/${PROJECT_NAME}")
    set_property(TEST ${PROJECT_NAME} PROPERTY LABELS CONFIG_PSA_API_TESTS)
endif()

if(NOT(CONFIG_TESTS_FROM_EXPORT))

    # Build TLS protocol samples from Mbed TLS if MBEDTLS_ROOT defined
    if(DEFINED MBEDTLS_ROOT)
        include(CTest)
        get_filename_component(MBEDTLS_ROOT "${MBEDTLS_ROOT}" REALPATH)
        message(STATUS "Mbed TLS: ${MBEDTLS_ROOT}")
        if(EXISTS "${MBEDTLS_ROOT}/programs/ssl/ssl_client2.c")
            add_subdirectory(programs/ssl)
        else()
            message(FATAL_ERROR
                    "Path ${MBEDTLS_ROOT} does not contain valid Mbed TLS sources. \
                    Please provide -DMBEDTLS_ROOT=path/to/mbedtls.")
        endif()
    endif()

endif()
