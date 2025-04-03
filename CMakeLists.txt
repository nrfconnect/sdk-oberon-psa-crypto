cmake_minimum_required(VERSION 3.13)
# Note: operator precedence for AND/OR differs in CMake 3.13.4 release, explicit bracketing required

# top level project for the PSA Core object libraries
project(oberon-psa-crypto-core LANGUAGES C)

# Prevent implicit installation to system default directory.
if(CMAKE_INSTALL_PREFIX_INITIALIZED_TO_DEFAULT)
    set_property(CACHE CMAKE_INSTALL_PREFIX PROPERTY VALUE "${CMAKE_SOURCE_DIR}/export")
endif()

set(PLATFORM demo CACHE STRING "Default generic 'demo' platform.")

option(CONFIG_PSA_API_TESTS     "Build PSA Certified APIs Architecture Test Suite"  ON)
option(CONFIG_MBEDTLS_PSA_TESTS "Build Mbed TLS tests"                             OFF)
option(CONFIG_MBEDTLS_THREADING "Build for multi-threading"                         ON)
option(CONFIG_TESTS_FROM_EXPORT "Build PSA API Tests from exported library"        OFF)

if(MSVC)
    set(CONFIG_PSA_API_TESTS OFF)
    add_compile_options(/std:c11)
elseif(CMAKE_C_COMPILER_ID MATCHES Clang)
    add_compile_options(-Wno-logical-op-parentheses)
    add_compile_options(-Wno-bitwise-op-parentheses)
    add_compile_options(-Wno-tautological-constant-out-of-range-compare)
elseif(UNIX)
    add_compile_options(-O2 -Wall -Wextra -Werror)
endif()

# Set build and test options
message(STATUS "PLATFORM: ${PLATFORM}")
message(STATUS "Options:")
if(EXISTS ${CMAKE_SOURCE_DIR}/oberon/platforms/${PLATFORM}/CMakeLists.txt)
    if(CONFIG_TESTS_FROM_EXPORT)
        set(CONFIG_MBEDTLS_PSA_TESTS OFF)
        if(EXISTS ${CMAKE_SOURCE_DIR}/export)
            set(CONFIG_PSA_API_TESTS ON)
            message(STATUS " - CONFIG_TESTS_FROM_EXPORT:     ${CONFIG_TESTS_FROM_EXPORT}")
            message(STATUS "   build PSA-API tests with previously installed library in export folder,")
            message(STATUS "   other test options are ignored")
        else()
            set(CONFIG_TESTS_FROM_EXPORT OFF)
            set(CONFIG_PSA_API_TESTS OFF)
            message(STATUS " - CONFIG_TESTS_FROM_EXPORT:     SKIPPED, build and install library first!")
            message(STATUS " - CONFIG_PSA_API_TESTS:         SKIPPED")
            message(STATUS " - CONFIG_MBEDTLS_PSA_TESTS:     SKIPPED")
            message(STATUS " - CONFIG_MBEDTLS_THREADING:     ${CONFIG_MBEDTLS_THREADING}")
        endif()
    else()
        message(STATUS " - CONFIG_PSA_API_TESTS:         ${CONFIG_PSA_API_TESTS}")
        message(STATUS " - CONFIG_MBEDTLS_PSA_TESTS:     ${CONFIG_MBEDTLS_PSA_TESTS}")
        message(STATUS " - CONFIG_MBEDTLS_THREADING:     ${CONFIG_MBEDTLS_THREADING}")
    endif()
else()
    set(CONFIG_PSA_API_TESTS OFF)
    set(CONFIG_TESTS_FROM_EXPORT OFF)
    message(STATUS " - CONFIG_PSA_API_TESTS:         SKIPPED, not available for ${PLATFORM}")
    set(CONFIG_MBEDTLS_PSA_TESTS OFF)
    message(STATUS " - CONFIG_MBEDTLS_PSA_TESTS:     SKIPPED, not available for ${PLATFORM}")
endif()

# skip library build if CONFIG_TESTS_FROM_EXPORT
if(NOT(CONFIG_TESTS_FROM_EXPORT))

    # Expand the ocrypto root directory, if provided, or set to default
    if(DEFINED OCRYPTO_ROOT)
        get_filename_component(OCRYPTO_ROOT "${OCRYPTO_ROOT}" REALPATH)
    else()
        set(OCRYPTO_ROOT oberon/drivers/ocrypto)
    endif()
    if(NOT EXISTS "${OCRYPTO_ROOT}/include/ocrypto_types_p256.h")
        message(FATAL_ERROR
                "Path ${OCRYPTO_ROOT} does not contain valid ocrypto sources. \
                Please provide -DOCRYPTO_ROOT=path/to/ocrypto/sources or copy \
                ocrypto sources to the following path: \
                ${CMAKE_CURRENT_LIST_DIR}/oberon/ocrypto")
    endif()

    # build ocrypto sources as object library
    add_subdirectory(oberon/drivers/ocrypto)

    # oberon-psa-crypto core library without wrapper
    add_library(${PROJECT_NAME} OBJECT)

    # define sources originating from Mbed TLS, modified and unmodified
    set(MBED_SOURCES
            ${CMAKE_SOURCE_DIR}/library/check_crypto_config.h        # modified
            ${CMAKE_SOURCE_DIR}/library/common.h
            ${CMAKE_SOURCE_DIR}/library/constant_time.c
            ${CMAKE_SOURCE_DIR}/library/platform.c
            ${CMAKE_SOURCE_DIR}/library/platform_util.c              # modified
            ${CMAKE_SOURCE_DIR}/library/psa_crypto.c                 # modified
            ${CMAKE_SOURCE_DIR}/library/psa_crypto_client.c          # modified
            ${CMAKE_SOURCE_DIR}/library/psa_crypto_core.h
            ${CMAKE_SOURCE_DIR}/library/psa_crypto_driver_wrappers.h
    #       ${CMAKE_SOURCE_DIR}/library/psa_crypto_driver_wrappers.c # platform-specific
            ${CMAKE_SOURCE_DIR}/library/psa_crypto_invasive.h
            ${CMAKE_SOURCE_DIR}/library/psa_crypto_its.h
            ${CMAKE_SOURCE_DIR}/library/psa_crypto_random_impl.h     # modified
            ${CMAKE_SOURCE_DIR}/library/psa_crypto_se.h
            ${CMAKE_SOURCE_DIR}/library/psa_crypto_slot_management.h
            ${CMAKE_SOURCE_DIR}/library/psa_crypto_slot_management.c
            ${CMAKE_SOURCE_DIR}/library/psa_crypto_storage.h
            ${CMAKE_SOURCE_DIR}/library/psa_crypto_storage.c
            ${CMAKE_SOURCE_DIR}/library/psa_its_file.c
            ${CMAKE_SOURCE_DIR}/library/threading.c
    )

    # common sources and includes
    target_sources(${PROJECT_NAME} PRIVATE ${MBED_SOURCES})

    # default MBed TLS includes
    target_include_directories(${PROJECT_NAME} PRIVATE include)
    target_include_directories(${PROJECT_NAME} PRIVATE library)

    # add Oberon drivers
    add_subdirectory(oberon/drivers)

    # add demo driver sources and includes
    add_subdirectory(oberon/platforms/demo/drivers)
    target_include_directories(${PROJECT_NAME} PRIVATE ${OCRYPTO_ROOT}/include)
    # target_include_directories(${PROJECT_NAME} PRIVATE oberon/platforms/demo/drivers)

    # Testing resources
    if (CONFIG_MBEDTLS_PSA_TESTS OR CONFIG_PSA_API_TESTS)
        include(CTest)

        # MBed TLS tests for PSA Certified Crypto API
        if (CONFIG_MBEDTLS_PSA_TESTS)

            # test suites relevant for PSA Crypto
            set(MBEDTEST_SUITES
                    test_suite_psa_crypto
                    test_suite_psa_crypto_attributes
                    test_suite_psa_crypto_driver_wrappers
                    # test_suite_psa_crypto_entropy  # n.a. - tests Mbed TLS entropy /* !!OM */
                    test_suite_psa_crypto_generate_key.generated
                    test_suite_psa_crypto_hash
                    # test_suite_psa_crypto_init # n.a. - tests Mbed TLS entropy initialization only /* !!OM */
                    test_suite_psa_crypto_memory
                    test_suite_psa_crypto_metadata
                    test_suite_psa_crypto_not_supported.generated
                    test_suite_psa_crypto_not_supported.misc
                    # test_suite_psa_crypto_op_fail.generated # n.a. - does not work with drivers /* !!OM */
                    test_suite_psa_crypto_op_fail.misc
                    test_suite_psa_crypto_pake
                    test_suite_psa_crypto_pbkdf2
                    test_suite_psa_crypto_persistent_key
                    # test_suite_psa_crypto_se_driver_hal       # n.a. - SE drivers are not supported /* !!OM */
                    # test_suite_psa_crypto_se_driver_hal_mocks # n.a.
                    test_suite_psa_crypto_slot_management
                    test_suite_psa_crypto_storage_format.current
                    test_suite_psa_crypto_storage_format.misc
                    test_suite_psa_crypto_storage_format.v0
                    # test_suite_psa_crypto_util                # n.a. - tests Mbed TLS specific funtions
                    test_suite_psa_its
            )

            # test suites added by Oberon
            set(OBERON_TEST_SUITES
                    pake_test
                    kdf_test
                    key_wrap_test
                    lms_test
            )

            # define Mbed TLS helper sources originating from Mbed TLS test, modified and unmodified
            set(MBEDTEST_SOURCES
                    ${CMAKE_SOURCE_DIR}/tests/src/asn1_helpers.c
                    ${CMAKE_SOURCE_DIR}/tests/src/asn1parse_min.c       # forked from asn1parse.c
                    ${CMAKE_SOURCE_DIR}/tests/src/asn1write_min.c       # forked from asn1write.c
                    ${CMAKE_SOURCE_DIR}/tests/src/psa_crypto_helpers.c
                    ${CMAKE_SOURCE_DIR}/tests/src/psa_exercise_key.c
                    ${CMAKE_SOURCE_DIR}/tests/src/helpers.c
            )
        endif()

        # add tests for selected platform
        add_subdirectory(oberon/platforms/${PLATFORM})

    endif()

    # demo library with config and other headers from default locations
    project(oberon-psa-crypto-demo LANGUAGES C)

    # create demo library for host platform
    add_library(${PROJECT_NAME} STATIC $<TARGET_OBJECTS:ocrypto> $<TARGET_OBJECTS:oberon-psa-crypto-core>)

    # includes psa/crypto_config.h with demo entropy driver and opaque drivers
    target_include_directories(${PROJECT_NAME} PUBLIC
            $<BUILD_INTERFACE:${CMAKE_CURRENT_LIST_DIR}/include>
            $<INSTALL_INTERFACE:include>)

    target_include_directories(${PROJECT_NAME} PRIVATE oberon/drivers)
    target_include_directories(${PROJECT_NAME} PRIVATE oberon/platforms/demo/drivers)
    target_include_directories(${PROJECT_NAME} PRIVATE ${OCRYPTO_ROOT}/include)

    # default driver wrapper supporting Oberon and demo drivers
    target_sources(${PROJECT_NAME} PRIVATE library/psa_crypto_driver_wrappers.c)

    # add threading
    if(CONFIG_MBEDTLS_THREADING)
        target_compile_definitions(${PROJECT_NAME} PRIVATE MBEDTLS_THREADING_C)
        target_compile_definitions(${PROJECT_NAME} PRIVATE MBEDTLS_THREADING_PTHREAD)
        target_sources(${PROJECT_NAME} PRIVATE "${CMAKE_SOURCE_DIR}/library/threading.c")
    endif()

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

    install(FILES
        "oberon/drivers/oberon_config.h"
        "oberon/drivers/oberon_check_unsupported.h"
        "oberon/drivers/oberon_hash.h"
        "oberon/drivers/oberon_cipher.h"
        "oberon/drivers/oberon_aead.h"
        "oberon/drivers/oberon_lms.h"
        "oberon/drivers/oberon_mac.h"
        "oberon/drivers/oberon_key_derivation.h"
        "oberon/drivers/oberon_key_wrap.h"
        "oberon/drivers/oberon_pake.h"
        "oberon/drivers/oberon_jpake.h"
        "oberon/drivers/oberon_spake2p.h"
        "oberon/drivers/oberon_srp.h"
        "oberon/drivers/oberon_ctr_drbg.h"
        "oberon/drivers/oberon_hmac_drbg.h"
        "oberon/drivers/oberon_helpers.h"
        "oberon/drivers/oberon_wpa3_sae.h"
        "oberon/drivers/oberon_xmss.h"
        DESTINATION "include/oberon"
    )
    install(FILES
        "oberon/platforms/demo/drivers/demo_driver_config.h"
        "oberon/platforms/demo/drivers/demo_opaque.h"
        DESTINATION "include/oberon"
    )

endif()

# PSA Certified APIs Architecture Test Suite; uses demo drivers for entropy and opaque
if (CONFIG_PSA_API_TESTS AND ("${PLATFORM}" STREQUAL "demo"))
    include(CTest)

    message(STATUS "CONFIG_PSA_API_TESTS:     ${CONFIG_PSA_API_TESTS}")
    message(STATUS "CONFIG_PSA_API_TESTS:     Building for ${PLATFORM}")

    # choose between library from current build or from installation in export
    if(CONFIG_TESTS_FROM_EXPORT) 
        set(PSA_INCLUDE_PATHS_RELATIVE
            export/include/oberon/ # dependencies to context types and configuration of Oberon drivers
            export/include # use default crypto_config that uses Oberon software drivers only
        )
        set(OBERON_PSA_CRYPTO_LIB "${CMAKE_SOURCE_DIR}/export/lib/liboberon-psa-crypto-demo.a")
    else()
        set(PSA_INCLUDE_PATHS_RELATIVE
            include # use default crypto_config that uses Oberon software drivers only
            oberon/drivers
            oberon/platforms/demo/drivers # required for entropy and opaque drivers
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
    add_subdirectory(api-tests)
    add_executable(${PROJECT_NAME} api-tests/platform/targets/${PROJECT_NAME}/nspe/main.c)

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
