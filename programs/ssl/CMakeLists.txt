# ssl_client2 and ssl_server2

option(CONFIG_MBEDTLS_SSL_TESTS "Build Mbed TLS TLS tests" ON)

set(src_x509
        ${MBEDTLS_ROOT}/library/x509.c
        ${MBEDTLS_ROOT}/library/x509_create.c
        ${MBEDTLS_ROOT}/library/x509_crl.c
        ${MBEDTLS_ROOT}/library/x509_crt.c
        ${MBEDTLS_ROOT}/library/x509_csr.c
        ${MBEDTLS_ROOT}/library/x509_oid.c
        ${MBEDTLS_ROOT}/library/x509write.c
        ${MBEDTLS_ROOT}/library/x509write_crt.c
        ${MBEDTLS_ROOT}/library/x509write_csr.c
)

set(src_tls
        ${MBEDTLS_ROOT}/library/debug.c
        ${MBEDTLS_ROOT}/library/net_sockets.c
        ${MBEDTLS_ROOT}/library/ssl_cache.c
        ${MBEDTLS_ROOT}/library/ssl_ciphersuites.c
        ${MBEDTLS_ROOT}/library/ssl_client.c
        ${MBEDTLS_ROOT}/library/ssl_cookie.c
        ${MBEDTLS_ROOT}/library/ssl_msg.c
        ${MBEDTLS_ROOT}/library/ssl_ticket.c
        ${MBEDTLS_ROOT}/library/ssl_tls.c
        ${MBEDTLS_ROOT}/library/ssl_tls12_client.c
        ${MBEDTLS_ROOT}/library/ssl_tls12_server.c
        ${MBEDTLS_ROOT}/library/ssl_tls13_keys.c
        ${MBEDTLS_ROOT}/library/ssl_tls13_server.c
        ${MBEDTLS_ROOT}/library/ssl_tls13_client.c
        ${MBEDTLS_ROOT}/library/ssl_tls13_generic.c
        ${MBEDTLS_ROOT}/library/timing.c
        ${CMAKE_SOURCE_DIR}/programs/ssl/generated/error.c # mbedtls generated; copied from mbedtls build directory
        ${CMAKE_SOURCE_DIR}/programs/ssl/generated/ssl_debug_helpers_generated.c # mbedtls generated; copied from mbedtls build directory
        ${CMAKE_SOURCE_DIR}/extras/pk.c
        ${CMAKE_SOURCE_DIR}/extras/pk_ecc.c
        ${CMAKE_SOURCE_DIR}/extras/pk_rsa.c
        ${CMAKE_SOURCE_DIR}/extras/pk_wrap.c
        ${CMAKE_SOURCE_DIR}/extras/pkparse.c
        ${CMAKE_SOURCE_DIR}/extras/pkwrite.c
        ${CMAKE_SOURCE_DIR}/utilities/asn1parse.c
        ${CMAKE_SOURCE_DIR}/utilities/asn1write.c
        ${CMAKE_SOURCE_DIR}/utilities/oid.c
        ${CMAKE_SOURCE_DIR}/utilities/pem.c
)

set(src_test_tls_helpers
        ${MBEDTLS_ROOT}/tests/src/certs.c
        ${MBEDTLS_ROOT}/framework/tests/src/helpers.c
        ${MBEDTLS_ROOT}/framework/tests/programs/query_config.h
        ${MBEDTLS_ROOT}/programs/ssl/ssl_test_lib.c
        ${CMAKE_SOURCE_DIR}/framework/tests/src/psa_crypto_helpers.c
        ${CMAKE_SOURCE_DIR}/programs/ssl/generated/query_config.c # mbedtls generated; copied from mbedtls build directory
)

set(src_mbedtls_legacy
        ${CMAKE_SOURCE_DIR}/legacy_sub/src/aesni.c
        ${CMAKE_SOURCE_DIR}/legacy_sub/src/aes.c
        ${CMAKE_SOURCE_DIR}/legacy_sub/src/aesce.c
        ${CMAKE_SOURCE_DIR}/legacy_sub/src/bignum.c
        ${CMAKE_SOURCE_DIR}/legacy_sub/src/bignum_core.c
        ${CMAKE_SOURCE_DIR}/legacy_sub/src/ccm.c
        ${CMAKE_SOURCE_DIR}/legacy_sub/src/chacha20.c
        ${CMAKE_SOURCE_DIR}/legacy_sub/src/chacha20_neon.c
        ${CMAKE_SOURCE_DIR}/legacy_sub/src/chachapoly.c
        ${CMAKE_SOURCE_DIR}/legacy_sub/src/cipher.c
        ${CMAKE_SOURCE_DIR}/legacy_sub/src/cipher_wrap.c
        ${CMAKE_SOURCE_DIR}/legacy_sub/src/ecdsa.c
        ${CMAKE_SOURCE_DIR}/legacy_sub/src/ecjpake.c
        ${CMAKE_SOURCE_DIR}/legacy_sub/src/ecp.c
        ${CMAKE_SOURCE_DIR}/legacy_sub/src/ecp_curves.c
        ${CMAKE_SOURCE_DIR}/legacy_sub/src/gcm.c
        ${CMAKE_SOURCE_DIR}/legacy_sub/src/hmac_drbg.c
        ${CMAKE_SOURCE_DIR}/legacy_sub/src/poly1305.c
        ${CMAKE_SOURCE_DIR}/legacy_sub/src/rsa.c
        ${CMAKE_SOURCE_DIR}/legacy_sub/src/rsa_alt_helpers.c
        ${CMAKE_SOURCE_DIR}/legacy_sub/src/sha1.c
        ${CMAKE_SOURCE_DIR}/legacy_sub/src/sha3.c
        ${CMAKE_SOURCE_DIR}/legacy_sub/src/sha256.c
        ${CMAKE_SOURCE_DIR}/legacy_sub/src/sha512.c
        ${CMAKE_SOURCE_DIR}/legacy_sub/src/psa_util_internal.c
        ${CMAKE_SOURCE_DIR}/core/psa_util.c
        ${CMAKE_SOURCE_DIR}/extras/md.c
        ${CMAKE_SOURCE_DIR}/extras/nist_kw.c
        ${CMAKE_SOURCE_DIR}/utilities/base64.c
        ${CMAKE_SOURCE_DIR}/utilities/pkcs5.c
)

if (CONFIG_MBEDTLS_SSL_TESTS)

    if(NOT EXISTS "${MBEDTLS_ROOT}/library/mbedtls_common.h")
        message(FATAL_ERROR
                "CONFIG_MBEDTLS_SSL_TESTS require Mbed TLS 4.1.0.")
    endif()

    message(STATUS "CONFIG_MBEDTLS_SSL_TESTS: ${CONFIG_MBEDTLS_SSL_TESTS}")

    set(MBEDTEST_TLS_SUITES
            test_suite_ssl
    )

    # add PSA tests for completeness
    list(APPEND TEST_SUITES ${MBEDTEST_SUITES} )
    # add tests for TLS
    list(APPEND TEST_SUITES ${MBEDTEST_TLS_SUITES} )
endif()

# create Oberon PSA Crypto projects with SSL for each mbedtls_config
file(GLOB config_files LIST_DIRECTORIES false "include/mbedtls/mbedtls_config*.h")
foreach(MBEDTLS_CONFIG_H ${config_files})
    get_filename_component(TEST_CONFIG "${MBEDTLS_CONFIG_H}" NAME_WE)
    message(STATUS "SSL config: ${TEST_CONFIG}")
    project("oberon-psa-crypto-ssl-${TEST_CONFIG}" LANGUAGES C ASM)
    message(STATUS "CMAKE_CURRENT_BINARY_DIR: ${CMAKE_CURRENT_BINARY_DIR}")
    configure_file("${MBEDTLS_CONFIG_H}"
            "${CMAKE_CURRENT_BINARY_DIR}/${TEST_CONFIG}/include/mbedtls/mbedtls_config.h"
            COPYONLY)

    add_library(${PROJECT_NAME} OBJECT)

    # ocrypto
    target_link_libraries(${PROJECT_NAME} PRIVATE ocrypto)

    # ssl sources
    target_sources(${PROJECT_NAME} PRIVATE
        ${src_x509}
        ${src_tls}
        ${src_tls_modified}
        ${src_test_tls_helpers}
        ${src_mbedtls_legacy} # build dependencies only
    )

    # Oberon PSA Crypto demo drivers
    target_sources(${PROJECT_NAME} PRIVATE
        ${CMAKE_SOURCE_DIR}/targets/acme/demo/dispatch/psa_crypto_driver_wrappers.c
        ${CMAKE_SOURCE_DIR}/targets/acme/demo/drivers/demo_entropy.c
        ${CMAKE_SOURCE_DIR}/targets/acme/demo/drivers/demo_hardware.c
        ${CMAKE_SOURCE_DIR}/targets/acme/demo/drivers/demo_opaque.c
    )
    add_subdirectory(${CMAKE_SOURCE_DIR}/drivers/oberon ${TEST_CONFIG}/drivers)
    target_sources(${PROJECT_NAME} PRIVATE ${TF_PSA_CRYPTO_SOURCES})

    # add TLS specific include for generated test/test_certs.h
    target_include_directories(${PROJECT_NAME} PRIVATE ${CMAKE_SOURCE_DIR}/programs/ssl/include)

    # add TLS specific includes to use different configuration
    target_include_directories(${PROJECT_NAME} PRIVATE ${CMAKE_CURRENT_BINARY_DIR}/${TEST_CONFIG}/include)

    # add demo platform includes
    target_include_directories(${PROJECT_NAME} PRIVATE ${CMAKE_SOURCE_DIR}/targets/acme/demo/dispatch)

    # add common includes
    target_include_directories(${PROJECT_NAME} PRIVATE ${CMAKE_SOURCE_DIR}/core)
    target_include_directories(${PROJECT_NAME} PRIVATE ${CMAKE_SOURCE_DIR}/dispatch)
    target_include_directories(${PROJECT_NAME} PRIVATE ${CMAKE_SOURCE_DIR}/platform)
    target_include_directories(${PROJECT_NAME} PRIVATE ${CMAKE_SOURCE_DIR}/utilities)
    target_include_directories(${PROJECT_NAME} PRIVATE ${CMAKE_SOURCE_DIR}/extras)
    target_include_directories(${PROJECT_NAME} PRIVATE ${CMAKE_SOURCE_DIR}/legacy_sub/src)
    target_include_directories(${PROJECT_NAME} PRIVATE ${CMAKE_SOURCE_DIR}/drivers/oberon)

    # add platform specific sources and includes before mbed includes
    target_include_directories(${PROJECT_NAME} PRIVATE ${CMAKE_SOURCE_DIR}/targets/acme/demo/drivers)

    # add mbed includes
    target_include_directories(${PROJECT_NAME} PRIVATE ${CMAKE_SOURCE_DIR}/include)
    target_include_directories(${PROJECT_NAME} PRIVATE ${CMAKE_SOURCE_DIR}/legacy_sub/include)
    target_include_directories(${PROJECT_NAME} PRIVATE ${CMAKE_SOURCE_DIR}/programs/ssl/include)

    # add mbedtls includes
    target_include_directories(${PROJECT_NAME} PRIVATE ${MBEDTLS_ROOT}/framework/tests/programs)
    target_include_directories(${PROJECT_NAME} PRIVATE ${MBEDTLS_ROOT}/include)

    target_include_directories(${PROJECT_NAME} PRIVATE ${MBEDTLS_ROOT}/framework/tests/include)
    target_include_directories(${PROJECT_NAME} PRIVATE ${MBEDTLS_ROOT}/tests/include)
    target_include_directories(${PROJECT_NAME} PRIVATE ${MBEDTLS_ROOT}/library)

    # executables
    set(executables
        ssl_client2
        ssl_server2
    )

    foreach(exe IN LISTS executables)

        project(${exe}_${TEST_CONFIG} LANGUAGES C ASM)
        add_executable(${PROJECT_NAME} ${MBEDTLS_ROOT}/programs/ssl/${exe}.c)
        set_target_properties(${PROJECT_NAME} PROPERTIES
            RUNTIME_OUTPUT_DIRECTORY "${CMAKE_CURRENT_BINARY_DIR}/${TEST_CONFIG}"
            RUNTIME_OUTPUT_NAME "${exe}")

        # add libs
        target_link_libraries(${PROJECT_NAME} PUBLIC oberon-psa-crypto-ssl-${TEST_CONFIG})
        target_link_libraries(${PROJECT_NAME} PRIVATE ocrypto)

        # add TLS specific include for generated test/test_certs.h
        target_include_directories(${PROJECT_NAME} PRIVATE ${CMAKE_SOURCE_DIR}/programs/ssl/include)

        # add TLS specific includes to use different configuration
        target_include_directories(${PROJECT_NAME} PRIVATE ${CMAKE_CURRENT_BINARY_DIR}/${TEST_CONFIG}/include)

        # add demo platform includes
        target_include_directories(${PROJECT_NAME} PRIVATE ${CMAKE_SOURCE_DIR}/targets/acme/demo/dispatch)

        # add common includes
        target_include_directories(${PROJECT_NAME} PRIVATE ${CMAKE_SOURCE_DIR}/core)
        target_include_directories(${PROJECT_NAME} PRIVATE ${CMAKE_SOURCE_DIR}/legacy_sub/src)
        target_include_directories(${PROJECT_NAME} PRIVATE ${CMAKE_SOURCE_DIR}/drivers/oberon)
        # target_include_directories(${PROJECT_NAME} PRIVATE ${CMAKE_SOURCE_DIR}/dispatch)
        # target_include_directories(${PROJECT_NAME} PRIVATE ${CMAKE_SOURCE_DIR}/platform)
        target_include_directories(${PROJECT_NAME} PRIVATE ${CMAKE_SOURCE_DIR}/utilities)
        target_include_directories(${PROJECT_NAME} PRIVATE ${CMAKE_SOURCE_DIR}/extras)

        # add platform specific sources and includes before mbed includes
        target_include_directories(${PROJECT_NAME} PRIVATE ${CMAKE_SOURCE_DIR}/targets/acme/demo/drivers)

        # add mbed includes
        target_include_directories(${PROJECT_NAME} PRIVATE ${CMAKE_SOURCE_DIR}/include)
        target_include_directories(${PROJECT_NAME} PRIVATE ${CMAKE_SOURCE_DIR}/legacy_sub/include)
        target_include_directories(${PROJECT_NAME} PRIVATE ${CMAKE_SOURCE_DIR}/programs/ssl/include)

        # add mbedtls includes
        target_include_directories(${PROJECT_NAME} PRIVATE ${MBEDTLS_ROOT}/framework/tests/programs)
        target_include_directories(${PROJECT_NAME} PRIVATE ${MBEDTLS_ROOT}/include)

        target_include_directories(${PROJECT_NAME} PRIVATE ${MBEDTLS_ROOT}/framework/tests/include)
        target_include_directories(${PROJECT_NAME} PRIVATE ${MBEDTLS_ROOT}/tests/include)
        target_include_directories(${PROJECT_NAME} PRIVATE ${MBEDTLS_ROOT}/library)
        
    endforeach()

    if (CONFIG_MBEDTLS_SSL_TESTS)

        foreach(SUITE ${TEST_SUITES})
            project("${TEST_CONFIG}-mbedtls-${SUITE}")
            message(STATUS "Add test suite ${SUITE} for ${TEST_CONFIG}")
            add_executable(${PROJECT_NAME})
            set_target_properties(${PROJECT_NAME} PROPERTIES
                RUNTIME_OUTPUT_DIRECTORY "${CMAKE_CURRENT_BINARY_DIR}/${TEST_CONFIG}/test-suites")
            target_sources(${PROJECT_NAME} PRIVATE "${CMAKE_SOURCE_DIR}/tests/generated/${SUITE}.c")

            if(UNIX)
                set(DATAX_DIR "${CMAKE_CURRENT_BINARY_DIR}/${TEST_CONFIG}/test-suites")
            else()
                set(DATAX_DIR "${PROJECT_BINARY_DIR}")
            endif()

            add_custom_command(
                TARGET ${PROJECT_NAME} PRE_LINK
                COMMAND ${CMAKE_COMMAND} -E copy
                ${CMAKE_SOURCE_DIR}/tests/generated/${SUITE}.datax
                ${DATAX_DIR}/
                )

            # add libs
            target_link_libraries(${PROJECT_NAME} PRIVATE oberon-psa-crypto-ssl-${TEST_CONFIG})
            target_link_libraries(${PROJECT_NAME} PRIVATE ocrypto)

            # ssl sources
            target_sources(${PROJECT_NAME} PRIVATE
                ${CMAKE_SOURCE_DIR}/legacy_sub/src/ctr_drbg.c
                ${CMAKE_SOURCE_DIR}/legacy_sub/src/entropy.c
                ${CMAKE_SOURCE_DIR}/legacy_sub/src/entropy_poll.c
                ${MBEDTLS_ROOT}/framework/tests/src/random.c
            )

            # test helpers
            target_sources(${PROJECT_NAME} PRIVATE
                ${CMAKE_SOURCE_DIR}/framework/tests/src/asn1_helpers.c
                ${CMAKE_SOURCE_DIR}/framework/tests/src/psa_exercise_key.c
                ${MBEDTLS_ROOT}/tests/src/test_helpers/ssl_helpers.c
            )

            # add TLS specific include for generated test/test_certs.h
            target_include_directories(${PROJECT_NAME} PRIVATE ${CMAKE_SOURCE_DIR}/programs/ssl/include)

            # add TLS specific includes to use different configuration
            target_include_directories(${PROJECT_NAME} PRIVATE ${CMAKE_CURRENT_BINARY_DIR}/${TEST_CONFIG}/include)

            # add demo platform includes
            target_include_directories(${PROJECT_NAME} PRIVATE ${CMAKE_SOURCE_DIR}/targets/acme/demo/dispatch)

            # add common includes
            target_include_directories(${PROJECT_NAME} PRIVATE ${CMAKE_SOURCE_DIR}/core)
            target_include_directories(${PROJECT_NAME} PRIVATE ${CMAKE_SOURCE_DIR}/legacy_sub/src)
            target_include_directories(${PROJECT_NAME} PRIVATE ${CMAKE_SOURCE_DIR}/drivers/oberon)
            # target_include_directories(${PROJECT_NAME} PRIVATE ${CMAKE_SOURCE_DIR}/dispatch)
            # target_include_directories(${PROJECT_NAME} PRIVATE ${CMAKE_SOURCE_DIR}/platform)
            target_include_directories(${PROJECT_NAME} PRIVATE ${CMAKE_SOURCE_DIR}/utilities)
            target_include_directories(${PROJECT_NAME} PRIVATE ${CMAKE_SOURCE_DIR}/extras)

            # add platform specific sources and includes before mbed includes
            target_include_directories(${PROJECT_NAME} PRIVATE ${CMAKE_SOURCE_DIR}/targets/acme/demo/drivers)

            # add mbed includes
            target_include_directories(${PROJECT_NAME} PRIVATE ${CMAKE_SOURCE_DIR}/include)
            target_include_directories(${PROJECT_NAME} PRIVATE ${CMAKE_SOURCE_DIR}/legacy_sub/include)
            target_include_directories(${PROJECT_NAME} PRIVATE ${CMAKE_SOURCE_DIR}/programs/ssl/include)

            # add mbedtls includes
            target_include_directories(${PROJECT_NAME} PRIVATE ${MBEDTLS_ROOT}/framework/tests/programs)
            target_include_directories(${PROJECT_NAME} PRIVATE ${MBEDTLS_ROOT}/include)

            target_include_directories(${PROJECT_NAME} PRIVATE ${MBEDTLS_ROOT}/framework/tests/include)
            target_include_directories(${PROJECT_NAME} PRIVATE ${MBEDTLS_ROOT}/tests/include)
            target_include_directories(${PROJECT_NAME} PRIVATE ${MBEDTLS_ROOT}/library)

            # add test
            add_test(NAME ${PROJECT_NAME} COMMAND ${PROJECT_NAME})
            set_property(TEST ${PROJECT_NAME} PROPERTY LABELS CONFIG_MBEDTLS_SSL_TESTS-${TEST_CONFIG})
        endforeach()
    endif()
endforeach()
