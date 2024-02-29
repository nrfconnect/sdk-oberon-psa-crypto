# ssl_client2 and ssl_server2

option(CONFIG_MBEDTLS_SSL_TESTS "Build Mbed TLS TLS tests" ON)

set(src_x509
        ${MBEDTLS_ROOT}/library/x509.c
        ${MBEDTLS_ROOT}/library/x509_create.c
        ${MBEDTLS_ROOT}/library/x509_crl.c
        ${MBEDTLS_ROOT}/library/x509_crt.c
        ${MBEDTLS_ROOT}/library/x509_csr.c
        ${MBEDTLS_ROOT}/library/x509write.c
        ${MBEDTLS_ROOT}/library/x509write_crt.c
        ${MBEDTLS_ROOT}/library/x509write_csr.c
)

set(src_tls
        ${MBEDTLS_ROOT}/library/asn1parse.c
        ${MBEDTLS_ROOT}/library/asn1write.c
        ${MBEDTLS_ROOT}/library/debug.c
        ${MBEDTLS_ROOT}/library/error.c
        ${MBEDTLS_ROOT}/library/net_sockets.c
        ${MBEDTLS_ROOT}/library/oid.c
        ${MBEDTLS_ROOT}/library/pem.c
        ${MBEDTLS_ROOT}/library/pk.c
        ${MBEDTLS_ROOT}/library/pk_wrap.c
        ${MBEDTLS_ROOT}/library/pkparse.c
        ${MBEDTLS_ROOT}/library/pkwrite.c
        ${MBEDTLS_ROOT}/library/ssl_cache.c
        ${MBEDTLS_ROOT}/library/ssl_ciphersuites.c
        ${MBEDTLS_ROOT}/library/ssl_client.c
        ${MBEDTLS_ROOT}/library/ssl_debug_helpers_generated.c
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
)

set(src_tls_helpers
        ${MBEDTLS_ROOT}/tests/src/certs.c
        ${MBEDTLS_ROOT}/tests/src/helpers.c
        ${MBEDTLS_ROOT}/tests/src/psa_crypto_helpers.c
        ${MBEDTLS_ROOT}/programs/ssl/ssl_test_lib.c
        ${MBEDTLS_ROOT}/programs/test/query_config.h
        ${MBEDTLS_ROOT}/programs/test/query_config.c
        ${CMAKE_SOURCE_DIR}/programs/ssl/library/psa_crypto_extra.c
)

set(src_mbedtls_legacy
        ${MBEDTLS_ROOT}/library/aesni.c
        ${MBEDTLS_ROOT}/library/aes.c
        ${MBEDTLS_ROOT}/library/aesce.c
        ${MBEDTLS_ROOT}/library/base64.c
        ${MBEDTLS_ROOT}/library/bignum.c
        ${MBEDTLS_ROOT}/library/bignum_core.c
        ${MBEDTLS_ROOT}/library/ccm.c
        ${MBEDTLS_ROOT}/library/chacha20.c
        ${MBEDTLS_ROOT}/library/chachapoly.c
        ${MBEDTLS_ROOT}/library/cipher.c
        ${MBEDTLS_ROOT}/library/cipher_wrap.c
        ${MBEDTLS_ROOT}/library/ecdh.c
        ${MBEDTLS_ROOT}/library/ecdsa.c
        ${MBEDTLS_ROOT}/library/ecjpake.c
        ${MBEDTLS_ROOT}/library/ecp.c
        ${MBEDTLS_ROOT}/library/ecp_curves.c
        ${MBEDTLS_ROOT}/library/gcm.c
        ${MBEDTLS_ROOT}/library/hkdf.c
        ${MBEDTLS_ROOT}/library/hmac_drbg.c
        # copied to oberon_psa_crypto to avoid wrong psa_crypto_core.h import
        ${CMAKE_SOURCE_DIR}/programs/ssl/library/md.c
        ${MBEDTLS_ROOT}/library/nist_kw.c
        ${MBEDTLS_ROOT}/library/pkcs12.c
        ${MBEDTLS_ROOT}/library/pkcs5.c
        ${MBEDTLS_ROOT}/library/poly1305.c
        # copied to oberon_psa_crypto to avoid wrong psa_crypto_core.h import
        ${CMAKE_SOURCE_DIR}/programs/ssl/library/psa_util.c
        ${MBEDTLS_ROOT}/library/rsa.c
        ${MBEDTLS_ROOT}/library/rsa_alt_helpers.c
        ${MBEDTLS_ROOT}/library/sha1.c
        ${MBEDTLS_ROOT}/library/sha256.c
        ${MBEDTLS_ROOT}/library/sha512.c
)

if (CONFIG_MBEDTLS_SSL_TESTS)

    if(NOT EXISTS "${MBEDTLS_ROOT}/library/ecp_curves_new.c")
        message(FATAL_ERROR
                "CONFIG_MBEDTLS_SSL_TESTS require Mbed TLS 3.5.0.")
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
        ${src_tls_helpers}
        ${src_mbedtls_legacy} # build dependencies only
    )

    # Oberon PSA Crypto drivers
    target_sources(${PROJECT_NAME} PRIVATE
        ${CMAKE_SOURCE_DIR}/library/psa_crypto_driver_wrappers.c
        ${CMAKE_SOURCE_DIR}/oberon/platforms/demo/drivers/demo_entropy.c
        ${CMAKE_SOURCE_DIR}/oberon/platforms/demo/drivers/demo_hardware.c
        ${CMAKE_SOURCE_DIR}/oberon/platforms/demo/drivers/demo_opaque.c
    )
    add_subdirectory(${CMAKE_SOURCE_DIR}/oberon/drivers ${TEST_CONFIG}/drivers)
    target_sources(${PROJECT_NAME} PRIVATE ${MBED_SOURCES})

    # add TLS specific include for build_info.h
    target_include_directories(${PROJECT_NAME} PRIVATE ${CMAKE_SOURCE_DIR}/programs/ssl/include)

    # add TLS specific includes to use different configuration
    target_include_directories(${PROJECT_NAME} PRIVATE ${CMAKE_CURRENT_BINARY_DIR}/${TEST_CONFIG}/include)

    # add common includes
    target_include_directories(${PROJECT_NAME} PRIVATE ${CMAKE_SOURCE_DIR}/library)
    target_include_directories(${PROJECT_NAME} PRIVATE ${CMAKE_SOURCE_DIR}/oberon/drivers)

    # add platform specific sources and includes before mbed includes
    target_include_directories(${PROJECT_NAME} PRIVATE ${CMAKE_SOURCE_DIR}/oberon/platforms/demo/drivers)

    # add mbed includes
    target_include_directories(${PROJECT_NAME} PRIVATE ${CMAKE_SOURCE_DIR}/tests/include)
    target_include_directories(${PROJECT_NAME} PRIVATE ${CMAKE_SOURCE_DIR}/include)

    # add mbedtls includes
    target_include_directories(${PROJECT_NAME} PRIVATE ${MBEDTLS_ROOT}/programs/test)
    target_include_directories(${PROJECT_NAME} PRIVATE ${MBEDTLS_ROOT}/include)

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

        # add TLS specific include for build_info.h
        target_include_directories(${PROJECT_NAME} PRIVATE ${CMAKE_SOURCE_DIR}/programs/ssl/include)

        # add libs
        target_link_libraries(${PROJECT_NAME} PUBLIC oberon-psa-crypto-ssl-${TEST_CONFIG})
        target_link_libraries(${PROJECT_NAME} PRIVATE ocrypto)

        # add TLS specific includes to use different configuration
        target_include_directories(${PROJECT_NAME} PRIVATE ${CMAKE_CURRENT_BINARY_DIR}/${TEST_CONFIG}/include)

        # add common includes
        target_include_directories(${PROJECT_NAME} PRIVATE ${CMAKE_SOURCE_DIR}/library)
        target_include_directories(${PROJECT_NAME} PRIVATE ${CMAKE_SOURCE_DIR}/oberon/drivers)

        # add platform specific sources and includes before mbed includes
        target_include_directories(${PROJECT_NAME} PRIVATE ${CMAKE_SOURCE_DIR}/oberon/platforms/demo/drivers)

        # add mbed includes
        target_include_directories(${PROJECT_NAME} PRIVATE ${CMAKE_SOURCE_DIR}/tests/include)
        target_include_directories(${PROJECT_NAME} PRIVATE ${CMAKE_SOURCE_DIR}/include)

        # add mbedtls includes
        target_include_directories(${PROJECT_NAME} PRIVATE ${MBEDTLS_ROOT}/programs/test)
        target_include_directories(${PROJECT_NAME} PRIVATE ${MBEDTLS_ROOT}/include)

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

            add_custom_command(
                TARGET ${PROJECT_NAME} PRE_LINK
                COMMAND ${CMAKE_COMMAND} -E copy
                ${CMAKE_SOURCE_DIR}/tests/generated/${SUITE}.datax
                ${PROJECT_BINARY_DIR}/
                DEPENDS ${PROJECT_BINARY_DIR}/${SUITE}.datax)

            # add libs
            target_link_libraries(${PROJECT_NAME} PRIVATE oberon-psa-crypto-ssl-${TEST_CONFIG})
            target_link_libraries(${PROJECT_NAME} PRIVATE ocrypto)

            # ssl sources
            target_sources(${PROJECT_NAME} PRIVATE
                ${MBEDTLS_ROOT}/library/ctr_drbg.c
                ${MBEDTLS_ROOT}/library/entropy.c
                ${MBEDTLS_ROOT}/library/entropy_poll.c
                ${MBEDTLS_ROOT}/tests/src/random.c
            )

            # test helpers
            target_sources(${PROJECT_NAME} PRIVATE
                ${CMAKE_SOURCE_DIR}/tests/src/asn1_helpers.c
                ${CMAKE_SOURCE_DIR}/tests/src/psa_exercise_key.c
                ${CMAKE_SOURCE_DIR}/tests/src/test_helpers/ssl_helpers.c
            )

            # add TLS specific include for build_info.h
            target_include_directories(${PROJECT_NAME} PRIVATE ${CMAKE_SOURCE_DIR}/programs/ssl/include)

            # add TLS specific includes to use different configuration
            target_include_directories(${PROJECT_NAME} PRIVATE ${CMAKE_CURRENT_BINARY_DIR}/${TEST_CONFIG}/include)

            # add common includes
            target_include_directories(${PROJECT_NAME} PRIVATE ${CMAKE_SOURCE_DIR}/library)
            target_include_directories(${PROJECT_NAME} PRIVATE ${CMAKE_SOURCE_DIR}/oberon/drivers)

            # add platform specific sources and includes before mbed includes
            target_include_directories(${PROJECT_NAME} PRIVATE ${CMAKE_SOURCE_DIR}/oberon/platforms/demo/drivers)

            # add mbed includes
            target_include_directories(${PROJECT_NAME} PRIVATE ${CMAKE_SOURCE_DIR}/tests/include)
            target_include_directories(${PROJECT_NAME} PRIVATE ${CMAKE_SOURCE_DIR}/include)

            # add mbedtls includes
            target_include_directories(${PROJECT_NAME} PRIVATE ${MBEDTLS_ROOT}/programs/test)
            target_include_directories(${PROJECT_NAME} PRIVATE ${MBEDTLS_ROOT}/include)

            target_include_directories(${PROJECT_NAME} PRIVATE ${MBEDTLS_ROOT}/tests/include)
            target_include_directories(${PROJECT_NAME} PRIVATE ${MBEDTLS_ROOT}/library)

            # add test
            add_test(NAME ${PROJECT_NAME} COMMAND ${PROJECT_NAME})
            set_property(TEST ${PROJECT_NAME} PROPERTY LABELS CONFIG_MBEDTLS_SSL_TESTS-${TEST_CONFIG})
        endforeach()
    endif()
endforeach()
