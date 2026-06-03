cmake_minimum_required(VERSION 3.13)

if(NOT "${PLATFORM}" STREQUAL "poc")
    message(FATAL_ERROR "Platform 'poc' expected but '${PLATFORM}' found!")
    return()
endif()

# MBed TLS tests for PSA Certified Crypto API
if (CONFIG_MBEDTLS_PSA_TESTS OR CONFIG_MBEDTLS_PSA_TESTS_LONG)
    include(CTest)

    message(STATUS "CONFIG_MBEDTLS_PSA_TESTS: Building for ${PLATFORM}")

    # add relative path to suites
    if(CONFIG_MBEDTLS_PSA_TESTS)
        foreach(SUITE ${MBEDTEST_SUITES})
            list(APPEND TEST_SUITES "generated/${SUITE}")
        endforeach()
        foreach(SUITE ${OBERON_TEST_SUITES})
            list(APPEND TEST_SUITES "src/${SUITE}")
        endforeach()
    endif()    
    if(CONFIG_MBEDTLS_PSA_TESTS_LONG)
        foreach(SUITE ${MBEDTEST_SUITES_LONG})
            list(APPEND TEST_SUITES "generated/${SUITE}")
        endforeach()
    endif()    

    # one pass with threading off, one pass with threading on
    set(THREADING_CONFIG single)
    if(CONFIG_MBEDTLS_THREADING)
        list(APPEND THREADING_CONFIG multi)
    endif()

    foreach(THREADING ${THREADING_CONFIG})
        set(VARIANT std)
        set(CRYPTO_CONFIG_H "dispatch/psa/crypto_config.h")
        get_filename_component(TEST_CONFIG "${CRYPTO_CONFIG_H}" NAME_WE)
        project("${TEST_CONFIG}-${VARIANT}-${THREADING}-lib" LANGUAGES C)
        configure_file(${CRYPTO_CONFIG_H}
            ${CMAKE_CURRENT_BINARY_DIR}/${TEST_CONFIG}-${VARIANT}-${THREADING}/dispatch/psa/crypto_config.h
            COPYONLY)

        # test configuration library
        add_library(${PROJECT_NAME} OBJECT)
        set_target_properties(${PROJECT_NAME} PROPERTIES
            RUNTIME_OUTPUT_DIRECTORY "${CMAKE_CURRENT_BINARY_DIR}/${TEST_CONFIG}-${VARIANT}-${THREADING}")

        # common sources
        target_sources(${PROJECT_NAME} PRIVATE ${TF_PSA_CRYPTO_SOURCES})
        target_sources(${PROJECT_NAME} PRIVATE ${MBEDTEST_SOURCES})

        # add platform specific sources
        add_subdirectory(${CMAKE_SOURCE_DIR}/drivers/acme drivers/${TEST_CONFIG}-${VARIANT}-${THREADING})

        # use demo psa_crypto_driver_wrappers.c
        target_sources(${PROJECT_NAME} PRIVATE dispatch/psa_crypto_driver_wrappers.c)

        if(${THREADING} STREQUAL "multi")
            target_compile_definitions(${PROJECT_NAME} PRIVATE MBEDTLS_THREADING_C)
            target_compile_definitions(${PROJECT_NAME} PRIVATE MBEDTLS_THREADING_PTHREAD)
            target_sources(${PROJECT_NAME} PRIVATE ${CMAKE_SOURCE_DIR}/platform/threading.c)
        endif()

        # add platform-config specific includes first
        target_include_directories(${PROJECT_NAME} PRIVATE ${CMAKE_CURRENT_BINARY_DIR}/${TEST_CONFIG}-${VARIANT}-${THREADING}/include)

        # add platform specific includes before mbed includes
        target_include_directories(${PROJECT_NAME} PRIVATE ${CMAKE_SOURCE_DIR}/drivers/acme)
        target_include_directories(${PROJECT_NAME} PRIVATE dispatch)

        # add mbed includes
        target_include_directories(${PROJECT_NAME} PRIVATE ${CMAKE_SOURCE_DIR}/core)
        target_include_directories(${PROJECT_NAME} PRIVATE ${CMAKE_SOURCE_DIR}/dispatch)
        target_include_directories(${PROJECT_NAME} PRIVATE ${CMAKE_SOURCE_DIR}/platform)
        target_include_directories(${PROJECT_NAME} PRIVATE ${CMAKE_SOURCE_DIR}/utilities)
        target_include_directories(${PROJECT_NAME} PRIVATE ${CMAKE_SOURCE_DIR}/extras)
        target_include_directories(${PROJECT_NAME} PRIVATE ${CMAKE_SOURCE_DIR}/include)

        # add mbed includes for testing
        target_include_directories(${PROJECT_NAME} PRIVATE ${CMAKE_SOURCE_DIR}/framework/tests/include)
        target_include_directories(${PROJECT_NAME} PRIVATE ${CMAKE_SOURCE_DIR}/tests/include)
        target_include_directories(${PROJECT_NAME} PRIVATE ${CMAKE_SOURCE_DIR}/legacy_sub/src)
        target_include_directories(${PROJECT_NAME} PRIVATE ${CMAKE_SOURCE_DIR}/legacy_sub/include)

        foreach(SUITE_FILE ${TEST_SUITES})
            get_filename_component(SUITE "${SUITE_FILE}" NAME)

            # make sure, CONFIG_MBEDTLS_PSA_TESTS_LONG only run once 
            if(NOT(SUITE IN_LIST MBEDTEST_SUITES_LONG) OR (${THREADING} STREQUAL "single"))

                    project("${TEST_CONFIG}-${SUITE}-${VARIANT}-${THREADING}")
                    message(STATUS "Add test suite ${SUITE}")
                    add_executable(${PROJECT_NAME})
                    set_target_properties(${PROJECT_NAME} PROPERTIES
                        RUNTIME_OUTPUT_DIRECTORY "${CMAKE_CURRENT_BINARY_DIR}/${TEST_CONFIG}-${VARIANT}-${THREADING}")
                    target_sources(${PROJECT_NAME} PRIVATE "${CMAKE_SOURCE_DIR}/tests/${SUITE_FILE}.c")

                    if(UNIX)
                        set(DATAX_DIR "${CMAKE_CURRENT_BINARY_DIR}/${TEST_CONFIG}-${VARIANT}-${THREADING}")
                    else()
                        set(DATAX_DIR "${PROJECT_BINARY_DIR}")
                    endif()

                    string(FIND ${SUITE_FILE} "generated" INDEX)
                    if (INDEX EQUAL 0)
                        add_custom_command(
                            TARGET ${PROJECT_NAME} PRE_LINK
                            COMMAND ${CMAKE_COMMAND} -E copy
                            ${CMAKE_SOURCE_DIR}/tests/${SUITE_FILE}.datax
                            ${DATAX_DIR}/
                        )
                    endif()

                    # include the same target include directories as the TEST_CONFIG library
                    target_include_directories("${PROJECT_NAME}" PRIVATE
                        "$<TARGET_PROPERTY:${TEST_CONFIG}-${VARIANT}-${THREADING}-lib,INCLUDE_DIRECTORIES>"
                    )

                    # link libraries
                    target_link_libraries(${PROJECT_NAME} PRIVATE ocrypto)
                    target_link_libraries(${PROJECT_NAME} PRIVATE ${TEST_CONFIG}-${VARIANT}-${THREADING}-lib)

                    add_test(NAME ${PROJECT_NAME} COMMAND ${PROJECT_NAME})
                    set_property(TEST ${PROJECT_NAME} PROPERTY LABELS CONFIG_MBEDTLS_PSA_TESTS-${TEST_CONFIG}-${VARIANT}-${THREADING})

            endif()
        endforeach()
    endforeach()

endif()

# PSA API Test Suite; uses demo drivers for RNG, SHA, and AES
# requires corresponding configuration in api-tests/platform/targets/tgt_dev_apis_linux/nspe/pal_crypto_config.h
if (CONFIG_PSA_API_TESTS)

    message(STATUS "CONFIG_PSA_API_TESTS:     Building for ${PLATFORM}")

    # cmake ../ -G"Unix Makefiles" -DTARGET=tgt_dev_apis_linux \
    #           -DTOOLCHAIN=INHERIT -DSUITE=CRYPTO -DPSA_INCLUDE_PATHS="..."

    set(TARGET tgt_dev_apis_linux)
    set(TOOLCHAIN INHERIT)
    set(SUITE CRYPTO)
    set(PSA_INCLUDE_PATHS_RELATIVE
            include
            drivers/acme
            targets/acme/${PLATFORM}/dispatch # use psa/crypto_config.h from ${PLATFORM}
    )
    set(PSA_INCLUDE_PATHS "")
    foreach(PSA_INCLUDE_PATH ${PSA_INCLUDE_PATHS_RELATIVE})
        get_filename_component(PSA_INCLUDE_PATH "${CMAKE_SOURCE_DIR}/${PSA_INCLUDE_PATH}" REALPATH)
        list(APPEND PSA_INCLUDE_PATHS ${PSA_INCLUDE_PATH})
    endforeach()

    project("${TARGET}" LANGUAGES C ASM)
    add_subdirectory(${PSA_ARCH_TESTS}/api-tests api-tests)
    add_executable(${PROJECT_NAME} ${PSA_ARCH_TESTS}/api-tests/platform/targets/${PROJECT_NAME}/nspe/main.c)

    if(CONFIG_MBEDTLS_THREADING)
        target_compile_definitions(${PROJECT_NAME} PRIVATE MBEDTLS_THREADING_C)
        target_compile_definitions(${PROJECT_NAME} PRIVATE MBEDTLS_THREADING_PTHREAD)
        target_sources(${PROJECT_NAME} PRIVATE "${CMAKE_SOURCE_DIR}/platform/threading.c")
    endif()

    add_subdirectory(${CMAKE_SOURCE_DIR}/drivers/acme targets/acme/${PLATFORM}/drivers/${TARGET})

    target_sources(${PROJECT_NAME} PRIVATE ${TF_PSA_CRYPTO_SOURCES})

    # use psa_crypto_driver_wrappers.c for ${PLATFORM}
    target_sources(${PROJECT_NAME} PRIVATE dispatch/psa_crypto_driver_wrappers.c)

    # use psa config from oberon/${PLATFORM}/dispatch/psa/
    target_include_directories(${PROJECT_NAME} PRIVATE "${CMAKE_SOURCE_DIR}/targets/acme/${PLATFORM}/dispatch")

    # use other headers from default locations
    target_include_directories(${PROJECT_NAME} PRIVATE "${CMAKE_SOURCE_DIR}/core")
    target_include_directories(${PROJECT_NAME} PRIVATE "${CMAKE_SOURCE_DIR}/dispatch")
    target_include_directories(${PROJECT_NAME} PRIVATE "${CMAKE_SOURCE_DIR}/platform")
    target_include_directories(${PROJECT_NAME} PRIVATE "${CMAKE_SOURCE_DIR}/utilities")
    target_include_directories(${PROJECT_NAME} PRIVATE "${CMAKE_SOURCE_DIR}/include")

    target_link_libraries(${TARGET} PRIVATE val_nspe)
    target_link_libraries(${TARGET} PRIVATE pal_nspe)
    target_link_libraries(${TARGET} PRIVATE test_combine)

    set_target_properties(${PROJECT_NAME} PROPERTIES
            RUNTIME_OUTPUT_DIRECTORY "${CMAKE_CURRENT_BINARY_DIR}/${TARGET}")

    add_test(NAME ${PROJECT_NAME} COMMAND "${CMAKE_CURRENT_BINARY_DIR}/${PROJECT_NAME}/${PROJECT_NAME}")
    set_property(TEST ${PROJECT_NAME} PROPERTY LABELS CONFIG_PSA_API_TESTS)
endif()
