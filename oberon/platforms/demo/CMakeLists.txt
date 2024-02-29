cmake_minimum_required(VERSION 3.13)

if(NOT "${PLATFORM}" STREQUAL "demo")
    message(FATAL_ERROR "Platform 'demo' expected but '${PLATFORM}' found!")
    return()
endif()

# MBed TLS tests for PSA Certified Crypto API
if (CONFIG_MBEDTLS_PSA_TESTS)
    include(CTest)

    message(STATUS "CONFIG_MBEDTLS_PSA_TESTS: Building for ${PLATFORM}")

    # create projects for each crypto_config
    file(GLOB config_files LIST_DIRECTORIES false "example_config/crypto_config*.h")
    foreach(CRYPTO_CONFIG_H ${config_files})
        get_filename_component(TEST_CONFIG "${CRYPTO_CONFIG_H}" NAME_WE)
        message(STATUS "Config: ${TEST_CONFIG}")
        project("${TEST_CONFIG}-lib" LANGUAGES C ASM)
        configure_file("${CRYPTO_CONFIG_H}"
                "${CMAKE_CURRENT_BINARY_DIR}/${TEST_CONFIG}/include/psa/crypto_config.h"
                COPYONLY)

        # test configuration library
        add_library(${PROJECT_NAME} OBJECT)
        set_target_properties(${PROJECT_NAME} PROPERTIES
                RUNTIME_OUTPUT_DIRECTORY "${CMAKE_CURRENT_BINARY_DIR}/${TEST_CONFIG}")

        # Oberon drivers and ocrypto
        target_link_libraries(${PROJECT_NAME} PUBLIC ocrypto)
        add_subdirectory(${CMAKE_SOURCE_DIR}/oberon/drivers ${TEST_CONFIG})

        # common sources
        target_sources(${PROJECT_NAME} PRIVATE ${MBED_SOURCES})
        target_sources(${PROJECT_NAME} PRIVATE ${MBEDTEST_SOURCES})

        # add platform specific sources
        add_subdirectory(drivers drivers/${TEST_CONFIG})
        target_sources(${PROJECT_NAME} PRIVATE library/psa_crypto_driver_wrappers.c)

        # add platform-config specific includes first
        target_include_directories(${PROJECT_NAME} PRIVATE ${CMAKE_CURRENT_BINARY_DIR}/${TEST_CONFIG}/include)

        # add platform specific includes before mbed includes
        target_include_directories(${PROJECT_NAME} PRIVATE drivers)
        target_include_directories(${PROJECT_NAME} PRIVATE include)
        target_include_directories(${PROJECT_NAME} PRIVATE ${CMAKE_SOURCE_DIR}/oberon/drivers)

        # add mbed includes
        target_include_directories(${PROJECT_NAME} PRIVATE ${CMAKE_SOURCE_DIR}/tests/include)
        target_include_directories(${PROJECT_NAME} PRIVATE ${CMAKE_SOURCE_DIR}/library)
        target_include_directories(${PROJECT_NAME} PRIVATE ${CMAKE_SOURCE_DIR}/include)

        foreach(SUITE ${MBEDTEST_SUITES})
            project("${TEST_CONFIG}-${SUITE}")
            message(STATUS "Add test suite ${SUITE}")
            add_executable(${PROJECT_NAME})
            set_target_properties(${PROJECT_NAME} PROPERTIES
                    RUNTIME_OUTPUT_DIRECTORY "${CMAKE_CURRENT_BINARY_DIR}/${TEST_CONFIG}")
            target_sources(${PROJECT_NAME} PRIVATE "${CMAKE_SOURCE_DIR}/tests/generated/${SUITE}.c")

            add_custom_command(
                    TARGET ${PROJECT_NAME} PRE_LINK
                    COMMAND ${CMAKE_COMMAND} -E copy
                    ${CMAKE_SOURCE_DIR}/tests/generated/${SUITE}.datax
                    ${PROJECT_BINARY_DIR}/
                    DEPENDS ${PROJECT_BINARY_DIR}/${SUITE}.datax)

            # include the same target include directories as the TEST_CONFIG library
            target_include_directories("${PROJECT_NAME}" PRIVATE
                    "$<TARGET_PROPERTY:${TEST_CONFIG}-lib,INCLUDE_DIRECTORIES>"
            )

            # link libraries
            target_link_libraries(${PROJECT_NAME} PRIVATE ocrypto)
            target_link_libraries(${PROJECT_NAME} PRIVATE ${TEST_CONFIG}-lib)

            add_test(NAME ${PROJECT_NAME} COMMAND ${PROJECT_NAME})
            set_property(TEST ${PROJECT_NAME} PROPERTY LABELS CONFIG_MBEDTLS_PSA_TESTS-${TEST_CONFIG})
        endforeach()
        foreach(SUITE ${OBERON_TEST_SUITES})
            project("${TEST_CONFIG}-${SUITE}")
            message(STATUS "Add test suite ${SUITE}")
            add_executable(${PROJECT_NAME})
            set_target_properties(${PROJECT_NAME} PROPERTIES
                    RUNTIME_OUTPUT_DIRECTORY "${CMAKE_CURRENT_BINARY_DIR}/${TEST_CONFIG}")
            target_sources(${PROJECT_NAME} PRIVATE "${CMAKE_SOURCE_DIR}/tests/src/${SUITE}.c")

            # include the same target include directories as the TEST_CONFIG library
            target_include_directories("${PROJECT_NAME}" PRIVATE
                    "$<TARGET_PROPERTY:${TEST_CONFIG}-lib,INCLUDE_DIRECTORIES>"
            )

            # link libraries
            target_link_libraries(${PROJECT_NAME} PRIVATE ocrypto)
            target_link_libraries(${PROJECT_NAME} PRIVATE ${TEST_CONFIG}-lib)

            add_test(NAME ${PROJECT_NAME} COMMAND ${PROJECT_NAME})
            set_property(TEST ${PROJECT_NAME} PROPERTY LABELS CONFIG_MBEDTLS_PSA_TESTS-${TEST_CONFIG})
        endforeach()
    endforeach()
endif()
