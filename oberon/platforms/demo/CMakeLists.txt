cmake_minimum_required(VERSION 3.13)

if(NOT "${PLATFORM}" STREQUAL "demo")
    message(FATAL_ERROR "Platform 'demo' expected but '${PLATFORM}' found!")
    return()
endif()

# MBed TLS tests for PSA Certified Crypto API
if (CONFIG_MBEDTLS_PSA_TESTS)
    include(CTest)

    message(STATUS "CONFIG_MBEDTLS_PSA_TESTS: Building for ${PLATFORM}")

    # add relative path to suites
    foreach(SUITE ${MBEDTEST_SUITES})
        list(APPEND TEST_SUITES "generated/${SUITE}")
    endforeach()    
    foreach(SUITE ${OBERON_TEST_SUITES})
        list(APPEND TEST_SUITES "src/${SUITE}")
    endforeach()

    # one pass with threading off, one pass with threading on
    set(THREADING_CONFIG single)
    if(CONFIG_MBEDTLS_THREADING)
        list(APPEND THREADING_CONFIG multi)
    endif()

    foreach(THREADING ${THREADING_CONFIG})
        if(CONFIG_MBEDTLS_THREADING AND ${THREADING} STREQUAL "multi") 
            file(GLOB config_files LIST_DIRECTORIES false "example_config/crypto_config_oberon*.h")
        else()
            file(GLOB config_files LIST_DIRECTORIES false "example_config/crypto_config*.h")
        endif()

        # one pass with pake inject, one pass without
        set(VARIANTS std pake_inject)
        foreach(VARIANT ${VARIANTS})
            # create projects for each crypto_config
            # file(GLOB config_files LIST_DIRECTORIES false "example_config/crypto_config*.h")
            foreach(CRYPTO_CONFIG_H ${config_files})
                get_filename_component(TEST_CONFIG "${CRYPTO_CONFIG_H}" NAME_WE)
                message(STATUS "Config: ${TEST_CONFIG}")
                project("${TEST_CONFIG}-${VARIANT}-${THREADING}-lib" LANGUAGES C)
                configure_file("${CRYPTO_CONFIG_H}"
                    "${CMAKE_CURRENT_BINARY_DIR}/${TEST_CONFIG}/include/psa/crypto_config.h"
                    COPYONLY)

                # test configuration library
                add_library(${PROJECT_NAME} OBJECT)
                set_target_properties(${PROJECT_NAME} PROPERTIES
                    RUNTIME_OUTPUT_DIRECTORY "${CMAKE_CURRENT_BINARY_DIR}/${TEST_CONFIG}-${VARIANT}-${THREADING}")

                # Oberon drivers and ocrypto
                target_link_libraries(${PROJECT_NAME} PUBLIC ocrypto)
                add_subdirectory(${CMAKE_SOURCE_DIR}/oberon/drivers ${TEST_CONFIG}-${VARIANT}-${THREADING})

                # common sources
                target_sources(${PROJECT_NAME} PRIVATE ${MBED_SOURCES})
                target_sources(${PROJECT_NAME} PRIVATE ${MBEDTEST_SOURCES})

                # add platform specific sources
                add_subdirectory(drivers drivers/${TEST_CONFIG}-${VARIANT}-${THREADING})
                target_sources(${PROJECT_NAME} PRIVATE library/psa_crypto_driver_wrappers.c)

                if(${VARIANT} STREQUAL "pake_inject")
                    target_compile_definitions(${PROJECT_NAME} PRIVATE OBERON_PAKE_INJECT_RANDOM)
                    target_sources(${PROJECT_NAME} PRIVATE "${CMAKE_SOURCE_DIR}/tests/src/oberon_test_drbg.c")
                endif()
                if(${THREADING} STREQUAL "multi")
                    target_compile_definitions(${PROJECT_NAME} PRIVATE MBEDTLS_THREADING_C)
                    target_compile_definitions(${PROJECT_NAME} PRIVATE MBEDTLS_THREADING_PTHREAD)
                    target_sources(${PROJECT_NAME} PRIVATE "${CMAKE_SOURCE_DIR}/library/threading.c")
                endif()

                # add platform-config specific includes first
                target_include_directories(${PROJECT_NAME} PRIVATE ${CMAKE_CURRENT_BINARY_DIR}/${TEST_CONFIG}-${VARIANT}-${THREADING}/include)

                # add platform specific includes before mbed includes
                target_include_directories(${PROJECT_NAME} PRIVATE drivers)
                target_include_directories(${PROJECT_NAME} PRIVATE include)
                target_include_directories(${PROJECT_NAME} PRIVATE ${CMAKE_SOURCE_DIR}/oberon/drivers)

                # add mbed includes
                target_include_directories(${PROJECT_NAME} PRIVATE ${CMAKE_SOURCE_DIR}/tests/include)
                target_include_directories(${PROJECT_NAME} PRIVATE ${CMAKE_SOURCE_DIR}/library)
                target_include_directories(${PROJECT_NAME} PRIVATE ${CMAKE_SOURCE_DIR}/include)

                foreach(SUITE_FILE ${TEST_SUITES})
                    get_filename_component(SUITE "${SUITE_FILE}" NAME)

                    if(${VARIANT} STREQUAL "pake_inject" AND ${SUITE} STREQUAL "pake_test" OR 
                        NOT(${VARIANT} STREQUAL "pake_inject") AND NOT(${SUITE} STREQUAL "pake_test"))
                        
                        project("${TEST_CONFIG}-${SUITE}-${VARIANT}-${THREADING}")
                        message(STATUS "Add test suite ${SUITE}")
                        add_executable(${PROJECT_NAME})
                        set_target_properties(${PROJECT_NAME} PROPERTIES
                            RUNTIME_OUTPUT_DIRECTORY "${CMAKE_CURRENT_BINARY_DIR}/${TEST_CONFIG}-${VARIANT}-${THREADING}")
                        target_sources(${PROJECT_NAME} PRIVATE "${CMAKE_SOURCE_DIR}/tests/${SUITE_FILE}.c")

                        string(FIND ${SUITE_FILE} "generated" INDEX)
                        if (INDEX EQUAL 0)
                            add_custom_command(
                                TARGET ${PROJECT_NAME} PRE_LINK
                                COMMAND ${CMAKE_COMMAND} -E copy
                                ${CMAKE_SOURCE_DIR}/tests/${SUITE_FILE}.datax
                                ${PROJECT_BINARY_DIR}/
                                DEPENDS ${PROJECT_BINARY_DIR}/${SUITE}.datax)
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
        endforeach()
    endforeach()

endif()
