cmake_minimum_required(VERSION 3.13)

if(NOT DEFINED OCRYPTO_ROOT)
    set(OCRYPTO_ROOT ${CMAKE_CURRENT_LIST_DIR})
endif()
message(STATUS "Add ocrypto source: ${OCRYPTO_ROOT}")

project(ocrypto
        LANGUAGES C ASM)

add_library(${PROJECT_NAME} OBJECT)

file(GLOB OCRYPTO_SOURCES LIST_DIRECTORIES false CONFIGURE_DEPENDS "${OCRYPTO_ROOT}/src/ocrypto_*.[c|h]")

file(GLOB OCRYPTO_PLATFORM_SOURCES LIST_DIRECTORIES false CONFIGURE_DEPENDS "${OCRYPTO_ROOT}/src/platforms/Generic/ocrypto_*.[c|h]")

target_sources(${PROJECT_NAME} PRIVATE
        ${OCRYPTO_SOURCES}
        ${OCRYPTO_PLATFORM_SOURCES})

target_include_directories(${PROJECT_NAME} PUBLIC
        ${OCRYPTO_ROOT}/include)

target_include_directories(${PROJECT_NAME} PRIVATE
        ${OCRYPTO_ROOT}/src/platforms/Generic)

target_include_directories(${PROJECT_NAME} PRIVATE
        ${OCRYPTO_ROOT}/src)
