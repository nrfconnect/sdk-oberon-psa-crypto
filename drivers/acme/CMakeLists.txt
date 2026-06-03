cmake_minimum_required(VERSION 3.13)

set(DRIVER_SOURCES
        acme_rng.c
        acme_rng.h
        acme_sha.c
        acme_sha.h
        acme_aes.c
        acme_aes.h
        acme_mac.c
        acme_mac.h
        acme_kdf.c
        acme_kdf.h
)

target_sources(${PROJECT_NAME} PRIVATE ${DRIVER_SOURCES})

target_include_directories(${PROJECT_NAME} PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
