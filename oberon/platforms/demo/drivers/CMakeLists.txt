cmake_minimum_required(VERSION 3.13)

set(OBERON_SOURCES
        demo_entropy.c
        demo_entropy.h
        demo_hardware.c
        demo_hardware.h
        demo_opaque.c
        demo_opaque.h
        )

target_sources(${PROJECT_NAME} PRIVATE ${OBERON_SOURCES})

target_include_directories(${PROJECT_NAME} PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
