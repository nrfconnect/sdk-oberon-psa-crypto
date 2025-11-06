#-------------------------------------------------------------------------------
# Copyright (c) 2025, Arm Limited or its affiliates. All rights reserved.
#
# SPDX-License-Identifier: BSD-3-Clause
#
#-------------------------------------------------------------------------------

get_filename_component(COMMON_VAL "${CMAKE_CURRENT_LIST_DIR}" ABSOLUTE)

# Listing all the sources required
list(APPEND COMMON_VAL_SRC_C
    ${COMMON_VAL}/src/val_common_log.c
    ${COMMON_VAL}/src/val_common_status.c
    ${COMMON_VAL}/src/val_common_framework.c
    ${COMMON_VAL}/src/val_common_peripherals.c
)

# Create a Common VAL library
add_library(${COMMON_VAL_LIB} STATIC ${COMMON_VAL_SRC_C})

# Listing all the header files required
target_include_directories(${COMMON_VAL_LIB} PRIVATE ${COMMON_VAL}/inc/)

if (COMMON_VAL_HEADERS)
    foreach(common_val_headers ${COMMON_VAL_HEADERS})
        target_include_directories(${COMMON_VAL_LIB} PRIVATE ${common_val_headers})
    endforeach()
else()
    message(FATAL_ERROR "Cannot find \"COMMON_VAL_HEADERS\" list. Please append and place it properly.")
endif()
