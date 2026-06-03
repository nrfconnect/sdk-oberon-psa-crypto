/*
 * Copyright (c) 2025, Arm Limited or its affiliates. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 */

#ifndef VAL_COMMON_LOG_H
#define VAL_COMMON_LOG_H

#include "val_common.h"

/* Verbosity enums, Lower the value, higher the verbosity */
typedef enum {
    INFO    = 1,
    DBG     = 2,
    TEST    = 3,
    WARN    = 4,
    ERROR   = 5,
    ALWAYS  = 9
} print_verbosity_t;

/**
 *   @brief    - This function prints the given string and data onto the uart
 *   @param    - verbosity  : Print Verbosity level
 *   @param    - msg        : Input String
 *   @param    - ...        : ellipses for variadic args
 *   @return   - SUCCESS((Any positive number for character written)/FAILURE(0))
**/
uint32_t val_printf(print_verbosity_t verbosity, const char *msg, ...);

#endif /* VAL_COMMON_LOG_H */
