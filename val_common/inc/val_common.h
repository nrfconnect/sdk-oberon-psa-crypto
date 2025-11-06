/*
 * Copyright (c) 2025, Arm Limited or its affiliates. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 */

#ifndef VAL_COMMON_H
#define VAL_COMMON_H

#include "pal_common_val_intf.h"

/* Various test status codes, Max value = 0xff */
#define  VAL_SUCCESS            0
#define  VAL_ERROR_POINT(n)     n
#define  VAL_TEST_INIT_FAILED   101
#define  VAL_STATUS_INVALID     102
#define  VAL_SKIP_CHECK         103
#define  VAL_SIM_ERROR          104

#define  VAL_STATUS_ERROR_MAX   255
#define  VAL_INVALID_TEST_NUM   0xFFFFFFFF

#define VAL_BIT_MASK(len) ((1 << len) - 1)
/* Set the value in given position */
#define VAL_SET_BITS(data, pos, len, val) (((uint32_t)(~(uint32_t)0 & ~(uint32_t) \
                    (VAL_BIT_MASK(len) << pos)) & data) | (val << pos))


/* Test state macros */
#define TEST_START              0x01
#define TEST_PASS               0x02
#define TEST_FAIL               0x03
#define TEST_SKIP               0x04
#define TEST_ERROR              0x05
#define TEST_END                0x06
#define TEST_REBOOTING          0x07

#define TEST_STATE_SHIFT        8
#define TEST_STATE_MASK         0xFF
#define TEST_STATUS_CODE_MASK   0xFF
#define TEST_STATUS_CODE_SHIFT  0

#define RESULT_START(status)   (((TEST_START) << TEST_STATE_SHIFT) |\
                                    ((status) << TEST_STATUS_CODE_SHIFT))
#define RESULT_END(status)       (((TEST_END) << TEST_STATE_SHIFT) |\
                                    ((status) << TEST_STATUS_CODE_SHIFT))
#define RESULT_PASS(status)     (((TEST_PASS) << TEST_STATE_SHIFT) |\
                                    ((status) << TEST_STATUS_CODE_SHIFT))
#define RESULT_FAIL(status)     (((TEST_FAIL) << TEST_STATE_SHIFT) |\
                                    ((status) << TEST_STATUS_CODE_SHIFT))
#define RESULT_SKIP(status)     (((TEST_SKIP) << TEST_STATE_SHIFT) |\
                                    ((status) << TEST_STATUS_CODE_SHIFT))
#define RESULT_ERROR(status)     (((TEST_ERROR) << TEST_STATE_SHIFT) |\
                                    ((status) << TEST_STATUS_CODE_SHIFT))

#define IS_TEST_FAIL(status)    (((status >> TEST_STATE_SHIFT) & TEST_STATE_MASK) == TEST_FAIL)
#define IS_TEST_PASS(status)    (((status >> TEST_STATE_SHIFT) & TEST_STATE_MASK) == TEST_PASS)
#define IS_TEST_SKIP(status)    (((status >> TEST_STATE_SHIFT) & TEST_STATE_MASK) == TEST_SKIP)
#define IS_TEST_ERROR(status)   (((status >> TEST_STATE_SHIFT) & TEST_STATE_MASK) == TEST_ERROR)
#define IS_TEST_START(status)   (((status >> TEST_STATE_SHIFT) & TEST_STATE_MASK) == TEST_START)
#define IS_TEST_END(status)     (((status >> TEST_STATE_SHIFT) & TEST_STATE_MASK) == TEST_END)
#define IS_STATUS_FAIL(status)  ((status & TEST_STATUS_CODE_MASK) ? 1 : 0)


/* NVM Indext size */
#define VAL_NVM_BLOCK_SIZE       4
#define VAL_NVM_OFFSET(nvm_idx)  (nvm_idx * VAL_NVM_BLOCK_SIZE)

typedef enum {
    NVM_PLATFORM_RESERVE_INDEX  =  0x0,
    NVM_CUR_SUITE_NUM_INDEX     =  0x1,
    NVM_CUR_TEST_NUM_INDEX      =  0x2,
    NVM_END_TEST_NUM_INDEX      =  0x3,
    NVM_TEST_PROGRESS_INDEX     =  0x4,
    NVM_TOTAL_PASS_INDEX        =  0x5,
    NVM_TOTAL_FAIL_INDEX        =  0x6,
    NVM_TOTAL_SKIP_INDEX        =  0x7,
    NVM_TOTAL_ERROR_INDEX       =  0x8,
    NVM_BOOT                    =  0x9,
    NVM_PREVIOUS_TEST_ID        =  0xA,
    NVM_TEST_DATA1              =  0xB,
    NVM_TEST_DATA2              =  0xC,
    NVM_TEST_DATA3              =  0xD,
} nvm_map_index_t;

#endif /* VAL_COMMON_H */
