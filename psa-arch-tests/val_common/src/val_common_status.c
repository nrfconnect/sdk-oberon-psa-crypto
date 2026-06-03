/*
 * Copyright (c) 2025, Arm Limited or its affiliates. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 */

#include "val_common_status.h"
#include "val_common_log.h"

static uint64_t width;

/**
 *   @brief    Returns the IPA address of the shared region
 *   @param    ipa_width      - Realm IPA width
 *   @return   IPA address of the shared region
**/
void *val_base_addr_ipa(uint64_t ipa_width)
{
    width = ipa_width;
    return ((void *)(uintptr_t)(VAL_NS_SHARED_REGION_IPA_OFFSET | (1ull << (width - 1))));
}

/**
 *   @brief    Returns the base address of the shared region
 *   @param    Void
 *   @return   Physical address of the shared region
**/
void *val_get_shared_region_base_pa(void)
{
    return ((void *)(PLATFORM_SHARED_REGION_BASE));
}

/**
 *   @brief    Returns the base address of the shared region
 *   @param    Void
 *   @return   Base address of the shared region
**/
void *val_get_shared_region_base(void)
{
    if (width)
        return val_base_addr_ipa(width);

    return val_get_shared_region_base_pa();
}

/**
 *   @brief    Records the state and status of test
 *   @param    status - Test status bit field - (state|status_code)
 *   @return   void
**/
void val_set_status(uint32_t status)
{
    uint8_t state = ((status >> TEST_STATE_SHIFT) & TEST_STATE_MASK);
    val_test_status_buffer_ts *curr_test_status = (void*)((uint8_t*)val_get_shared_region_base() /* !!OM */
                                                          + TEST_STATUS_OFFSET);

    curr_test_status->state = state;
    curr_test_status->status_code  = (status & TEST_STATUS_CODE_MASK);
}

/**
 *   @brief    Returns the state and status for a given test
 *   @param    Void
 *   @return   test status
**/
uint32_t val_get_status(void)
{
    val_test_status_buffer_ts *curr_test_status = (void*)((uint8_t*)val_get_shared_region_base() /* !!OM */
                                                          + TEST_STATUS_OFFSET);
    return (uint32_t)(((curr_test_status->state) << TEST_STATE_SHIFT) |
            (curr_test_status->status_code));
}

/**
 *   @brief    Parses input status for a given test and
 *             outputs appropriate information on the console
 *   @param    Void
 *   @return   Test state
**/
uint32_t val_report_status(void)
{
    uint32_t status, status_code, state;
    status = val_get_status();
    state = (status >> TEST_STATE_SHIFT) & TEST_STATE_MASK;
    status_code = status & TEST_STATUS_CODE_MASK;

    switch (state)
    {
        case TEST_PASS:
            state = TEST_PASS;
            val_printf(ALWAYS, "Result=Passed\n");
            break;

        case TEST_FAIL:
            state = TEST_FAIL;
            val_printf(ALWAYS, "Result=Failed (Error code=%d)\n",
                status_code);
            break;

        case TEST_SKIP:
            state = TEST_SKIP;
            val_printf(ALWAYS, "Result=Skipped (Skip code=%d)\n",
                status_code);
            break;

        case TEST_ERROR:
            state = TEST_ERROR;
            val_printf(ALWAYS, "Result=Error (Error code=%d)\n",
                status_code);
            break;
        default:
            state = TEST_FAIL;
            val_printf(ALWAYS, "Result=Failed (Error Code=%d)\n",
                status_code);
            break;
    }

    val_printf(ALWAYS, "***********************************\n");
    return state;
}
