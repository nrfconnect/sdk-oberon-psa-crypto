/*
 * Copyright (c) 2025, Arm Limited or its affiliates. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 */

#ifndef VAL_COMMON_STATUS_H
#define VAL_COMMON_STATUS_H

#include "val_common.h"

/* Struture to capture test state */
typedef struct {
    uint16_t reserved;
    uint8_t  state;
    uint8_t  status_code;
} val_test_status_buffer_ts;

#define TEST_STATUS_OFFSET         0

//MSB is set at runtime based on ipa_width selected
#define VAL_NS_SHARED_REGION_IPA_OFFSET 0x700000

void *val_base_addr_ipa(uint64_t ipa_width);
void *val_get_shared_region_base_pa(void);
void *val_get_shared_region_base(void);
void val_set_status(uint32_t status);
uint32_t val_get_status(void);
uint32_t val_report_status(void);

#endif /* VAL_COMMON_STATUS_H */
