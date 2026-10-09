/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2026 Khadem Ullah
 */

#pragma once
#include "tlp.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    uint32_t mask;
    uint32_t value;
} pcie_filter_t;

#define PCIE_MATCH_TYPE(t) \
    (pcie_filter_t){ .mask = 0xFF, .value = (t) }

int pcie_filter_match(const pcie_filter_t *f,
                      const pcie_tlp_t *t);

#ifdef __cplusplus
}
#endif