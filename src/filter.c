/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2026 Khadem Ullah
 */

#include "pcapcie/filter.h"

int pcie_filter_match(const pcie_filter_t *f,
                      const pcie_tlp_t *t)
{
    return (((uint32_t)t->type & f->mask) == f->value);
}