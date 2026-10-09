/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2026 Khadem Ullah
 */

#pragma once
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    PCIE_TLP_UNKNOWN   = 0xFF,
    PCIE_TLP_MEM_READ  = 0x00,
    PCIE_TLP_MEM_WRITE = 0x01,
    PCIE_TLP_CFG_READ  = 0x04,
    PCIE_TLP_CFG_WRITE = 0x05,
    PCIE_TLP_CPL       = 0x0A
} pcie_tlp_type_t;

typedef struct {
    uint64_t addr;
    uint8_t *data;
} pcie_mem_t;

typedef struct {
    pcie_tlp_type_t type;
    uint16_t requester_id;
    uint16_t completer_id;
    uint8_t  tag;
    uint16_t length;

    union {
        pcie_mem_t mem;
    };
} pcie_tlp_t;

/* TLP decoding helpers */
const char *pcie_tlp_type_name(pcie_tlp_type_t type);
pcie_tlp_type_t pcie_tlp_type_from_code(uint8_t code);
pcie_tlp_t pcie_tlp_decode(uint8_t type_code,
                          uint16_t requester_id,
                          uint16_t completer_id,
                          uint8_t tag,
                          uint16_t length,
                          uint64_t addr,
                          uint8_t *payload);

/* Convenience constructors */
pcie_tlp_t pcie_tlp_mem_write(uint64_t addr,
                             uint16_t length,
                             uint8_t *data);
pcie_tlp_t pcie_tlp_cfg_write(uint32_t addr,
                             uint16_t length,
                             uint8_t *data);
pcie_tlp_t pcie_tlp_cfg_read(uint32_t addr);

#ifdef __cplusplus
}
#endif
