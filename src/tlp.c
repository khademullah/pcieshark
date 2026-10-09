/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2026 Khadem Ullah
 */

#include "pcapcie/tlp.h"
#include <stddef.h>

const char *pcie_tlp_type_name(pcie_tlp_type_t type)
{
    switch (type) {
        case PCIE_TLP_MEM_READ:  return "MemRead";
        case PCIE_TLP_MEM_WRITE: return "MemWrite";
        case PCIE_TLP_CFG_READ:  return "CfgRead";
        case PCIE_TLP_CFG_WRITE: return "CfgWrite";
        case PCIE_TLP_CPL:       return "Completion";
        default:                 return "Unknown";
    }
}

pcie_tlp_type_t pcie_tlp_type_from_code(uint8_t code)
{
    switch (code) {
        case PCIE_TLP_MEM_READ:  return PCIE_TLP_MEM_READ;
        case PCIE_TLP_MEM_WRITE: return PCIE_TLP_MEM_WRITE;
        case PCIE_TLP_CFG_READ:  return PCIE_TLP_CFG_READ;
        case PCIE_TLP_CFG_WRITE: return PCIE_TLP_CFG_WRITE;
        case PCIE_TLP_CPL:       return PCIE_TLP_CPL;
        default:                 return PCIE_TLP_UNKNOWN;
    }
}

pcie_tlp_t pcie_tlp_decode(uint8_t type_code,
                          uint16_t requester_id,
                          uint16_t completer_id,
                          uint8_t tag,
                          uint16_t length,
                          uint64_t addr,
                          uint8_t *payload)
{
    pcie_tlp_t t = {0};
    t.type = pcie_tlp_type_from_code(type_code);
    t.requester_id = requester_id;
    t.completer_id = completer_id;
    t.tag = tag;
    t.length = length;
    t.mem.addr = addr;
    t.mem.data = payload;
    return t;
}

pcie_tlp_t pcie_tlp_mem_write(uint64_t addr,
                             uint16_t length,
                             uint8_t *data)
{
    pcie_tlp_t t = {0};
    t.type = PCIE_TLP_MEM_WRITE;
    t.length = length;
    t.mem.addr = addr;
    t.mem.data = data;
    return t;
}

pcie_tlp_t pcie_tlp_cfg_write(uint32_t addr,
                             uint16_t length,
                             uint8_t *data)
{
    pcie_tlp_t t = {0};
    t.type = PCIE_TLP_CFG_WRITE;
    t.length = length;
    t.mem.addr = addr;
    t.mem.data = data;
    return t;
}

pcie_tlp_t pcie_tlp_cfg_read(uint32_t addr)
{
    pcie_tlp_t t = {0};
    t.type = PCIE_TLP_CFG_READ;
    t.length = 0;  // No data for read requests
    t.mem.addr = addr;
    t.mem.data = NULL;
    return t;
}
