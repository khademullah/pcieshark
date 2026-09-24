#pragma once
#include "tlp.h"

#ifdef __cplusplus
extern "C" {
#endif

struct pcie_link_status;
typedef struct pcie_link_status pcie_link_status_t;
struct pcie_device_info;
typedef struct pcie_device_info pcie_device_info_t;

typedef struct pcie_backend_ops {
    int (*send)(const pcie_tlp_t *t);
    int (*recv)(pcie_tlp_t *t);
    int (*link_status)(pcie_link_status_t *status);
    int (*device_info)(pcie_device_info_t *info);
    void (*close)(void);
} pcie_backend_ops_t;

const pcie_backend_ops_t *pcie_backend_dummy(void);
const pcie_backend_ops_t *pcie_backend_golden(void);
const pcie_backend_ops_t *pcie_backend_fpga(void);
const pcie_backend_ops_t *pcie_backend_armds(void);
const pcie_backend_ops_t *pcie_backend_pci(void);

#ifdef __cplusplus
}
#endif
