/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2026 Khadem Ullah
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include "pcapcie/backend.h"
#include "pcapcie/pcapcie.h"

// PCI config backend: use the Linux PCI sysfs config file to perform config reads/writes.
// Override with PCIE_PCI_DEVICE or set PCI_DEVICE_ID at compile time.

#ifndef PCI_DEVICE_ID
#define PCI_DEVICE_ID "0000:00:03.0"
#endif
#define PCI_CONFIG_PATH "/sys/bus/pci/devices/%s/config"

#define MAX_COMPLETIONS 16

typedef struct {
    pcie_tlp_t tlp;
    uint8_t data[256];
} completion_t;

typedef struct {
    completion_t completions[MAX_COMPLETIONS];
    int head;
    int tail;
    int count;
} pci_backend_state_t;

static pci_backend_state_t pci_state = {0};

static int pci_enqueue_completion(const pcie_tlp_t *cpl) {
    if (pci_state.count >= MAX_COMPLETIONS) {
        pcie_log(PCIE_LOG_ERROR, "[pci] Completion queue full");
        return -1;
    }
    completion_t *comp = &pci_state.completions[pci_state.tail];
    memcpy(&comp->tlp, cpl, sizeof(pcie_tlp_t));
    if (cpl->length > 0 && cpl->mem.data) {
        memcpy(comp->data, cpl->mem.data, cpl->length);
        comp->tlp.mem.data = comp->data;
    }
    pci_state.tail = (pci_state.tail + 1) % MAX_COMPLETIONS;
    pci_state.count++;
    return 0;
}

static int pci_dequeue_completion(pcie_tlp_t *t) {
    if (pci_state.count == 0) {
        return -1;
    }
    completion_t *comp = &pci_state.completions[pci_state.head];
    memcpy(t, &comp->tlp, sizeof(pcie_tlp_t));
    if (t->length > 0) {
        t->mem.data = malloc(t->length);
        if (!t->mem.data) {
            pcie_log(PCIE_LOG_ERROR, "[pci] Memory allocation failed");
            return -1;
        }
        memcpy(t->mem.data, comp->data, t->length);
    }
    pci_state.head = (pci_state.head + 1) % MAX_COMPLETIONS;
    pci_state.count--;
    return 0;
}

static const char *pci_device_id(void)
{
    const char *device = getenv("PCIE_PCI_DEVICE");
    if (device && device[0] != '\0') {
        return device;
    }
    return PCI_DEVICE_ID;
}

static int pci_access_config(uint64_t offset, void *buf, size_t len, int is_write)
{
    char path[256];
    const char *device = pci_device_id();
    snprintf(path, sizeof(path), PCI_CONFIG_PATH, device);

    int fd = open(path, is_write ? O_RDWR : O_RDONLY);
    if (fd < 0) {
        pcie_log(PCIE_LOG_ERROR,
                 "[pci] Failed to open %s: %s (device=%s)",
                 path,
                 strerror(errno),
                 device);
        if (errno == EACCES || errno == EPERM) {
            pcie_log(PCIE_LOG_ERROR,
                     "[pci] Permission denied. Run as root or set correct sysfs permissions for %s",
                     device);
        }
        return -1;
    }

    ssize_t remaining = (ssize_t)len;
    uint8_t *cursor = (uint8_t *)buf;
    while (remaining > 0) {
        ssize_t result;
        if (is_write) {
            result = pwrite(fd, cursor, (size_t)remaining, (off_t)offset);
        } else {
            result = pread(fd, cursor, (size_t)remaining, (off_t)offset);
        }

        if (result < 0) {
            pcie_log(PCIE_LOG_ERROR, "[pci] %s config access failed: %s",
                     is_write ? "write" : "read",
                     strerror(errno));
            close(fd);
            return -1;
        }

        if (result == 0) {
            pcie_log(PCIE_LOG_ERROR, "[pci] %s config access failed: short transfer",
                     is_write ? "write" : "read");
            close(fd);
            return -1;
        }

        remaining -= result;
        cursor += result;
        offset += (uint64_t)result;
    }

    close(fd);
    return 0;
}

static int pci_find_pcie_capability(uint32_t *cap_offset)
{
    uint8_t cfg[256] = {0};
    uint8_t cap_ptr = 0;

    if (!cap_offset) {
        return -1;
    }

    if (pci_access_config(0x00, cfg, sizeof(cfg), 0) != 0) {
        return -1;
    }

    if ((cfg[0x06] & 0x10) == 0) {
        return -1;
    }

    cap_ptr = cfg[0x34];
    for (int i = 0; i < 48 && cap_ptr > 0; ++i) {
        uint8_t cap_hdr[2] = {0};
        if (pci_access_config(cap_ptr, cap_hdr, sizeof(cap_hdr), 0) != 0) {
            return -1;
        }

        if (cap_hdr[0] == 0x10) {
            *cap_offset = cap_ptr;
            return 0;
        }

        if (cap_hdr[1] == 0) {
            break;
        }

        cap_ptr = cap_hdr[1];
    }

    return -1;
}

static int pci_device_info(pcie_device_info_t *info)
{
    uint8_t hdr[16] = {0};
    uint16_t vendor_id;
    uint16_t device_id;
    uint16_t class_code;
    uint8_t rev_id;
    uint32_t cap_offset = 0;

    if (!info) {
        return -1;
    }

    memset(info, 0, sizeof(*info));
    if (pci_access_config(0x00, hdr, sizeof(hdr), 0) != 0) {
        return -1;
    }

    vendor_id = (uint16_t)hdr[0x00] | ((uint16_t)hdr[0x01] << 8);
    device_id = (uint16_t)hdr[0x02] | ((uint16_t)hdr[0x03] << 8);
    rev_id = hdr[0x08];
    class_code = (uint16_t)((uint32_t)hdr[0x0B] << 16 |
                            (uint32_t)hdr[0x0A] << 8 |
                            (uint32_t)hdr[0x09]);

    info->vendor_id = vendor_id;
    info->device_id = device_id;
    info->class_code = class_code;
    info->revision_id = rev_id;
    info->has_pcie_capability = (pci_find_pcie_capability(&cap_offset) == 0);

    pcie_log(PCIE_LOG_INFO,
             "[pci] Device vendor=0x%04x device=0x%04x class=0x%06x rev=0x%02x pcie_cap=%s",
             info->vendor_id,
             info->device_id,
             info->class_code,
             info->revision_id,
             info->has_pcie_capability ? "yes" : "no");

    return 0;
}

static int pci_link_status(pcie_link_status_t *status)
{
    uint32_t cap_offset = 0;
    uint8_t lnkcap_raw[2] = {0};
    uint8_t lnksta_raw[2] = {0};
    uint16_t lnkcap;
    uint16_t lnksta;
    uint8_t max_speed_code;
    uint8_t neg_speed_code;

    if (!status) {
        return -1;
    }
    memset(status, 0, sizeof(*status));

    if (pci_find_pcie_capability(&cap_offset) != 0) {
        pcie_log(PCIE_LOG_WARN,
                 "[pci] Device %s does not expose a PCIe capability list; this is usually a non-Express PCI device or a VM/virtualized environment.",
                 pci_device_id());
        return -1;
    }

    if (pci_access_config(cap_offset + 0x0C, lnkcap_raw, sizeof(lnkcap_raw), 0) != 0) {
        return -1;
    }
    if (pci_access_config(cap_offset + 0x12, lnksta_raw, sizeof(lnksta_raw), 0) != 0) {
        return -1;
    }

    lnkcap = (uint16_t)lnkcap_raw[0] | ((uint16_t)lnkcap_raw[1] << 8);
    lnksta = (uint16_t)lnksta_raw[0] | ((uint16_t)lnksta_raw[1] << 8);

    max_speed_code = (uint8_t)(lnkcap & 0x0F);
    neg_speed_code = (uint8_t)(lnksta & 0x0F);
    status->max_link_speed = pcie_link_speed_from_code(max_speed_code);
    status->negotiated_link_speed = pcie_link_speed_from_code(neg_speed_code);
    status->max_link_width = (uint8_t)((lnkcap >> 4) & 0x3F);
    status->negotiated_link_width = (uint8_t)((lnksta >> 4) & 0x3F);
    status->max_gen = pcie_gen_from_speed_code(max_speed_code);
    status->negotiated_gen = pcie_gen_from_speed_code(neg_speed_code);

    if (status->max_link_speed == PCIE_LINK_SPEED_UNKNOWN ||
        status->negotiated_link_speed == PCIE_LINK_SPEED_UNKNOWN) {
        pcie_log(PCIE_LOG_WARN,
                 "[pci] Link capability parsing is incomplete for %s; max_speed_code=0x%02x negotiated_speed_code=0x%02x",
                 pci_device_id(),
                 max_speed_code,
                 neg_speed_code);
        return -1;
    }

    pcie_log(PCIE_LOG_INFO,
             "[pci] Link status: max=%s/%u lanes, negotiated=%s/%u lanes",
             pcie_link_speed_name(status->max_link_speed),
             status->max_link_width,
             pcie_link_speed_name(status->negotiated_link_speed),
             status->negotiated_link_width);

    return 0;
}

static int pci_send(const pcie_tlp_t *t)
{
    if (!t) {
        pcie_log(PCIE_LOG_ERROR, "[pci] NULL TLP pointer");
        return -1;
    }

    if (t->type == PCIE_TLP_CFG_WRITE) {
        if (t->length == 0 || !t->mem.data) {
            pcie_log(PCIE_LOG_ERROR, "[pci] CFG write requires payload data");
            return -1;
        }
        pcie_log(PCIE_LOG_INFO, "[pci] CFG write offset=0x%lx len=%u", t->mem.addr, t->length);
        return pci_access_config(t->mem.addr, t->mem.data, t->length, 1);
    }

    if (t->type == PCIE_TLP_CFG_READ) {
        uint16_t length = t->length ? t->length : 4;
        uint8_t *data = (uint8_t *)t->mem.data;
        int alloc_local = 0;

        if (length > 256) {
            pcie_log(PCIE_LOG_ERROR, "[pci] CFG read length too large: %u", length);
            return -1;
        }

        if (!data) {
            data = calloc(1, length);
            if (!data) {
                pcie_log(PCIE_LOG_ERROR, "[pci] Failed to allocate CFG read buffer");
                return -1;
            }
            alloc_local = 1;
        }

        pcie_log(PCIE_LOG_INFO, "[pci] CFG read offset=0x%lx len=%u", t->mem.addr, length);
        if (pci_access_config(t->mem.addr, data, length, 0) != 0) {
            if (alloc_local) {
                free(data);
            }
            return -1;
        }

        printf("[pci] CFG read result:");
        for (int i = 0; i < length; ++i) {
            printf(" %02x", data[i]);
        }
        printf("\n");

        if (alloc_local) {
            free(data);
        }
        return 0;
    }

    pcie_log(PCIE_LOG_ERROR, "[pci] Unsupported TLP type %d", t->type);
    return -1;
}

static int pci_recv(pcie_tlp_t *t)
{
    (void)t;
    return -1;
}

static void pci_close(void)
{
    pcie_log(PCIE_LOG_INFO, "[pci] closed");
}

static const pcie_backend_ops_t pci_ops = {
    .send  = pci_send,
    .recv  = pci_recv,
    .link_status = pci_link_status,
    .device_info = pci_device_info,
    .close = pci_close
};

const pcie_backend_ops_t *pcie_backend_pci(void)
{
    return &pci_ops;
}
