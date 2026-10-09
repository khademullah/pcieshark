/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2026 Khadem Ullah
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/ioctl.h>
#include <errno.h>
#include "pcapcie/backend.h"
#include "pcapcie/pcapcie.h"

// FPGA PCIe TLP Backend
// Configurable for different FPGA implementations

// FPGA Configuration - MODIFY THESE FOR YOUR FPGA BOARD
#define FPGA_DEVICE "/dev/mem"  // Use /dev/mem for direct BAR access
#define FPGA_BAR_ADDR 0xC0000000  // Base address of FPGA BAR - CHANGE THIS
#define FPGA_BAR_SIZE (4 * 1024 * 1024)  // 4MB BAR size - CHANGE IF NEEDED

// FPGA Register Offsets - MODIFY THESE BASED ON YOUR FPGA DESIGN
#define FPGA_REG_TLP_SEND     0x0000  // Write TLP data here to send
#define FPGA_REG_TLP_STATUS   0x0004  // Read status: bit 0 = ready, bit 1 = data available
#define FPGA_REG_TLP_RECV     0x0008  // Read received TLP data
#define FPGA_REG_CONTROL      0x000C  // Control register: bit 0 = reset, bit 1 = enable

// Status register bits
#define STATUS_READY          (1 << 0)
#define STATUS_DATA_AVAIL     (1 << 1)

// Control register bits
#define CTRL_RESET            (1 << 0)
#define CTRL_ENABLE           (1 << 1)

static int fpga_fd = -1;
static volatile uint32_t *fpga_regs = NULL;

static inline void fpga_write_reg(uint32_t offset, uint32_t value) {
    if (fpga_regs && offset < FPGA_BAR_SIZE) {
        fpga_regs[offset / 4] = value;
    }
}

static inline uint32_t fpga_read_reg(uint32_t offset) {
    return (fpga_regs && offset < FPGA_BAR_SIZE) ? fpga_regs[offset / 4] : 0;
}

static int fpga_wait_ready(void) {
    // Wait for FPGA to be ready (timeout after 1 second)
    for (int i = 0; i < 1000000; i++) {
        if (fpga_read_reg(FPGA_REG_TLP_STATUS) & STATUS_READY) {
            return 0;
        }
        usleep(1);
    }
    pcie_log(PCIE_LOG_ERROR, "[fpga] Timeout waiting for FPGA ready");
    return -1;
}

static int fpga_send(const pcie_tlp_t *t) {
    if (!fpga_regs) {
        pcie_log(PCIE_LOG_ERROR, "[fpga] FPGA not initialized");
        return -1;
    }

    pcie_log(PCIE_LOG_DEBUG, "[fpga] Sending TLP: type=%d, len=%u, addr=0x%lx",
             t->type, t->length, t->mem.addr);

    // Wait for FPGA to be ready
    if (fpga_wait_ready() != 0) {
        return -1;
    }

    // Pack TLP data into registers (simplified - you may need more registers)
    // This is just an example - modify based on your FPGA's expected format
    uint32_t tlp_word0 = (t->type << 24) | (t->length << 16) | t->requester_id;
    uint32_t tlp_word1 = (uint32_t)(t->mem.addr & 0xFFFFFFFF);
    uint32_t tlp_word2 = (uint32_t)((t->mem.addr >> 32) & 0xFFFFFFFF);
    uint32_t tlp_word3 = t->tag;

    // Write TLP data to FPGA
    fpga_write_reg(FPGA_REG_TLP_SEND, tlp_word0);
    fpga_write_reg(FPGA_REG_TLP_SEND + 4, tlp_word1);
    fpga_write_reg(FPGA_REG_TLP_SEND + 8, tlp_word2);
    fpga_write_reg(FPGA_REG_TLP_SEND + 12, tlp_word3);

    // If there's payload data, write it too
    if (t->length > 0 && t->mem.data) {
        // Write payload data (up to 64 bytes for this example)
        for (int i = 0; i < t->length && i < 64; i += 4) {
            uint32_t data_word = 0;
            memcpy(&data_word, t->mem.data + i, (t->length - i >= 4) ? 4 : (t->length - i));
            fpga_write_reg(FPGA_REG_TLP_SEND + 16 + i, data_word);
        }
    }

    pcie_log(PCIE_LOG_INFO, "[fpga] TLP sent successfully");
    return 0;
}

static int fpga_recv(pcie_tlp_t *t) {
    if (!fpga_regs) {
        pcie_log(PCIE_LOG_ERROR, "[fpga] FPGA not initialized");
        return -1;
    }

    // Check if data is available
    uint32_t status = fpga_read_reg(FPGA_REG_TLP_STATUS);
    if (!(status & STATUS_DATA_AVAIL)) {
        return -1;  // No data available
    }

    // Read TLP data from FPGA (simplified example)
    uint32_t tlp_word0 = fpga_read_reg(FPGA_REG_TLP_RECV);
    uint32_t tlp_word1 = fpga_read_reg(FPGA_REG_TLP_RECV + 4);
    uint32_t tlp_word2 = fpga_read_reg(FPGA_REG_TLP_RECV + 8);
    uint32_t tlp_word3 = fpga_read_reg(FPGA_REG_TLP_RECV + 12);

    // Unpack TLP data
    t->type = (tlp_word0 >> 24) & 0xFF;
    t->length = (tlp_word0 >> 16) & 0xFF;
    t->requester_id = tlp_word0 & 0xFFFF;
    t->mem.addr = ((uint64_t)tlp_word2 << 32) | tlp_word1;
    t->tag = tlp_word3 & 0xFF;

    // If there's payload, read it
    if (t->length > 0) {
        t->mem.data = malloc(t->length);
        if (t->mem.data) {
            for (int i = 0; i < t->length && i < 64; i += 4) {
                uint32_t data_word = fpga_read_reg(FPGA_REG_TLP_RECV + 16 + i);
                int bytes_to_copy = (t->length - i >= 4) ? 4 : (t->length - i);
                memcpy(t->mem.data + i, &data_word, bytes_to_copy);
            }
        }
    }

    pcie_log(PCIE_LOG_DEBUG, "[fpga] Received TLP: type=%d, len=%u, addr=0x%lx",
             t->type, t->length, t->mem.addr);

    return 0;
}

static void fpga_close(void) {
    if (fpga_regs) {
        // Reset FPGA
        fpga_write_reg(FPGA_REG_CONTROL, CTRL_RESET);
        munmap((void *)fpga_regs, FPGA_BAR_SIZE);
        fpga_regs = NULL;
    }
    if (fpga_fd >= 0) {
        close(fpga_fd);
        fpga_fd = -1;
    }
    printf("[fpga] closed\n");
}

static int fpga_init(void) {
    // Open /dev/mem for direct memory access
    fpga_fd = open(FPGA_DEVICE, O_RDWR | O_SYNC);
    if (fpga_fd < 0) {
        pcie_log(PCIE_LOG_ERROR, "[fpga] Failed to open %s: %s",
                 FPGA_DEVICE, strerror(errno));
        return -1;
    }

    // Map FPGA BAR
    fpga_regs = mmap(NULL, FPGA_BAR_SIZE, PROT_READ | PROT_WRITE, MAP_SHARED,
                     fpga_fd, FPGA_BAR_ADDR);
    if (fpga_regs == MAP_FAILED) {
        pcie_log(PCIE_LOG_ERROR, "[fpga] Failed to mmap BAR at 0x%x: %s",
                 FPGA_BAR_ADDR, strerror(errno));
        close(fpga_fd);
        fpga_fd = -1;
        return -1;
    }

    // Initialize FPGA
    fpga_write_reg(FPGA_REG_CONTROL, CTRL_RESET);
    usleep(1000);  // Wait for reset
    fpga_write_reg(FPGA_REG_CONTROL, CTRL_ENABLE);

    // Wait for FPGA to be ready
    if (fpga_wait_ready() != 0) {
        fpga_close();
        return -1;
    }

    pcie_log(PCIE_LOG_INFO, "[fpga] FPGA backend initialized at BAR 0x%x",
             FPGA_BAR_ADDR);
    return 0;
}

const pcie_backend_ops_t *pcie_backend_fpga(void) {
    if (fpga_init() != 0) {
        return NULL;
    }
    return &(pcie_backend_ops_t){
        .send  = fpga_send,
        .recv  = fpga_recv,
        .link_status = NULL,
        .device_info = NULL,
        .close = fpga_close
    };
}
