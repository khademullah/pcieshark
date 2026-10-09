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

// ARM Development Studio PCIe TLP Backend
// Communicates with FPGA through ARM DS network bridge

// Network Configuration - MODIFY FOR ARM DS SETUP
#define ARM_DS_HOST "8.8.8.8"  // ARM DS host (DSTREAM IP)
#define ARM_DS_PORT 12345        // Port for TLP communication
#define FPGA_DEVICE_ID 0x1234    // Your FPGA device ID

// Network protocol for TLP communication with ARM DS
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

static int arm_ds_sock = -1;
static struct sockaddr_in arm_ds_addr;

static int arm_ds_connect(void) {
    if (arm_ds_sock >= 0) return 0; // Already connected

    pcie_log(PCIE_LOG_DEBUG, "[arm_ds] Connecting to %s:%d", ARM_DS_HOST, ARM_DS_PORT);

    arm_ds_sock = socket(AF_INET, SOCK_STREAM, 0);
    if (arm_ds_sock < 0) {
        pcie_log(PCIE_LOG_ERROR, "[arm_ds] Socket creation failed: %s", strerror(errno));
        return -1;
    }

    memset(&arm_ds_addr, 0, sizeof(arm_ds_addr));
    arm_ds_addr.sin_family = AF_INET;
    arm_ds_addr.sin_port = htons(ARM_DS_PORT);

    if (inet_pton(AF_INET, ARM_DS_HOST, &arm_ds_addr.sin_addr) <= 0) {
        pcie_log(PCIE_LOG_ERROR, "[arm_ds] Invalid address: %s", ARM_DS_HOST);
        close(arm_ds_sock);
        arm_ds_sock = -1;
        return -1;
    }

    // Set socket timeout to avoid hanging
    struct timeval tv;
    tv.tv_sec = 5;  // 5 second timeout
    tv.tv_usec = 0;
    setsockopt(arm_ds_sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(arm_ds_sock, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));

    if (connect(arm_ds_sock, (struct sockaddr *)&arm_ds_addr, sizeof(arm_ds_addr)) < 0) {
        pcie_log(PCIE_LOG_ERROR, "[arm_ds] Connection failed: %s", strerror(errno));
        close(arm_ds_sock);
        arm_ds_sock = -1;
        return -1;
    }

    // Send device identification
    uint32_t device_id = FPGA_DEVICE_ID;
    if (send(arm_ds_sock, &device_id, sizeof(device_id), 0) != sizeof(device_id)) {
        pcie_log(PCIE_LOG_ERROR, "[arm_ds] Failed to send device ID");
        close(arm_ds_sock);
        arm_ds_sock = -1;
        return -1;
    }

    pcie_log(PCIE_LOG_INFO, "[arm_ds] Connected to ARM DS at %s:%d", ARM_DS_HOST, ARM_DS_PORT);
    return 0;
}

static int arm_ds_send(const pcie_tlp_t *t) {
    if (arm_ds_connect() != 0) {
        printf("[arm_ds] Failed to connect to ARM DS\n");
        return -1;
    }

    printf("[arm_ds] Sending TLP: type=%d, addr=0x%lx, len=%d\n", t->type, t->mem.addr, t->length);

    // Send TLP header
    if (send(arm_ds_sock, t, sizeof(pcie_tlp_t), 0) != sizeof(pcie_tlp_t)) {
        printf("[arm_ds] Failed to send TLP header\n");
        return -1;
    }

    // Send payload data if present
    if (t->length > 0 && t->mem.data) {
        if (send(arm_ds_sock, t->mem.data, t->length, 0) != (ssize_t)t->length) {
            printf("[arm_ds] Failed to send TLP payload\n");
            return -1;
        }
    }

    printf("[arm_ds] TLP sent successfully\n");
    return 0;
}

static int arm_ds_recv(pcie_tlp_t *t) {
    if (arm_ds_connect() != 0) return -1;

    // Set socket to non-blocking for receive check
    int flags = fcntl(arm_ds_sock, F_GETFL, 0);
    fcntl(arm_ds_sock, F_SETFL, flags | O_NONBLOCK);

    // Try to receive TLP header
    ssize_t received = recv(arm_ds_sock, t, sizeof(pcie_tlp_t), 0);
    if (received == 0) {
        // Connection closed
        pcie_log(PCIE_LOG_INFO, "[arm_ds] ARM DS connection closed");
        close(arm_ds_sock);
        arm_ds_sock = -1;
        return -1;
    } else if (received < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            // No data available
            return -1;
        }
        pcie_log(PCIE_LOG_ERROR, "[arm_ds] Receive error: %s", strerror(errno));
        return -1;
    } else if (received != sizeof(pcie_tlp_t)) {
        pcie_log(PCIE_LOG_ERROR, "[arm_ds] Incomplete TLP header received");
        return -1;
    }

    // Restore blocking mode
    fcntl(arm_ds_sock, F_SETFL, flags);

    // Receive payload data if present
    if (t->length > 0) {
        t->mem.data = malloc(t->length);
        if (!t->mem.data) {
            pcie_log(PCIE_LOG_ERROR, "[arm_ds] Memory allocation failed");
            return -1;
        }

        if (recv(arm_ds_sock, t->mem.data, t->length, MSG_WAITALL) != (ssize_t)t->length) {
            pcie_log(PCIE_LOG_ERROR, "[arm_ds] Failed to receive TLP payload");
            free(t->mem.data);
            t->mem.data = NULL;
            return -1;
        }
    }

    pcie_log(PCIE_LOG_DEBUG, "[arm_ds] Received TLP: type=%d, len=%u, addr=0x%lx",
             t->type, t->length, t->mem.addr);

    return 0;
}

static void arm_ds_close(void) {
    if (arm_ds_sock >= 0) {
        close(arm_ds_sock);
        arm_ds_sock = -1;
    }
    printf("[arm_ds] closed\n");
}

static const pcie_backend_ops_t armds_backend_ops = {
    .send  = arm_ds_send,
    .recv  = arm_ds_recv,
    .link_status = NULL,
    .device_info = NULL,
    .close = arm_ds_close
};

const pcie_backend_ops_t *pcie_backend_armds(void) {
    // This backend connects to ARM Development Studio
    // ARM DS needs to be running a TLP bridge server
    pcie_log(PCIE_LOG_INFO, "[arm_ds] Initializing ARM Development Studio TLP backend");
    return &armds_backend_ops;
}