/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2026 Khadem Ullah
 */

#pragma once
#include "tlp.h"
#include "filter.h"
#include "backend.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct pcie_ctx pcie_ctx_t;

typedef void (*pcie_cb_t)(pcie_tlp_t *t, void *user);

typedef enum {
    PCIE_GEN_UNKNOWN = 0,
    PCIE_GEN_1 = 1,
    PCIE_GEN_2 = 2,
    PCIE_GEN_3 = 3,
    PCIE_GEN_4 = 4,
    PCIE_GEN_5 = 5,
    PCIE_GEN_6 = 6,
    PCIE_GEN_7 = 7,
    PCIE_GEN_8 = 8
} pcie_gen_t;

typedef enum {
    PCIE_LINK_SPEED_UNKNOWN = 0,
    PCIE_LINK_SPEED_2_5_GT_S = 1,
    PCIE_LINK_SPEED_5_0_GT_S = 2,
    PCIE_LINK_SPEED_8_0_GT_S = 3,
    PCIE_LINK_SPEED_16_0_GT_S = 4,
    PCIE_LINK_SPEED_32_0_GT_S = 5,
    PCIE_LINK_SPEED_64_0_GT_S = 6,
    PCIE_LINK_SPEED_128_0_GT_S = 7,
    PCIE_LINK_SPEED_256_0_GT_S = 8
} pcie_link_speed_t;

struct pcie_link_status {
    pcie_link_speed_t max_link_speed;
    pcie_link_speed_t negotiated_link_speed;
    uint8_t max_link_width;
    uint8_t negotiated_link_width;
    pcie_gen_t max_gen;
    pcie_gen_t negotiated_gen;
};
typedef struct pcie_link_status pcie_link_status_t;

struct pcie_device_info {
    uint16_t vendor_id;
    uint16_t device_id;
    uint16_t class_code;
    uint8_t revision_id;
    uint8_t has_pcie_capability;
};
typedef struct pcie_device_info pcie_device_info_t;

pcie_ctx_t *pcie_open(const char *backend_name);
void pcie_close(pcie_ctx_t *ctx);

int pcie_send(pcie_ctx_t *ctx, const pcie_tlp_t *t);
int pcie_recv(pcie_ctx_t *ctx, pcie_tlp_t *t);
int pcie_get_link_status(pcie_ctx_t *ctx, pcie_link_status_t *status);
int pcie_get_device_info(pcie_ctx_t *ctx, pcie_device_info_t *info);
int pcie_check_link_target(pcie_ctx_t *ctx,
                          pcie_gen_t min_gen,
                          uint8_t min_width,
                          int *pass);

int pcie_sniff(pcie_ctx_t *ctx,
               pcie_filter_t filter,
               pcie_cb_t cb,
               void *user);

void pcie_loop(pcie_ctx_t *ctx);

typedef struct {
    unsigned long sent;
    unsigned long received;
} pcie_stats_t;

typedef enum {
    PCIE_TRACE_TX = 1,
    PCIE_TRACE_RX = 2
} pcie_trace_direction_t;

typedef struct {
    uint64_t timestamp_ns;
    pcie_trace_direction_t direction;
    uint8_t type;
    uint16_t requester_id;
    uint16_t completer_id;
    uint8_t tag;
    uint16_t length;
    uint64_t addr;
    uint8_t payload[256];
} pcie_trace_record_t;

int pcie_trace_reset(pcie_ctx_t *ctx);
size_t pcie_trace_count(const pcie_ctx_t *ctx);
int pcie_trace_append(pcie_ctx_t *ctx, const pcie_tlp_t *t, pcie_trace_direction_t direction);
int pcie_trace_write_pcap(pcie_ctx_t *ctx, const char *path);
int pcie_trace_write_csv(pcie_ctx_t *ctx, const char *path);

typedef enum {
    PCIE_LOG_INFO,
    PCIE_LOG_WARN,
    PCIE_LOG_ERROR,
    PCIE_LOG_DEBUG
} pcie_log_level_t;

void pcie_log(pcie_log_level_t lvl, const char *fmt, ...);
const char *pcie_gen_name(pcie_gen_t gen);
const char *pcie_link_speed_name(pcie_link_speed_t speed);
pcie_gen_t pcie_gen_from_speed_code(uint8_t speed_code);
pcie_link_speed_t pcie_link_speed_from_code(uint8_t speed_code);

const pcie_stats_t *pcie_stats(pcie_ctx_t *ctx);

uint64_t pcie_rx_addr_min(pcie_ctx_t *ctx);
uint64_t pcie_rx_addr_max(pcie_ctx_t *ctx);

#ifdef __cplusplus
}
#endif
