/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2026 Khadem Ullah
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "pcapcie/pcapcie.h"

int main(int argc, char **argv)
{
    const char *backend = argc > 1 ? argv[1] : "dummy";
    const char *trace_path = argc > 2 ? argv[2] : "tlp_capture.pcap";
    const char *format = argc > 3 ? argv[3] : "pcap";
    pcie_ctx_t *ctx = NULL;
    uint8_t payload[4] = {0x10, 0x20, 0x30, 0x40};
    pcie_tlp_t cfg_write = {0};
    pcie_tlp_t rx_tlp = {0};
    int rc;

    ctx = pcie_open(backend);
    if (!ctx) {
        fprintf(stderr, "Failed to open backend: %s\n", backend);
        return 1;
    }

    cfg_write = pcie_tlp_cfg_write(0x20, 4, payload);
    cfg_write.requester_id = 0x0001;
    cfg_write.tag = 0x0F;

    rc = pcie_send(ctx, &cfg_write);
    if (rc != 0) {
        fprintf(stderr, "Failed to send TLP on backend %s\n", backend);
        pcie_close(ctx);
        return 2;
    }

    rx_tlp = pcie_tlp_cfg_read(0x20);
    rx_tlp.requester_id = 0x0001;
    rx_tlp.tag = 0x10;

    rc = pcie_recv(ctx, &rx_tlp);
    if (rc == 0) {
        printf("Received a TLP from %s: type=%u length=%u addr=0x%lx\n",
               backend,
               rx_tlp.type,
               rx_tlp.length,
               rx_tlp.mem.addr);
    }

    if (strcmp(format, "csv") == 0) {
        if (pcie_trace_write_csv(ctx, trace_path) != 0) {
            fprintf(stderr, "CSV trace export failed for %s\n", trace_path);
            pcie_close(ctx);
            return 3;
        }
    } else {
        if (pcie_trace_write_pcap(ctx, trace_path) != 0) {
            fprintf(stderr, "Trace export failed for %s\n", trace_path);
            pcie_close(ctx);
            return 3;
        }
    }

    printf("Captured %zu TLP(s) in %s (%s format)\n",
           pcie_trace_count(ctx),
           trace_path,
           format);
    pcie_close(ctx);
    return 0;
}
