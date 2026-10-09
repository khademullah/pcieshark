/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2026 Khadem Ullah
 */

#include <stdio.h>
#include <stdlib.h>
#include "pcapcie/pcapcie.h"

int main(int argc, char **argv)
{
    const char *backend = argc > 1 ? argv[1] : "pci";
    pcie_ctx_t *ctx = pcie_open(backend);
    if (!ctx) {
        fprintf(stderr, "Failed to open backend: %s\n", backend);
        return 1;
    }

    pcie_link_status_t link = {0};
    if (pcie_get_link_status(ctx, &link) != 0) {
        fprintf(stderr, "Failed to query PCIe link status on %s\n", backend);
        pcie_close(ctx);
        return 2;
    }

    printf("Device: %s\n", backend);
    printf("Max link speed: %s (code=%u)\n",
           pcie_link_speed_name(link.max_link_speed),
           link.max_link_speed);
    printf("Negotiated link speed: %s (code=%u)\n",
           pcie_link_speed_name(link.negotiated_link_speed),
           link.negotiated_link_speed);
    printf("Max link width: %u lanes\n", link.max_link_width);
    printf("Negotiated link width: %u lanes\n", link.negotiated_link_width);
    printf("Max PCIe generation: %s\n", pcie_gen_name(link.max_gen));
    printf("Negotiated PCIe generation: %s\n", pcie_gen_name(link.negotiated_gen));

    pcie_close(ctx);
    return 0;
}
