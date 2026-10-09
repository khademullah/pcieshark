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
    int expected_gen = argc > 2 ? atoi(argv[2]) : 5;
    int expected_width = argc > 3 ? atoi(argv[3]) : 1;
    int pass = 0;

    pcie_ctx_t *ctx = pcie_open(backend);
    if (!ctx) {
        fprintf(stderr, "Failed to open backend: %s\n", backend);
        return 1;
    }

    if (pcie_check_link_target(ctx,
                               (pcie_gen_t)expected_gen,
                               (uint8_t)expected_width,
                               &pass) != 0) {
        fprintf(stderr, "Link check failed: backend could not read link status\n");
        pcie_close(ctx);
        return 2;
    }

    printf("Expected PCIe Gen %d, width %d\n", expected_gen, expected_width);
    if (pass) {
        printf("RESULT: PASS\n");
        pcie_close(ctx);
        return 0;
    }

    printf("RESULT: FAIL\n");
    pcie_close(ctx);
    return 3;
}
