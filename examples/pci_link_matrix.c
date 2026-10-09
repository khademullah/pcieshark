/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2026 Khadem Ullah
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "pcapcie/pcapcie.h"

typedef struct {
    const char *label;
    pcie_gen_t gen;
    uint8_t width;
} link_case_t;

static void print_case_result(const link_case_t *tc, int pass, const char *fmt, int *first)
{
    if (strcmp(fmt, "json") == 0) {
        if (!*first) {
            printf(",\n");
        }
        printf("  {\"case\":\"%s\",\"target_gen\":\"%s\",\"target_width\":%u,\"pass\":%s}",
               tc->label,
               pcie_gen_name(tc->gen),
               tc->width,
               pass ? "true" : "false");
        *first = 0;
        return;
    }

    if (strcmp(fmt, "csv") == 0) {
        printf("%s,%s,%u,%s\n",
               tc->label,
               pcie_gen_name(tc->gen),
               tc->width,
               pass ? "PASS" : "FAIL");
        return;
    }

    printf("[%s] %s: gen>=%s width>=%u lanes -> %s\n",
           tc->label,
           tc->label,
           pcie_gen_name(tc->gen),
           tc->width,
           pass ? "PASS" : "FAIL");
}

int main(int argc, char **argv)
{
    const char *backend = argc > 1 ? argv[1] : "pci";
    const char *fmt = "text";
    const char *profile = NULL;
    const link_case_t cases[] = {
        { "Gen5x1", PCIE_GEN_5, 1 },
        { "Gen6x4", PCIE_GEN_6, 4 },
        { "Gen7x8", PCIE_GEN_7, 8 },
        { "Gen8x16", PCIE_GEN_8, 16 }
    };

    if (argc > 2) {
        if (strcmp(argv[2], "text") == 0 ||
            strcmp(argv[2], "json") == 0 ||
            strcmp(argv[2], "csv") == 0) {
            fmt = argv[2];
        } else {
            profile = argv[2];
            if (argc > 3) {
                fmt = argv[3];
            }
        }
    }

    if (profile && strcmp(backend, "dummy") == 0) {
        setenv("PCIE_DUMMY_PROFILE", profile, 1);
    }

    pcie_ctx_t *ctx = pcie_open(backend);
    if (!ctx) {
        fprintf(stderr, "Failed to open backend: %s\n", backend);
        return 1;
    }

    pcie_device_info_t info = {0};
    pcie_link_status_t status = {0};
    int all_pass = 1;
    int first_result = 1;

    if (strcmp(fmt, "json") == 0) {
        printf("{\n  \"backend\":\"%s\"",
               backend);
        if (profile) {
            printf(",\n  \"profile\":\"%s\"", profile);
        }
        printf(",\n  \"results\":[\n");
    } else if (strcmp(fmt, "csv") == 0) {
        printf("case,target_gen,target_width,result\n");
    } else {
        if (profile) {
            printf("Profile: %s\n", profile);
        }

        if (pcie_get_device_info(ctx, &info) == 0) {
            printf("Device: vendor=0x%04x device=0x%04x class=0x%06x rev=0x%02x pcie_cap=%s\n",
                   info.vendor_id,
                   info.device_id,
                   info.class_code,
                   info.revision_id,
                   info.has_pcie_capability ? "yes" : "no");
        }

        if (pcie_get_link_status(ctx, &status) == 0) {
            printf("Link summary: max=%s/%u lanes, negotiated=%s/%u lanes, gen=%s\n",
                   pcie_link_speed_name(status.max_link_speed),
                   status.max_link_width,
                   pcie_link_speed_name(status.negotiated_link_speed),
                   status.negotiated_link_width,
                   pcie_gen_name(status.negotiated_gen));
        }

        printf("Compliance matrix:\n");
    }

    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
        int pass = 0;
        int rc = pcie_check_link_target(ctx, cases[i].gen, cases[i].width, &pass);
        if (rc != 0) {
            print_case_result(&cases[i], 0, fmt, &first_result);
            all_pass = 0;
            continue;
        }
        print_case_result(&cases[i], pass, fmt, &first_result);
        if (!pass) {
            all_pass = 0;
        }
    }

    if (strcmp(fmt, "json") == 0) {
        printf("  ],\n  \"overall\":\"%s\"\n}\n", all_pass ? "PASS" : "FAIL");
    } else if (strcmp(fmt, "csv") == 0) {
        printf("Overall,%s\n", all_pass ? "PASS" : "FAIL");
    } else {
        printf("Overall: %s\n", all_pass ? "PASS" : "FAIL");
    }

    pcie_close(ctx);
    return all_pass ? 0 : 3;
}
