#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "pcapcie/pcapcie.h"

int main(int argc, char *argv[])
{
    const char *backend = argc > 1 ? argv[1] : "pci";
    const char *trace_path = argc > 2 ? argv[2] : NULL;
    const char *trace_format = argc > 3 ? argv[3] : "csv";

    if (argc < 2) {
        fprintf(stderr, "Usage: %s <backend> [trace_file] [format]\n", argv[0]);
        fprintf(stderr, "Backends: dummy, pci\n");
        fprintf(stderr, "Example: %s pci /tmp/pcie_trace.csv csv\n", argv[0]);
        return 1;
    }

    printf("Testing PCIe TLP with backend: %s\n", backend);

    pcie_ctx_t *ctx = pcie_open(backend);
    if (!ctx) {
        fprintf(stderr, "Failed to open backend '%s'\n", backend);
        return 1;
    }

    printf("Backend opened successfully!\n");

    // Send CfgWr0 TLP: 44 00 00 01 00 00 00 0F 01 00 00 18 01 02 FF 00
    uint8_t cfgwr_data[4] = {0x01, 0x02, 0xFF, 0x00};
    pcie_tlp_t cfgwr = pcie_tlp_cfg_write(0x18, 4, cfgwr_data);
    cfgwr.requester_id = 0x0001;
    cfgwr.tag = 0x0F;

    printf("Sending CfgWr0 TLP: addr=0x%lx, data=0x%02x%02x%02x%02x\n",
           cfgwr.mem.addr, cfgwr_data[0], cfgwr_data[1], cfgwr_data[2], cfgwr_data[3]);

    int result = pcie_send(ctx, &cfgwr);
    printf("CfgWr0 result: %d\n", result);

    // Send CfgRd1 TLP: 05 00 00 01 00 00 00 0F 02 00 00 00
    pcie_tlp_t cfgrd = pcie_tlp_cfg_read(0x00);
    cfgrd.requester_id = 0x0001;
    cfgrd.tag = 0x0F;
    cfgrd.mem.addr = 0x02;  // Extended register number

    printf("Sending CfgRd1 TLP: addr=0x%lx\n", cfgrd.mem.addr);

    result = pcie_send(ctx, &cfgrd);
    printf("CfgRd1 result: %d\n", result);

    // Send a series of config reads similar to PCI enumeration
    // Enumeration output interpretation:
    // 0x00: ec 10 68 81   -> vendor/device ID = 0x10ec:0x8168 (Realtek)
    // 0x04: 07 04 10 00   -> command/status = 0x0407 / 0x0010
    // 0x08: 15 00 00 02   -> revision ID = 0x15, class = 0x020000 (Ethernet controller)
    // 0x0c: 10 00 00 00   -> header type etc.
    // 0x10: 01 30 00 00   -> BAR0 = 0x00003001
    // 0x14: 00 00 00 00   -> BAR1 empty
    // 0x18: 04 40 00 74   -> BAR2 value
    // 0x1c: 00 00 00 00   -> BAR3 empty
    uint64_t enum_addrs[] = {0x00, 0x04, 0x08, 0x0c, 0x10, 0x14, 0x18, 0x1c};
    const size_t enum_count = sizeof(enum_addrs) / sizeof(enum_addrs[0]);

    for (size_t i = 0; i < enum_count; ++i) {
        pcie_tlp_t enum_rd = pcie_tlp_cfg_read(enum_addrs[i]);
        enum_rd.requester_id = 0x0001;
        enum_rd.tag = 0x0F;

        printf("Sending enumeration CfgRd TLP: addr=0x%lx\n", enum_addrs[i]);
        result = pcie_send(ctx, &enum_rd);
        printf("  Result: %d\n", result);
    }

    if (trace_path) {
        int rc = 0;
        if (strcmp(trace_format, "pcap") == 0) {
            rc = pcie_trace_write_pcap(ctx, trace_path);
        } else {
            rc = pcie_trace_write_csv(ctx, trace_path);
        }

        if (rc != 0) {
            fprintf(stderr, "Failed to write PCIe trace to %s (%s format)\n",
                    trace_path,
                    trace_format);
            pcie_close(ctx);
            return 3;
        }

        printf("PCIe trace written to %s (%s format)\n", trace_path, trace_format);
    }

    pcie_close(ctx);
    printf("Test completed.\n");
    return 0;
}