#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>

#define MAX_LINE 4096

static const char *pcie_type_name(const char *type)
{
    if (!type) {
        return "UNKNOWN";
    }
    if (strcmp(type, "0") == 0 || strcasecmp(type, "MemRd") == 0 || strcasecmp(type, "MemRead") == 0) return "MemRd";
    if (strcmp(type, "1") == 0 || strcasecmp(type, "MemWr") == 0 || strcasecmp(type, "MemWrite") == 0) return "MemWr";
    if (strcmp(type, "4") == 0 || strcasecmp(type, "CfgRd") == 0 || strcasecmp(type, "CfgRead") == 0) return "CfgRd";
    if (strcmp(type, "5") == 0 || strcasecmp(type, "CfgWr") == 0 || strcasecmp(type, "CfgWrite") == 0) return "CfgWr";
    if (strcmp(type, "10") == 0 || strcasecmp(type, "Cpl") == 0 || strcasecmp(type, "CplD") == 0
        || strcasecmp(type, "Completion") == 0) return "Cpl";
    return "Other";
}

static void print_packet_list(FILE *fp, const char *path)
{
    char line[MAX_LINE];
    int row = 0;

    printf("PCIe trace: %s\n", path);
    printf("No.  Time(ns)  Direction  Type  ReqID  CplID  Tag  Len  Addr  Payload\n");

    while (fgets(line, sizeof(line), fp)) {
        char *ctx = NULL;
        char *timestamp = strtok_r(line, ",", &ctx);
        char *direction = strtok_r(NULL, ",", &ctx);
        char *type = strtok_r(NULL, ",", &ctx);
        char *requester = strtok_r(NULL, ",", &ctx);
        char *completer = strtok_r(NULL, ",", &ctx);
        char *tag = strtok_r(NULL, ",", &ctx);
        char *length = strtok_r(NULL, ",", &ctx);
        char *addr = strtok_r(NULL, ",", &ctx);
        char *payload = strtok_r(NULL, "\n", &ctx);

        if (!direction || !type || !timestamp) {
            continue;
        }
        if (strncmp(timestamp, "timestamp", 9) == 0) {
            continue;
        }

        printf("%d    %-15s %-9s %-6s %-6s %-5s %-4s %-4s %-8s %s\n",
               ++row,
               timestamp,
               direction,
               pcie_type_name(type),
               requester ? requester : "0",
               completer ? completer : "0",
               tag ? tag : "0",
               length ? length : "0",
               addr ? addr : "0",
               payload ? payload : "-");
    }
}

static void print_summary(FILE *fp, const char *path)
{
    char line[MAX_LINE];
    unsigned long total = 0;
    unsigned long tx_count = 0;
    unsigned long rx_count = 0;
    unsigned long cfg_read = 0;
    unsigned long cfg_write = 0;
    unsigned long mem_read = 0;
    unsigned long mem_write = 0;
    unsigned long cpl = 0;

    while (fgets(line, sizeof(line), fp)) {
        char *ctx = NULL;
        char *timestamp = strtok_r(line, ",", &ctx);
        char *direction = strtok_r(NULL, ",", &ctx);
        char *type = strtok_r(NULL, ",", &ctx);
        char *requester = strtok_r(NULL, ",", &ctx);
        char *completer = strtok_r(NULL, ",", &ctx);
        char *tag = strtok_r(NULL, ",", &ctx);
        char *length = strtok_r(NULL, ",", &ctx);
        char *addr = strtok_r(NULL, ",", &ctx);
        char *payload = strtok_r(NULL, "\n", &ctx);

        (void)timestamp; (void)requester; (void)completer; (void)tag;
        (void)length; (void)addr; (void)payload;

        if (!direction || !type || !timestamp) {
            continue;
        }
        if (strncmp(timestamp, "timestamp", 9) == 0) {
            continue;
        }

        total++;
        if (strcmp(direction, "TX") == 0) {
            tx_count++;
        } else if (strcmp(direction, "RX") == 0) {
            rx_count++;
        }

        const char *named = pcie_type_name(type);
        if (strcmp(named, "CfgWr") == 0) {
            cfg_write++;
        } else if (strcmp(named, "CfgRd") == 0) {
            cfg_read++;
        } else if (strcmp(named, "MemWr") == 0) {
            mem_write++;
        } else if (strcmp(named, "MemRd") == 0) {
            mem_read++;
        } else if (strcmp(named, "Cpl") == 0) {
            cpl++;
        }
    }

    printf("PCIe trace summary for %s\n", path);
    printf("Total TLPs: %lu\n", total);
    printf("TX: %lu\n", tx_count);
    printf("RX: %lu\n", rx_count);
    printf("Config read: %lu\n", cfg_read);
    printf("Config write: %lu\n", cfg_write);
    printf("Memory read: %lu\n", mem_read);
    printf("Memory write: %lu\n", mem_write);
    printf("Completion: %lu\n", cpl);
}

static void print_usage(const char *prog)
{
    fprintf(stderr, "Usage: %s <trace.csv> [--summary]\n", prog);
    fprintf(stderr, "Example: %s /tmp/pcie_trace.csv\n", prog);
}

int main(int argc, char **argv)
{
    FILE *fp = NULL;
    char line[MAX_LINE];
    int summary_only = 0;

    if (argc < 2) {
        print_usage(argv[0]);
        return 1;
    }

    if (argc >= 3 && strcmp(argv[2], "--summary") == 0) {
        summary_only = 1;
    }

    fp = fopen(argv[1], "r");
    if (!fp) {
        fprintf(stderr, "Failed to open trace file: %s\n", argv[1]);
        return 2;
    }

    if (!fgets(line, sizeof(line), fp)) {
        fprintf(stderr, "Trace file is empty\n");
        fclose(fp);
        return 3;
    }

    rewind(fp);

    if (summary_only) {
        print_summary(fp, argv[1]);
    } else {
        print_packet_list(fp, argv[1]);
    }

    fclose(fp);
    return 0;
}
