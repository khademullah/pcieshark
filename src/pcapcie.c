#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "pcapcie/pcapcie.h"
#include "pcapcie/backend.h"
#include <stdarg.h>
#include <time.h>

struct sniff_entry {
    pcie_filter_t filter;
    pcie_cb_t cb;
    void *user;
};

struct pcie_ctx {
    const pcie_backend_ops_t *backend;
    struct sniff_entry sniffers[8];
    int sniffer_count;
    uint64_t rx_addr_min;
    uint64_t rx_addr_max;

    pcie_trace_record_t *trace_records;
    size_t trace_count;
    size_t trace_capacity;

    pcie_stats_t stats;
};

static void pcie_trace_record(pcie_ctx_t *ctx, const pcie_tlp_t *t, pcie_trace_direction_t direction)
{
    pcie_trace_record_t *entry = NULL;
    size_t new_capacity;
    struct timespec ts;

    if (!ctx || !t) {
        return;
    }

    clock_gettime(CLOCK_REALTIME, &ts);

    if (ctx->trace_count == ctx->trace_capacity) {
        new_capacity = ctx->trace_capacity == 0 ? 16 : ctx->trace_capacity * 2;
        entry = realloc(ctx->trace_records, new_capacity * sizeof(*entry));
        if (!entry) {
            pcie_log(PCIE_LOG_WARN, "[trace] Failed to grow TLP trace buffer");
            return;
        }
        ctx->trace_records = entry;
        ctx->trace_capacity = new_capacity;
    }

    entry = &ctx->trace_records[ctx->trace_count++];
    memset(entry, 0, sizeof(*entry));
    entry->timestamp_ns = ((uint64_t)ts.tv_sec * 1000000000ULL) + (uint64_t)ts.tv_nsec;
    entry->direction = direction;
    entry->type = (uint8_t)t->type;
    entry->requester_id = t->requester_id;
    entry->completer_id = t->completer_id;
    entry->tag = t->tag;
    entry->length = t->length;
    entry->addr = t->mem.addr;

    if (t->mem.data && t->length > 0) {
        size_t payload_len = t->length;
        if (payload_len > sizeof(entry->payload)) {
            payload_len = sizeof(entry->payload);
        }
        memcpy(entry->payload, t->mem.data, payload_len);
    }
}

pcie_ctx_t *pcie_open(const char *backend_name)
{
    pcie_log(PCIE_LOG_INFO,
         "Opening PCIe backend '%s'", backend_name);
    pcie_ctx_t *ctx = calloc(1, sizeof(*ctx));
    if (!ctx) {
        pcie_log(PCIE_LOG_ERROR, "Failed to allocate context");
        return NULL;
    }
    ctx->rx_addr_min = UINT64_MAX;
    ctx->rx_addr_max = 0;

    // Select backend based on name
    if (strcmp(backend_name, "dummy") == 0 || strcmp(backend_name, "golden") == 0 ||
        strcmp(backend_name, "golden-standard") == 0 || strcmp(backend_name, "golden_standard") == 0) {
        ctx->backend = pcie_backend_golden();
    } else if (strcmp(backend_name, "fpga") == 0) {
        ctx->backend = pcie_backend_fpga();
    } else if (strcmp(backend_name, "armds") == 0) {
        ctx->backend = pcie_backend_armds();
    } else if (strcmp(backend_name, "xgig") == 0) {
        ctx->backend = pcie_backend_xgig();
    } else if (strcmp(backend_name, "pci") == 0) {
        ctx->backend = pcie_backend_pci();
    } else {
        pcie_log(PCIE_LOG_ERROR, "Unknown backend '%s'. Supported: golden, dummy, fpga, armds, xgig, pci", backend_name);
        free(ctx);
        return NULL;
    }

    if (!ctx->backend) {
        pcie_log(PCIE_LOG_ERROR, "Failed to initialize backend '%s'", backend_name);
        free(ctx);
        return NULL;
    }

    return ctx;
}

void pcie_close(pcie_ctx_t *ctx)
{
    pcie_log(PCIE_LOG_INFO,
         "Closing PCIe backend");
    if (ctx) {
        free(ctx->trace_records);
    }
    ctx->backend->close();
    free(ctx);
}

int pcie_trace_reset(pcie_ctx_t *ctx)
{
    if (!ctx) {
        return -1;
    }

    ctx->trace_count = 0;
    return 0;
}

size_t pcie_trace_count(const pcie_ctx_t *ctx)
{
    if (!ctx) {
        return 0;
    }
    return ctx->trace_count;
}

int pcie_trace_append(pcie_ctx_t *ctx, const pcie_tlp_t *t, pcie_trace_direction_t direction)
{
    if (!ctx || !t) {
        return -1;
    }
    pcie_trace_record(ctx, t, direction);
    return 0;
}

int pcie_trace_write_pcap(pcie_ctx_t *ctx, const char *path)
{
    FILE *fp;
    uint32_t magic_number = 0xa1b2c3d4U;
    uint32_t version_major = 2;
    uint32_t version_minor = 4;
    uint32_t thiszone = 0;
    uint32_t sigfigs = 0;
    uint32_t snaplen = 65535;
    uint32_t network = 1;

    if (!ctx || !path) {
        return -1;
    }

    fp = fopen(path, "wb");
    if (!fp) {
        pcie_log(PCIE_LOG_ERROR, "[trace] Unable to open capture file '%s' for writing", path);
        return -1;
    }

    fwrite(&magic_number, sizeof(magic_number), 1, fp);
    fwrite(&version_major, sizeof(version_major), 1, fp);
    fwrite(&version_minor, sizeof(version_minor), 1, fp);
    fwrite(&thiszone, sizeof(thiszone), 1, fp);
    fwrite(&sigfigs, sizeof(sigfigs), 1, fp);
    fwrite(&snaplen, sizeof(snaplen), 1, fp);
    fwrite(&network, sizeof(network), 1, fp);

    for (size_t i = 0; i < ctx->trace_count; ++i) {
        const pcie_trace_record_t *rec = &ctx->trace_records[i];
        uint32_t ts_sec = (uint32_t)(rec->timestamp_ns / 1000000000ULL);
        uint32_t ts_usec = (uint32_t)((rec->timestamp_ns % 1000000000ULL) / 1000ULL);
        uint32_t incl_len = (uint32_t)(sizeof(uint8_t) * 2 + sizeof(uint16_t) * 3 + sizeof(uint64_t) + sizeof(rec->payload));
        uint32_t orig_len = incl_len;

        fwrite(&ts_sec, sizeof(ts_sec), 1, fp);
        fwrite(&ts_usec, sizeof(ts_usec), 1, fp);
        fwrite(&incl_len, sizeof(incl_len), 1, fp);
        fwrite(&orig_len, sizeof(orig_len), 1, fp);

        fwrite(&rec->direction, sizeof(rec->direction), 1, fp);
        fwrite(&rec->type, sizeof(rec->type), 1, fp);
        fwrite(&rec->requester_id, sizeof(rec->requester_id), 1, fp);
        fwrite(&rec->completer_id, sizeof(rec->completer_id), 1, fp);
        fwrite(&rec->tag, sizeof(rec->tag), 1, fp);
        fwrite(&rec->length, sizeof(rec->length), 1, fp);
        fwrite(&rec->addr, sizeof(rec->addr), 1, fp);
        fwrite(rec->payload, sizeof(rec->payload), 1, fp);
    }

    fclose(fp);
    pcie_log(PCIE_LOG_INFO, "[trace] Wrote %zu TLP records to '%s'", ctx->trace_count, path);
    return 0;
}

int pcie_trace_write_csv(pcie_ctx_t *ctx, const char *path)
{
    FILE *fp;
    if (!ctx || !path) {
        return -1;
    }

    fp = fopen(path, "w");
    if (!fp) {
        pcie_log(PCIE_LOG_ERROR, "[trace] Unable to open CSV file '%s' for writing", path);
        return -1;
    }

    fprintf(fp,
            "timestamp_ns,direction,type,requester_id,completer_id,tag,length,addr,payload\n");

    for (size_t i = 0; i < ctx->trace_count; ++i) {
        const pcie_trace_record_t *rec = &ctx->trace_records[i];
        static const char *direction_name[] = { "", "TX", "RX" };
        char payload_hex[sizeof(rec->payload) * 3 + 1];
        size_t payload_len = 0;

        payload_hex[0] = '\0';
        size_t nbytes = rec->length < sizeof(rec->payload) ? rec->length : sizeof(rec->payload);
        if (nbytes == 0) {
            nbytes = sizeof(rec->payload);
            while (nbytes > 0 && rec->payload[nbytes - 1] == 0) {
                --nbytes;
            }
        }
        for (size_t j = 0; j < nbytes; ++j) {
            payload_len += (size_t)snprintf(payload_hex + payload_len,
                                           sizeof(payload_hex) - payload_len,
                                           "%02x",
                                           rec->payload[j]);
        }

        fprintf(fp,
                "%llu,%s,%u,%u,%u,%u,%u,0x%llx,%s\n",
                (unsigned long long)rec->timestamp_ns,
                direction_name[rec->direction > 0 && rec->direction < 3 ? rec->direction : 0],
                rec->type,
                rec->requester_id,
                rec->completer_id,
                rec->tag,
                rec->length,
                (unsigned long long)rec->addr,
                payload_hex);
    }

    fclose(fp);
    pcie_log(PCIE_LOG_INFO, "[trace] Wrote %zu TLP records to '%s' in CSV format", ctx->trace_count, path);
    return 0;
}

int pcie_send(pcie_ctx_t *ctx, const pcie_tlp_t *t)
{
    int rc;

    ctx->stats.sent++;

    printf("pcie_send: ctx=%p, t=%p, backend=%p\n", (void*)ctx, (void*)t, (void*)ctx->backend);
    if (ctx->backend && ctx->backend->send) {
        printf("pcie_send: calling backend send function at %p\n", (void*)ctx->backend->send);
        rc = ctx->backend->send(t);
        if (rc == 0 && t) {
            pcie_trace_record(ctx, t, PCIE_TRACE_TX);
        }
        return rc;
    } else {
        printf("pcie_send: ERROR - backend or send function is NULL\n");
        return -1;
    }
}

int pcie_recv(pcie_ctx_t *ctx, pcie_tlp_t *t)
{
    int result = ctx->backend->recv(t);
    if (result == 0) {
        ctx->stats.received++;
        pcie_trace_record(ctx, t, PCIE_TRACE_RX);
    }
    return result;
}

int pcie_sniff(pcie_ctx_t *ctx,
               pcie_filter_t filter,
               pcie_cb_t cb,
               void *user)
{
    int i = ctx->sniffer_count++;
    ctx->sniffers[i].filter = filter;
    ctx->sniffers[i].cb = cb;
    ctx->sniffers[i].user = user;
    return 0;
}

void pcie_loop(pcie_ctx_t *ctx)
{
    pcie_tlp_t t;

    while (ctx->backend->recv(&t) == 0) {
        
        ctx->stats.received++;

        if (ctx->stats.received == 1) {
            pcie_log(PCIE_LOG_INFO,
                     "RX started (first TLP type=%d addr=0x%lx)",
                     t.type,
                     t.mem.addr);
        }

        if ((ctx->stats.received % 100) == 0) {
            pcie_log(PCIE_LOG_DEBUG,
                     "RX %lu packets (last addr=0x%lx)",
                     ctx->stats.received,
                     t.mem.addr);
        }

        for (int i = 0; i < ctx->sniffer_count; i++) {
            if (pcie_filter_match(&ctx->sniffers[i].filter, &t)) {
                ctx->sniffers[i].cb(&t,
                                    ctx->sniffers[i].user);
            }
        }
    }

    pcie_log(PCIE_LOG_INFO,
             "RX stopped after %lu packets",
             ctx->stats.received);
}

int pcie_get_link_status(pcie_ctx_t *ctx, pcie_link_status_t *status)
{
    if (!ctx || !status) {
        return -1;
    }

    memset(status, 0, sizeof(*status));
    if (!ctx->backend || !ctx->backend->link_status) {
        pcie_log(PCIE_LOG_WARN,
                 "Backend '%s' does not expose PCIe link status",
                 ctx->backend ? "configured" : "uninitialized");
        return -1;
    }

    return ctx->backend->link_status(status);
}

int pcie_get_device_info(pcie_ctx_t *ctx, pcie_device_info_t *info)
{
    if (!ctx || !info) {
        return -1;
    }

    memset(info, 0, sizeof(*info));
    if (!ctx->backend || !ctx->backend->device_info) {
        pcie_log(PCIE_LOG_WARN,
                 "Backend '%s' does not expose device info",
                 ctx->backend ? "configured" : "uninitialized");
        return -1;
    }

    return ctx->backend->device_info(info);
}

int pcie_check_link_target(pcie_ctx_t *ctx,
                          pcie_gen_t min_gen,
                          uint8_t min_width,
                          int *pass)
{
    pcie_link_status_t status = {0};

    if (!ctx || !pass) {
        return -1;
    }

    *pass = 0;
    if (pcie_get_link_status(ctx, &status) != 0) {
        return -1;
    }

    if (min_gen != PCIE_GEN_UNKNOWN && status.negotiated_gen != PCIE_GEN_UNKNOWN) {
        if (status.negotiated_gen < min_gen) {
            return 0;
        }
    }

    if (min_width > 0 && status.negotiated_link_width < min_width) {
        return 0;
    }

    *pass = 1;
    return 0;
}

const pcie_stats_t *pcie_stats(pcie_ctx_t *ctx)
{
    return &ctx->stats;
}

const char *pcie_gen_name(pcie_gen_t gen)
{
    switch (gen) {
        case PCIE_GEN_1: return "PCIe Gen 1";
        case PCIE_GEN_2: return "PCIe Gen 2";
        case PCIE_GEN_3: return "PCIe Gen 3";
        case PCIE_GEN_4: return "PCIe Gen 4";
        case PCIE_GEN_5: return "PCIe Gen 5";
        case PCIE_GEN_6: return "PCIe Gen 6";
        case PCIE_GEN_7: return "PCIe Gen 7";
        case PCIE_GEN_8: return "PCIe Gen 8";
        default: return "Unknown";
    }
}

const char *pcie_link_speed_name(pcie_link_speed_t speed)
{
    switch (speed) {
        case PCIE_LINK_SPEED_2_5_GT_S: return "2.5 GT/s";
        case PCIE_LINK_SPEED_5_0_GT_S: return "5.0 GT/s";
        case PCIE_LINK_SPEED_8_0_GT_S: return "8.0 GT/s";
        case PCIE_LINK_SPEED_16_0_GT_S: return "16.0 GT/s";
        case PCIE_LINK_SPEED_32_0_GT_S: return "32.0 GT/s";
        case PCIE_LINK_SPEED_64_0_GT_S: return "64.0 GT/s";
        case PCIE_LINK_SPEED_128_0_GT_S: return "128.0 GT/s";
        case PCIE_LINK_SPEED_256_0_GT_S: return "256.0 GT/s";
        default: return "Unknown";
    }
}

pcie_gen_t pcie_gen_from_speed_code(uint8_t speed_code)
{
    switch (speed_code) {
        case 1: return PCIE_GEN_1;
        case 2: return PCIE_GEN_2;
        case 3: return PCIE_GEN_3;
        case 4: return PCIE_GEN_4;
        case 5: return PCIE_GEN_5;
        case 6: return PCIE_GEN_6;
        case 7: return PCIE_GEN_7;
        case 8: return PCIE_GEN_8;
        default: return PCIE_GEN_UNKNOWN;
    }
}

pcie_link_speed_t pcie_link_speed_from_code(uint8_t speed_code)
{
    switch (speed_code) {
        case 1: return PCIE_LINK_SPEED_2_5_GT_S;
        case 2: return PCIE_LINK_SPEED_5_0_GT_S;
        case 3: return PCIE_LINK_SPEED_8_0_GT_S;
        case 4: return PCIE_LINK_SPEED_16_0_GT_S;
        case 5: return PCIE_LINK_SPEED_32_0_GT_S;
        case 6: return PCIE_LINK_SPEED_64_0_GT_S;
        case 7: return PCIE_LINK_SPEED_128_0_GT_S;
        case 8: return PCIE_LINK_SPEED_256_0_GT_S;
        default: return PCIE_LINK_SPEED_UNKNOWN;
    }
}

void pcie_log(pcie_log_level_t lvl, const char *fmt, ...)
{
    static const char *lvl_str[] = {
        "INFO", "WARN", "ERR", "DBG"
    };

    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);

    fprintf(stderr, "[%ld.%06ld] %-4s ",
            ts.tv_sec,
            ts.tv_nsec / 1000,
            lvl_str[lvl]);

    va_list ap;
    va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    va_end(ap);

    fprintf(stderr, "\n");
}


uint64_t pcie_rx_addr_min(pcie_ctx_t *ctx)
{
    return ctx->rx_addr_min;
}

uint64_t pcie_rx_addr_max(pcie_ctx_t *ctx)
{
    return ctx->rx_addr_max;
}
