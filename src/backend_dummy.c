/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2026 Khadem Ullah
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <time.h>
#include "pcapcie/backend.h"
#include "pcapcie/pcapcie.h"

static uint32_t dummy_parse_u32(const char *value, uint32_t def)
{
    char *end = NULL;
    unsigned long v;

    if (!value || !value[0]) {
        return def;
    }

    v = strtoul(value, &end, 0);
    return end && *end == '\0' ? (uint32_t)v : def;
}

static uint64_t dummy_parse_duration_ns(const char *value, uint64_t def)
{
    unsigned long long v = 0;
    char *end = NULL;

    if (!value || !value[0]) {
        return def;
    }

    v = strtoull(value, &end, 10);
    if (end == value) {
        return def;
    }

    if (*end == '\0') {
        return v;
    }

    switch (tolower((unsigned char)*end)) {
        case 'n': return v;
        case 'u': return v * 1000ULL;
        case 'm': return v * 1000000ULL;
        case 's': return v * 1000000000ULL;
        default: return def;
    }
}

static void dummy_trim_whitespace(char *s)
{
    char *start = s;
    char *end;

    if (!s) {
        return;
    }

    while (*start != '\0' && isspace((unsigned char)*start)) {
        start++;
    }

    if (start != s) {
        memmove(s, start, strlen(start) + 1);
    }

    end = s + strlen(s);
    while (end > s && isspace((unsigned char)end[-1])) {
        end--;
    }
    *end = '\0';
}

static void dummy_tolower_copy(char *out, size_t out_size, const char *in)
{
    size_t i = 0;

    if (!out || out_size == 0 || !in) {
        return;
    }

    while (in[i] != '\0' && i + 1 < out_size) {
        out[i] = (char)tolower((unsigned char)in[i]);
        i++;
    }
    out[i] = '\0';
}

static int dummy_profile_from_name(const char *name,
                                  uint32_t *max_speed,
                                  uint32_t *neg_speed,
                                  uint32_t *max_width,
                                  uint32_t *neg_width)
{
    char key[32];
    uint32_t speed = 0;
    uint32_t width = 0;

    if (!name || !max_speed || !neg_speed || !max_width || !neg_width) {
        return -1;
    }

    dummy_tolower_copy(key, sizeof(key), name);
    if (strcmp(key, "gen5x1") == 0 || strcmp(key, "5x1") == 0) {
        speed = 5; width = 1;
    } else if (strcmp(key, "gen6x4") == 0 || strcmp(key, "6x4") == 0) {
        speed = 6; width = 4;
    } else if (strcmp(key, "gen7x8") == 0 || strcmp(key, "7x8") == 0) {
        speed = 7; width = 8;
    } else if (strcmp(key, "gen8x16") == 0 || strcmp(key, "8x16") == 0) {
        speed = 8; width = 16;
    } else if (strcmp(key, "gen8x8") == 0 || strcmp(key, "8x8") == 0) {
        speed = 8; width = 8;
    } else if (sscanf(key, "gen%ux%u", &speed, &width) == 2) {
        /* valid */
    } else if (sscanf(key, "%ux%u", &speed, &width) == 2) {
        /* valid */
    } else {
        return -1;
    }

    if (speed < 1 || speed > 8 || width < 1 || width > 16) {
        return -1;
    }

    *max_speed = speed;
    *neg_speed = speed;
    *max_width = width;
    *neg_width = width;
    return 0;
}

typedef struct {
    uint32_t max_speed;
    uint32_t neg_speed;
    uint32_t max_width;
    uint32_t neg_width;
    uint64_t latency_ns;
    uint64_t jitter_ns;
    uint32_t tokens_per_second;
    uint32_t burst_size;
    double drop_rate;
} dummy_profile_config_t;

static void dummy_apply_scenario_values(const char *scenario,
                                       dummy_profile_config_t *cfg)
{
    char buffer[256];
    char *saveptr = NULL;
    char *part;
    char *eq;
    char *profile_name = NULL;

    if (!cfg || !scenario || !scenario[0]) {
        return;
    }

    snprintf(buffer, sizeof(buffer), "%s", scenario);

    for (part = strtok_r(buffer, ",;", &saveptr); part; part = strtok_r(NULL, ",;", &saveptr)) {
        dummy_trim_whitespace(part);
        if (part[0] == '\0') {
            continue;
        }

        eq = strchr(part, '=');
        if (eq) {
            *eq = '\0';
            char *key = part;
            char *value = eq + 1;
            dummy_trim_whitespace(key);
            dummy_trim_whitespace(value);

            if (strcmp(key, "profile") == 0 || strcmp(key, "name") == 0) {
                profile_name = value;
            } else if (strcmp(key, "latency") == 0 || strcmp(key, "latency_ns") == 0) {
                cfg->latency_ns = dummy_parse_duration_ns(value, cfg->latency_ns);
            } else if (strcmp(key, "jitter") == 0 || strcmp(key, "jitter_ns") == 0) {
                cfg->jitter_ns = dummy_parse_duration_ns(value, cfg->jitter_ns);
            } else if (strcmp(key, "tps") == 0 || strcmp(key, "tokens_per_second") == 0) {
                cfg->tokens_per_second = dummy_parse_u32(value, cfg->tokens_per_second);
            } else if (strcmp(key, "burst") == 0 || strcmp(key, "burst_size") == 0) {
                cfg->burst_size = dummy_parse_u32(value, cfg->burst_size);
            } else if (strcmp(key, "drop_rate") == 0) {
                cfg->drop_rate = strtod(value, NULL);
            }
        } else if (!profile_name) {
            profile_name = part;
        }
    }

    if (profile_name && profile_name[0] != '\0') {
        uint32_t profile_max_speed = cfg->max_speed;
        uint32_t profile_neg_speed = cfg->neg_speed;
        uint32_t profile_max_width = cfg->max_width;
        uint32_t profile_neg_width = cfg->neg_width;

        if (dummy_profile_from_name(profile_name,
                                    &profile_max_speed,
                                    &profile_neg_speed,
                                    &profile_max_width,
                                    &profile_neg_width) == 0) {
            cfg->max_speed = profile_max_speed;
            cfg->neg_speed = profile_neg_speed;
            cfg->max_width = profile_max_width;
            cfg->neg_width = profile_neg_width;
        }
    }
}

static void dummy_read_runtime_config(dummy_profile_config_t *cfg)
{
    const char *profile_name = getenv("PCIE_DUMMY_PROFILE");
    const char *scenario = getenv("PCIE_DUMMY_SCENARIO");

    memset(cfg, 0, sizeof(*cfg));

    cfg->max_speed = dummy_parse_u32(getenv("PCIE_DUMMY_MAX_SPEED"), 5);
    cfg->neg_speed = dummy_parse_u32(getenv("PCIE_DUMMY_NEG_SPEED"), 0);
    cfg->max_width = dummy_parse_u32(getenv("PCIE_DUMMY_MAX_WIDTH"), 16);
    cfg->neg_width = dummy_parse_u32(getenv("PCIE_DUMMY_NEG_WIDTH"), 0);
    cfg->latency_ns = dummy_parse_duration_ns(getenv("PCIE_DUMMY_LATENCY_NS"), 0);
    cfg->jitter_ns = dummy_parse_duration_ns(getenv("PCIE_DUMMY_JITTER_NS"), 0);
    cfg->tokens_per_second = dummy_parse_u32(getenv("PCIE_DUMMY_TOKENS_PER_SEC"), 0);
    cfg->burst_size = dummy_parse_u32(getenv("PCIE_DUMMY_BURST_SIZE"), 16);
    cfg->drop_rate = strtod(getenv("PCIE_DUMMY_DROP_RATE") ? getenv("PCIE_DUMMY_DROP_RATE") : "0", NULL);

    if (profile_name && profile_name[0] != '\0') {
        uint32_t pmax_speed = cfg->max_speed;
        uint32_t pneg_speed = cfg->neg_speed;
        uint32_t pmax_width = cfg->max_width;
        uint32_t pneg_width = cfg->neg_width;

        if (dummy_profile_from_name(profile_name,
                                    &pmax_speed,
                                    &pneg_speed,
                                    &pmax_width,
                                    &pneg_width) == 0) {
            cfg->max_speed = pmax_speed;
            cfg->neg_speed = pneg_speed;
            cfg->max_width = pmax_width;
            cfg->neg_width = pneg_width;
        }
    }

    if (scenario && scenario[0] != '\0') {
        dummy_apply_scenario_values(scenario, cfg);
    }

    if (cfg->neg_speed == 0) {
        cfg->neg_speed = cfg->max_speed;
    }
    if (cfg->neg_width == 0) {
        cfg->neg_width = cfg->max_width;
    }
}

static uint64_t dummy_time_ns(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ((uint64_t)ts.tv_sec * 1000000000ULL) + (uint64_t)ts.tv_nsec;
}

static void dummy_apply_latency(uint64_t latency_ns)
{
    struct timespec ts;

    if (latency_ns == 0) {
        return;
    }

    ts.tv_sec = (time_t)(latency_ns / 1000000000ULL);
    ts.tv_nsec = (long)(latency_ns % 1000000000ULL);
    nanosleep(&ts, NULL);
}

static void dummy_apply_throttle(uint32_t tokens_per_second)
{
    static uint64_t next_tx_ns = 0;
    static uint64_t next_rx_ns = 0;
    uint64_t now = dummy_time_ns();
    uint64_t *next = NULL;

    if (tokens_per_second == 0) {
        return;
    }

    next = &next_tx_ns;
    if (now < *next) {
        uint64_t delay_ns = *next - now;
        dummy_apply_latency(delay_ns);
    }
    *next = now + (1000000000ULL / tokens_per_second);
}

static int dummy_device_info(pcie_device_info_t *info)
{
    uint16_t vendor_id = (uint16_t)dummy_parse_u32(getenv("PCIE_DUMMY_VENDOR_ID"), 0x1AE0);
    uint16_t device_id = (uint16_t)dummy_parse_u32(getenv("PCIE_DUMMY_DEVICE_ID"), 0x0001);
    uint16_t class_code = (uint16_t)dummy_parse_u32(getenv("PCIE_DUMMY_CLASS_CODE"), 0x060400);
    uint8_t rev_id = (uint8_t)dummy_parse_u32(getenv("PCIE_DUMMY_REVISION"), 0x01);

    if (!info) {
        return -1;
    }

    memset(info, 0, sizeof(*info));
    info->vendor_id = vendor_id;
    info->device_id = device_id;
    info->class_code = class_code;
    info->revision_id = rev_id;
    info->has_pcie_capability = 1;

    pcie_log(PCIE_LOG_INFO,
             "[dummy] Device vendor=0x%04x device=0x%04x class=0x%06x rev=0x%02x pcie_cap=yes",
             info->vendor_id,
             info->device_id,
             info->class_code,
             info->revision_id);
    return 0;
}

static int dummy_link_status(pcie_link_status_t *status)
{
    dummy_profile_config_t cfg;
    const char *profile_name = getenv("PCIE_DUMMY_PROFILE");
    const char *scenario = getenv("PCIE_DUMMY_SCENARIO");

    if (!status) {
        return -1;
    }

    dummy_read_runtime_config(&cfg);

    if (profile_name && profile_name[0] != '\0') {
        pcie_log(PCIE_LOG_INFO,
                 "[dummy] Active profile '%s' -> %s/%u lanes",
                 profile_name,
                 pcie_link_speed_name(pcie_link_speed_from_code((uint8_t)cfg.max_speed)),
                 cfg.max_width);
    } else if (scenario && scenario[0] != '\0') {
        pcie_log(PCIE_LOG_INFO,
                 "[dummy] Active scenario '%s' -> %s/%u lanes",
                 scenario,
                 pcie_link_speed_name(pcie_link_speed_from_code((uint8_t)cfg.max_speed)),
                 cfg.max_width);
    }

    memset(status, 0, sizeof(*status));
    status->max_link_speed = pcie_link_speed_from_code((uint8_t)cfg.max_speed);
    status->negotiated_link_speed = pcie_link_speed_from_code((uint8_t)cfg.neg_speed);
    status->max_link_width = (uint8_t)(cfg.max_width > 0 ? cfg.max_width : 1);
    status->negotiated_link_width = (uint8_t)(cfg.neg_width > 0 ? cfg.neg_width : 1);
    status->max_gen = pcie_gen_from_speed_code((uint8_t)cfg.max_speed);
    status->negotiated_gen = pcie_gen_from_speed_code((uint8_t)cfg.neg_speed);

    pcie_log(PCIE_LOG_INFO,
             "[dummy] Link status: max=%s/%u lanes, negotiated=%s/%u lanes, latency=%llu ns, tps=%u, burst=%u",
             pcie_link_speed_name(status->max_link_speed),
             status->max_link_width,
             pcie_link_speed_name(status->negotiated_link_speed),
             status->negotiated_link_width,
             (unsigned long long)cfg.latency_ns,
             cfg.tokens_per_second,
             cfg.burst_size);
    return 0;
}

static int dummy_send(const pcie_tlp_t *t)
{
    dummy_profile_config_t cfg;

    if (!t) {
        return -1;
    }

    dummy_read_runtime_config(&cfg);
    dummy_apply_latency(cfg.latency_ns);
    dummy_apply_throttle(cfg.tokens_per_second);

    pcie_log(PCIE_LOG_DEBUG,
             "[dummy] TX TLP type=%d len=%u latency=%llu ns tps=%u",
             t->type,
             t->length,
             (unsigned long long)cfg.latency_ns,
             cfg.tokens_per_second);
    return 0;
}

static int dummy_recv(pcie_tlp_t *t)
{
    static int count = 0;
    dummy_profile_config_t cfg;

    if (count >= 1000) {
        return -1;
    }

    dummy_read_runtime_config(&cfg);
    dummy_apply_latency(cfg.latency_ns);
    dummy_apply_throttle(cfg.tokens_per_second);

    memset(t, 0, sizeof(*t));
    t->type = PCIE_TLP_MEM_READ;
    t->length = 4;
    t->mem.addr = 0x1000 + count * 4;

    count++;
    return 0;
}

static void dummy_close(void)
{
    fprintf(stderr, "[dummy] close\n");
}

static const pcie_backend_ops_t ops = {
    .send  = dummy_send,
    .recv  = dummy_recv,
    .link_status = dummy_link_status,
    .device_info = dummy_device_info,
    .close = dummy_close
};

const pcie_backend_ops_t *pcie_backend_dummy(void)
{
    return &ops;
}

const pcie_backend_ops_t *pcie_backend_golden(void)
{
    return &ops;
}
