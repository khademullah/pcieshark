#include "pcie_topology.h"

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct {
    const char *s;
    size_t n;
    size_t i;
    char err[160];
} json_cur_t;

static void json_set_err(json_cur_t *c, const char *msg)
{
    if (!c) {
        return;
    }
    snprintf(c->err, sizeof(c->err), "%s", msg ? msg : "JSON parse error");
}

static void json_skip_ws(json_cur_t *c)
{
    while (c->i < c->n && isspace((unsigned char)c->s[c->i])) {
        c->i++;
    }
}

static int json_peek(json_cur_t *c)
{
    json_skip_ws(c);
    return c->i < c->n ? (unsigned char)c->s[c->i] : -1;
}

static int json_eat(json_cur_t *c, char ch)
{
    json_skip_ws(c);
    if (c->i >= c->n || c->s[c->i] != ch) {
        json_set_err(c, "unexpected token");
        return -1;
    }
    c->i++;
    return 0;
}

static int json_parse_string(json_cur_t *c, char *out, size_t out_sz)
{
    size_t o = 0;

    json_skip_ws(c);
    if (c->i >= c->n || c->s[c->i] != '"') {
        json_set_err(c, "expected string");
        return -1;
    }
    c->i++;
    while (c->i < c->n) {
        char ch = c->s[c->i++];
        if (ch == '"') {
            if (out && out_sz) {
                out[o < out_sz ? o : out_sz - 1] = '\0';
            }
            return 0;
        }
        if (ch == '\\' && c->i < c->n) {
            char esc = c->s[c->i++];
            switch (esc) {
                case 'n': ch = '\n'; break;
                case 't': ch = '\t'; break;
                case 'r': ch = '\r'; break;
                case '"': ch = '"'; break;
                case '\\': ch = '\\'; break;
                default: ch = esc; break;
            }
        }
        if (out && o + 1 < out_sz) {
            out[o++] = ch;
        }
    }
    json_set_err(c, "unterminated string");
    return -1;
}

static int json_skip_string(json_cur_t *c)
{
    return json_parse_string(c, NULL, 0);
}

static int json_skip_value(json_cur_t *c);

static int json_skip_object(json_cur_t *c)
{
    int first = 1;
    if (json_eat(c, '{') != 0) {
        return -1;
    }
    while (json_peek(c) != '}') {
        if (!first && json_eat(c, ',') != 0) {
            return -1;
        }
        first = 0;
        if (json_skip_string(c) != 0 || json_eat(c, ':') != 0 || json_skip_value(c) != 0) {
            return -1;
        }
    }
    return json_eat(c, '}');
}

static int json_skip_array(json_cur_t *c)
{
    int first = 1;
    if (json_eat(c, '[') != 0) {
        return -1;
    }
    while (json_peek(c) != ']') {
        if (!first && json_eat(c, ',') != 0) {
            return -1;
        }
        first = 0;
        if (json_skip_value(c) != 0) {
            return -1;
        }
    }
    return json_eat(c, ']');
}

static int json_skip_literal_or_number(json_cur_t *c)
{
    json_skip_ws(c);
    if (c->i + 4 <= c->n && strncmp(c->s + c->i, "true", 4) == 0) {
        c->i += 4;
        return 0;
    }
    if (c->i + 5 <= c->n && strncmp(c->s + c->i, "false", 5) == 0) {
        c->i += 5;
        return 0;
    }
    if (c->i + 4 <= c->n && strncmp(c->s + c->i, "null", 4) == 0) {
        c->i += 4;
        return 0;
    }
    if (c->i < c->n && (c->s[c->i] == '-' || isdigit((unsigned char)c->s[c->i]))) {
        if (c->s[c->i] == '-') {
            c->i++;
        }
        while (c->i < c->n && (isdigit((unsigned char)c->s[c->i]) || c->s[c->i] == '.' ||
                               c->s[c->i] == 'e' || c->s[c->i] == 'E' ||
                               c->s[c->i] == '+' || c->s[c->i] == '-')) {
            c->i++;
        }
        return 0;
    }
    json_set_err(c, "expected value");
    return -1;
}

static int json_skip_value(json_cur_t *c)
{
    int ch = json_peek(c);
    if (ch == '{') {
        return json_skip_object(c);
    }
    if (ch == '[') {
        return json_skip_array(c);
    }
    if (ch == '"') {
        return json_skip_string(c);
    }
    return json_skip_literal_or_number(c);
}

static int json_parse_bool(json_cur_t *c, bool *out)
{
    json_skip_ws(c);
    if (c->i + 4 <= c->n && strncmp(c->s + c->i, "true", 4) == 0) {
        c->i += 4;
        *out = true;
        return 0;
    }
    if (c->i + 5 <= c->n && strncmp(c->s + c->i, "false", 5) == 0) {
        c->i += 5;
        *out = false;
        return 0;
    }
    json_set_err(c, "expected boolean");
    return -1;
}

static int json_parse_int(json_cur_t *c, int *out)
{
    char *end = NULL;
    long v;

    json_skip_ws(c);
    v = strtol(c->s + c->i, &end, 10);
    if (end == c->s + c->i) {
        json_set_err(c, "expected integer");
        return -1;
    }
    c->i = (size_t)(end - c->s);
    *out = (int)v;
    return 0;
}

static void copy_str(char *dst, size_t dst_sz, const char *src)
{
    if (!dst || dst_sz == 0) {
        return;
    }
    if (!src) {
        dst[0] = '\0';
        return;
    }
    snprintf(dst, dst_sz, "%s", src);
}

static void bdf_to_addr(const char *bdf, char *addr, size_t addr_sz)
{
    unsigned bus = 0, dev = 0, fn = 0;
    if (!bdf || !addr || addr_sz == 0) {
        return;
    }
    if (sscanf(bdf, "%x:%x.%x", &bus, &dev, &fn) == 3 || sscanf(bdf, "%x.%x", &dev, &fn) == 2) {
        snprintf(addr, addr_sz, "%02x.%x", dev, fn);
        return;
    }
    copy_str(addr, addr_sz, bdf);
}

static int parse_root_port(json_cur_t *c, pcie_root_port_t *rp, int index)
{
    memset(rp, 0, sizeof(*rp));
    snprintf(rp->id, sizeof(rp->id), "rp%d", index + 1);

    if (json_peek(c) == '"') {
        if (json_parse_string(c, rp->bdf, sizeof(rp->bdf)) != 0) {
            return -1;
        }
        bdf_to_addr(rp->bdf, rp->addr, sizeof(rp->addr));
        return 0;
    }

    if (json_eat(c, '{') != 0) {
        return -1;
    }
    while (json_peek(c) != '}') {
        char key[64];
        if (json_parse_string(c, key, sizeof(key)) != 0 || json_eat(c, ':') != 0) {
            return -1;
        }
        if (strcmp(key, "id") == 0) {
            if (json_parse_string(c, rp->id, sizeof(rp->id)) != 0) {
                return -1;
            }
        } else if (strcmp(key, "bdf") == 0) {
            if (json_parse_string(c, rp->bdf, sizeof(rp->bdf)) != 0) {
                return -1;
            }
        } else if (strcmp(key, "addr") == 0) {
            if (json_parse_string(c, rp->addr, sizeof(rp->addr)) != 0) {
                return -1;
            }
        } else if (strcmp(key, "label") == 0) {
            if (json_parse_string(c, rp->label, sizeof(rp->label)) != 0) {
                return -1;
            }
        } else if (strcmp(key, "secondary_bus") == 0) {
            if (json_parse_string(c, rp->secondary_bus, sizeof(rp->secondary_bus)) != 0) {
                return -1;
            }
        } else if (json_skip_value(c) != 0) {
            return -1;
        }
        json_skip_ws(c);
        if (json_peek(c) == ',') {
            c->i++;
        }
    }
    if (json_eat(c, '}') != 0) {
        return -1;
    }
    if (rp->addr[0] == '\0' && rp->bdf[0] != '\0') {
        bdf_to_addr(rp->bdf, rp->addr, sizeof(rp->addr));
    }
    if (rp->bdf[0] == '\0' && rp->addr[0] != '\0') {
        snprintf(rp->bdf, sizeof(rp->bdf), "00:%s", rp->addr);
    }
    return 0;
}

static int parse_root_complex(json_cur_t *c, root_complex_t *rc)
{
    memset(rc, 0, sizeof(*rc));
    copy_str(rc->domain, sizeof(rc->domain), "0000");
    copy_str(rc->root_bus, sizeof(rc->root_bus), "00");

    if (json_eat(c, '{') != 0) {
        return -1;
    }
    while (json_peek(c) != '}') {
        char key[64];
        if (json_parse_string(c, key, sizeof(key)) != 0 || json_eat(c, ':') != 0) {
            return -1;
        }
        if (strcmp(key, "domain") == 0) {
            if (json_parse_string(c, rc->domain, sizeof(rc->domain)) != 0) {
                return -1;
            }
        } else if (strcmp(key, "root_bus") == 0) {
            if (json_parse_string(c, rc->root_bus, sizeof(rc->root_bus)) != 0) {
                return -1;
            }
        } else if (strcmp(key, "label") == 0) {
            if (json_parse_string(c, rc->label, sizeof(rc->label)) != 0) {
                return -1;
            }
        } else if (strcmp(key, "root_ports") == 0) {
            if (json_eat(c, '[') != 0) {
                return -1;
            }
            while (json_peek(c) != ']') {
                if (rc->root_port_count >= MAX_PORTS) {
                    json_set_err(c, "too many root ports");
                    return -1;
                }
                if (parse_root_port(c, &rc->root_ports[rc->root_port_count], rc->root_port_count) != 0) {
                    return -1;
                }
                rc->root_port_count++;
                json_skip_ws(c);
                if (json_peek(c) == ',') {
                    c->i++;
                }
            }
            if (json_eat(c, ']') != 0) {
                return -1;
            }
        } else if (json_skip_value(c) != 0) {
            return -1;
        }
        json_skip_ws(c);
        if (json_peek(c) == ',') {
            c->i++;
        }
    }
    return json_eat(c, '}');
}

static int parse_switch(json_cur_t *c, pcie_switch_t *sw)
{
    memset(sw, 0, sizeof(*sw));
    if (json_eat(c, '{') != 0) {
        return -1;
    }
    while (json_peek(c) != '}') {
        char key[64];
        if (json_parse_string(c, key, sizeof(key)) != 0 || json_eat(c, ':') != 0) {
            return -1;
        }
        if (strcmp(key, "name") == 0) {
            if (json_parse_string(c, sw->name, sizeof(sw->name)) != 0) {
                return -1;
            }
        } else if (strcmp(key, "parent") == 0) {
            if (json_parse_string(c, sw->parent, sizeof(sw->parent)) != 0) {
                return -1;
            }
        } else if (strcmp(key, "upstream_port") == 0) {
            if (json_parse_string(c, sw->upstream_port, sizeof(sw->upstream_port)) != 0) {
                return -1;
            }
        } else if (strcmp(key, "p2p_allowed") == 0) {
            if (json_parse_bool(c, &sw->p2p_allowed) != 0) {
                return -1;
            }
        } else if (strcmp(key, "downstream_ports") == 0) {
            if (json_eat(c, '[') != 0) {
                return -1;
            }
            while (json_peek(c) != ']') {
                char port[MAX_BDF_LEN];
                if (sw->downstream_port_count >= MAX_PORTS) {
                    json_set_err(c, "too many downstream ports");
                    return -1;
                }
                if (json_parse_string(c, port, sizeof(port)) != 0) {
                    return -1;
                }
                copy_str(sw->downstream_ports[sw->downstream_port_count], MAX_BDF_LEN, port);
                sw->downstream_port_count++;
                json_skip_ws(c);
                if (json_peek(c) == ',') {
                    c->i++;
                }
            }
            if (json_eat(c, ']') != 0) {
                return -1;
            }
        } else if (json_skip_value(c) != 0) {
            return -1;
        }
        json_skip_ws(c);
        if (json_peek(c) == ',') {
            c->i++;
        }
    }
    if (json_eat(c, '}') != 0) {
        return -1;
    }
    for (int i = 0; i < sw->downstream_port_count; ++i) {
        snprintf(sw->downstream_ids[i], MAX_NAME_LEN, "%s_dp%d", sw->name, i);
    }
    return 0;
}

static int parse_endpoint(json_cur_t *c, pcie_endpoint_t *ep)
{
    memset(ep, 0, sizeof(*ep));
    if (json_eat(c, '{') != 0) {
        return -1;
    }
    while (json_peek(c) != '}') {
        char key[64];
        if (json_parse_string(c, key, sizeof(key)) != 0 || json_eat(c, ':') != 0) {
            return -1;
        }
        if (strcmp(key, "bdf") == 0) {
            if (json_parse_string(c, ep->bdf, sizeof(ep->bdf)) != 0) {
                return -1;
            }
        } else if (strcmp(key, "type") == 0) {
            if (json_parse_string(c, ep->type, sizeof(ep->type)) != 0) {
                return -1;
            }
        } else if (strcmp(key, "label") == 0) {
            if (json_parse_string(c, ep->label, sizeof(ep->label)) != 0) {
                return -1;
            }
        } else if (strcmp(key, "display") == 0) {
            if (json_parse_string(c, ep->display, sizeof(ep->display)) != 0) {
                return -1;
            }
        } else if (strcmp(key, "parent") == 0) {
            if (json_parse_string(c, ep->parent, sizeof(ep->parent)) != 0) {
                return -1;
            }
        } else if (strcmp(key, "serial") == 0) {
            if (json_parse_string(c, ep->serial, sizeof(ep->serial)) != 0) {
                return -1;
            }
        } else if (strcmp(key, "peer_group") == 0) {
            if (json_parse_int(c, &ep->peer_group) != 0) {
                return -1;
            }
        } else if (json_skip_value(c) != 0) {
            return -1;
        }
        json_skip_ws(c);
        if (json_peek(c) == ',') {
            c->i++;
        }
    }
    return json_eat(c, '}');
}

static void assign_default_parents(pcie_topology_t *topo)
{
    char rp_ids[MAX_PORTS][MAX_NAME_LEN];
    int rp_count = 0;
    int next_rp = 0;
    char slots[MAX_DEVICES][MAX_NAME_LEN];
    int slot_count = 0;
    int next_slot = 0;

    for (int r = 0; r < topo->rc_count; ++r) {
        for (int p = 0; p < topo->root_complexes[r].root_port_count; ++p) {
            if (rp_count < MAX_PORTS) {
                copy_str(rp_ids[rp_count++], MAX_NAME_LEN, topo->root_complexes[r].root_ports[p].id);
            }
        }
    }

    for (int s = 0; s < topo->switch_count; ++s) {
        if (topo->switches[s].parent[0] == '\0' && rp_count > 0) {
            copy_str(topo->switches[s].parent, MAX_NAME_LEN, rp_ids[next_rp % rp_count]);
            next_rp++;
        }
        for (int d = 0; d < topo->switches[s].downstream_port_count && slot_count < MAX_DEVICES; ++d) {
            copy_str(slots[slot_count++], MAX_NAME_LEN, topo->switches[s].downstream_ids[d]);
        }
    }

    if (slot_count == 0) {
        for (int i = 0; i < rp_count && slot_count < MAX_DEVICES; ++i) {
            copy_str(slots[slot_count++], MAX_NAME_LEN, rp_ids[i]);
        }
    }

    for (int e = 0; e < topo->endpoint_count; ++e) {
        if (topo->endpoints[e].parent[0] == '\0' && slot_count > 0) {
            copy_str(topo->endpoints[e].parent, MAX_NAME_LEN, slots[next_slot % slot_count]);
            next_slot++;
        }
        if (topo->endpoints[e].display[0] == '\0') {
            copy_str(topo->endpoints[e].display, MAX_NAME_LEN,
                     topo->endpoints[e].label[0] ? topo->endpoints[e].label : topo->endpoints[e].type);
        }
    }
}

int load_topology_from_json(const char *json_path, pcie_topology_t *topo)
{
    FILE *fp;
    long sz;
    char *buf;
    json_cur_t cur;

    if (!json_path || !topo) {
        return -1;
    }

    memset(topo, 0, sizeof(*topo));
    fp = fopen(json_path, "rb");
    if (!fp) {
        return -1;
    }
    if (fseek(fp, 0, SEEK_END) != 0) {
        fclose(fp);
        return -1;
    }
    sz = ftell(fp);
    if (sz < 2) {
        fclose(fp);
        return -1;
    }
    rewind(fp);
    buf = (char *)malloc((size_t)sz + 1);
    if (!buf) {
        fclose(fp);
        return -1;
    }
    if (fread(buf, 1, (size_t)sz, fp) != (size_t)sz) {
        free(buf);
        fclose(fp);
        return -1;
    }
    buf[sz] = '\0';
    fclose(fp);

    memset(&cur, 0, sizeof(cur));
    cur.s = buf;
    cur.n = (size_t)sz;

    if (json_eat(&cur, '{') != 0) {
        free(buf);
        return -1;
    }

    while (json_peek(&cur) != '}') {
        char key[64];
        if (json_parse_string(&cur, key, sizeof(key)) != 0 || json_eat(&cur, ':') != 0) {
            free(buf);
            return -1;
        }
        if (strcmp(key, "topology_name") == 0) {
            if (json_parse_string(&cur, topo->topology_name, sizeof(topo->topology_name)) != 0) {
                free(buf);
                return -1;
            }
        } else if (strcmp(key, "root_complexes") == 0) {
            if (json_eat(&cur, '[') != 0) {
                free(buf);
                return -1;
            }
            while (json_peek(&cur) != ']') {
                if (topo->rc_count >= MAX_RC) {
                    json_set_err(&cur, "too many root complexes");
                    free(buf);
                    return -1;
                }
                if (parse_root_complex(&cur, &topo->root_complexes[topo->rc_count]) != 0) {
                    free(buf);
                    return -1;
                }
                topo->rc_count++;
                json_skip_ws(&cur);
                if (json_peek(&cur) == ',') {
                    cur.i++;
                }
            }
            if (json_eat(&cur, ']') != 0) {
                free(buf);
                return -1;
            }
        } else if (strcmp(key, "switches") == 0) {
            if (json_eat(&cur, '[') != 0) {
                free(buf);
                return -1;
            }
            while (json_peek(&cur) != ']') {
                if (topo->switch_count >= MAX_SWITCHES) {
                    free(buf);
                    return -1;
                }
                if (parse_switch(&cur, &topo->switches[topo->switch_count]) != 0) {
                    free(buf);
                    return -1;
                }
                topo->switch_count++;
                json_skip_ws(&cur);
                if (json_peek(&cur) == ',') {
                    cur.i++;
                }
            }
            if (json_eat(&cur, ']') != 0) {
                free(buf);
                return -1;
            }
        } else if (strcmp(key, "endpoints") == 0) {
            if (json_eat(&cur, '[') != 0) {
                free(buf);
                return -1;
            }
            while (json_peek(&cur) != ']') {
                if (topo->endpoint_count >= MAX_DEVICES) {
                    free(buf);
                    return -1;
                }
                if (parse_endpoint(&cur, &topo->endpoints[topo->endpoint_count]) != 0) {
                    free(buf);
                    return -1;
                }
                topo->endpoint_count++;
                json_skip_ws(&cur);
                if (json_peek(&cur) == ',') {
                    cur.i++;
                }
            }
            if (json_eat(&cur, ']') != 0) {
                free(buf);
                return -1;
            }
        } else if (json_skip_value(&cur) != 0) {
            free(buf);
            return -1;
        }
        json_skip_ws(&cur);
        if (json_peek(&cur) == ',') {
            cur.i++;
        }
    }

    if (json_eat(&cur, '}') != 0) {
        free(buf);
        return -1;
    }
    free(buf);

    if (topo->topology_name[0] == '\0') {
        copy_str(topo->topology_name, sizeof(topo->topology_name), "unnamed");
    }
    assign_default_parents(topo);
    return 0;
}

int topology_function_count(const pcie_topology_t *topo)
{
    int n = 0;
    int r, s;

    if (!topo) {
        return 0;
    }
    for (r = 0; r < topo->rc_count; ++r) {
        n += topo->root_complexes[r].root_port_count;
    }
    for (s = 0; s < topo->switch_count; ++s) {
        n += 1 + topo->switches[s].downstream_port_count;
    }
    n += topo->endpoint_count;
    return n;
}

static void emit_cfgrd(FILE *out, const char *bdf, const char *role)
{
    static const unsigned offs[] = {0x00, 0x04, 0x08, 0x0c, 0x10, 0x14, 0x18, 0x1c};
    size_t i;
    if (!out || !bdf || bdf[0] == '\0') {
        return;
    }
    for (i = 0; i < sizeof(offs) / sizeof(offs[0]); ++i) {
        fprintf(out, "CfgRd  bdf=%-10s  offset=0x%02x  %s\n", bdf, offs[i], role ? role : "");
    }
}

void run_pcie_fabric_enumeration_to(const pcie_topology_t *topo, FILE *out)
{
    if (!topo || !out) {
        return;
    }

    fprintf(out, "=== PCIe fabric enumeration: %s ===\n", topo->topology_name);
    fprintf(out, "root complexes: %d  switches: %d  endpoints: %d  functions: %d\n\n",
            topo->rc_count, topo->switch_count, topo->endpoint_count,
            topology_function_count(topo));

    for (int r = 0; r < topo->rc_count; ++r) {
        const root_complex_t *rc = &topo->root_complexes[r];
        fprintf(out, "Root Complex %d  domain=%s  bus=%s  %s\n",
                r, rc->domain, rc->root_bus, rc->label[0] ? rc->label : "");
        for (int p = 0; p < rc->root_port_count; ++p) {
            const pcie_root_port_t *rp = &rc->root_ports[p];
            fprintf(out, "  Root Port %-8s  bdf=%-10s  addr=%-6s  %s",
                    rp->id, rp->bdf, rp->addr, rp->label);
            if (rp->secondary_bus[0]) {
                fprintf(out, "  sec_bus=%s", rp->secondary_bus);
            }
            fputc('\n', out);
            emit_cfgrd(out, rp->bdf, rp->id);

            for (int s = 0; s < topo->switch_count; ++s) {
                const pcie_switch_t *sw = &topo->switches[s];
                if (strcmp(sw->parent, rp->id) != 0) {
                    continue;
                }
                fprintf(out, "    Switch %-16s  up=%-10s  p2p=%s\n",
                        sw->name, sw->upstream_port, sw->p2p_allowed ? "yes" : "no");
                emit_cfgrd(out, sw->upstream_port, sw->name);
                for (int d = 0; d < sw->downstream_port_count; ++d) {
                    fprintf(out, "      DP %-16s  %s\n",
                            sw->downstream_ids[d], sw->downstream_ports[d]);
                    emit_cfgrd(out, sw->downstream_ports[d], sw->downstream_ids[d]);
                    for (int e = 0; e < topo->endpoint_count; ++e) {
                        const pcie_endpoint_t *ep = &topo->endpoints[e];
                        if (strcmp(ep->parent, sw->downstream_ids[d]) != 0) {
                            continue;
                        }
                        fprintf(out, "        Endpoint %-12s  type=%-12s  bdf=%-10s  %s\n",
                                ep->display[0] ? ep->display : ep->label,
                                ep->type, ep->bdf, ep->label);
                        emit_cfgrd(out, ep->bdf, ep->label);
                    }
                }
            }

            for (int e = 0; e < topo->endpoint_count; ++e) {
                const pcie_endpoint_t *ep = &topo->endpoints[e];
                if (strcmp(ep->parent, rp->id) != 0) {
                    continue;
                }
                fprintf(out, "    Endpoint %-12s  type=%-12s  bdf=%-10s  %s\n",
                        ep->display[0] ? ep->display : ep->label,
                        ep->type, ep->bdf, ep->label);
                emit_cfgrd(out, ep->bdf, ep->label);
            }
        }
    }

    fprintf(out, "\nEnumeration complete.\n");
}

void run_pcie_fabric_enumeration(const pcie_topology_t *topo)
{
    run_pcie_fabric_enumeration_to(topo, stdout);
}
