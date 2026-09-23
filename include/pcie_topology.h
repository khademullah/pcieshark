#ifndef PCIE_TOPOLOGY_H
#define PCIE_TOPOLOGY_H

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>

#define MAX_NAME_LEN 96
#define MAX_BDF_LEN  16
#define MAX_PORTS    32
#define MAX_DEVICES  128
#define MAX_RC       8
#define MAX_SWITCHES 64

typedef struct {
    char id[MAX_NAME_LEN];
    char bdf[MAX_BDF_LEN];
    char addr[MAX_BDF_LEN];
    char label[MAX_NAME_LEN];
    char secondary_bus[MAX_BDF_LEN];
} pcie_root_port_t;

typedef struct {
    char domain[MAX_NAME_LEN];
    char root_bus[MAX_NAME_LEN];
    char label[MAX_NAME_LEN];
    pcie_root_port_t root_ports[MAX_PORTS];
    int root_port_count;
} root_complex_t;

typedef struct {
    char name[MAX_NAME_LEN];
    char parent[MAX_NAME_LEN];
    char upstream_port[MAX_BDF_LEN];
    char downstream_ports[MAX_PORTS][MAX_BDF_LEN];
    char downstream_ids[MAX_PORTS][MAX_NAME_LEN];
    int downstream_port_count;
    bool p2p_allowed;
} pcie_switch_t;

typedef struct {
    char bdf[MAX_BDF_LEN];
    char type[MAX_NAME_LEN];
    char label[MAX_NAME_LEN];
    char display[MAX_NAME_LEN];
    char parent[MAX_NAME_LEN];
    char serial[MAX_NAME_LEN];
    int peer_group;
} pcie_endpoint_t;

typedef struct {
    char topology_name[MAX_NAME_LEN];
    root_complex_t root_complexes[MAX_RC];
    int rc_count;
    pcie_switch_t switches[MAX_SWITCHES];
    int switch_count;
    pcie_endpoint_t endpoints[MAX_DEVICES];
    int endpoint_count;
} pcie_topology_t;

int load_topology_from_json(const char *json_path, pcie_topology_t *topo);
void run_pcie_fabric_enumeration(const pcie_topology_t *topo);
void run_pcie_fabric_enumeration_to(const pcie_topology_t *topo, FILE *out);
int topology_function_count(const pcie_topology_t *topo);

#endif /* PCIE_TOPOLOGY_H */
