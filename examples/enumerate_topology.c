#include "pcie_topology.h"

#include <stdio.h>

int main(int argc, char **argv)
{
    pcie_topology_t topo;
    const char *path;

    if (argc < 2) {
        fprintf(stderr, "usage: %s <topology.json>\n", argv[0]);
        return 1;
    }

    path = argv[1];
    if (load_topology_from_json(path, &topo) != 0) {
        fprintf(stderr, "failed to load topology JSON: %s\n", path);
        return 1;
    }

    run_pcie_fabric_enumeration(&topo);
    return 0;
}
