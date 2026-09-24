# Shared QEMU PCIe fabric helpers. Sourced by the Zephyr and Linux runners.

append_topology_args() {
    local gen="${GEN_QEMU_ARGS:-}"
    local json="${TOPOLOGY_JSON:-}"
    local raw=()
    local token

    if [[ -n "$json" && -f "$json" && -f "$gen" ]]; then
        mapfile -t raw < <(python3 "$gen" "$json")
    elif [[ -f "$gen" ]]; then
        mapfile -t raw < <(python3 "$gen" --builtin-golden)
    fi

    TOPO_ARGS=()
    for token in "${raw[@]+"${raw[@]}"}"; do
        [[ -z "$token" ]] && continue
        if [[ "$token" == -device\ * || "$token" == -netdev\ * ]]; then
            TOPO_ARGS+=("${token%% *}" "${token#* }")
        else
            TOPO_ARGS+=("$token")
        fi
    done

    if [[ ${#TOPO_ARGS[@]} -eq 0 ]]; then
        echo "Failed to generate QEMU topology args" >&2
        return 1
    fi
    QEMU_ARGS+=("${TOPO_ARGS[@]}")
}
