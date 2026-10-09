#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (c) 2026 Khadem Ullah

# Capture (optional) → export CSV → gate in TLP2HDL.
# Covers cfg (pci_cfg_*) and Mem (memory_region_ops_*) paths.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
# shellcheck source=qemu_topology_lib.sh
source "${SCRIPT_DIR}/qemu_topology_lib.sh"

TLP2HDL_ROOT="${TLP2HDL_ROOT:-/home/khadem/TLP2HDL}"
OUT_DIR="${OUT_DIR:-${REPO_ROOT}/out}"
TRACE_LOG="${TRACE_LOG:-${OUT_DIR}/fabric_trace.log}"
CSV_OUT="${CSV_OUT:-${OUT_DIR}/fabric_trace.csv}"
RUN_TIMEOUT_SECONDS="${RUN_TIMEOUT_SECONDS:-12}"
CAPTURE_MEM="${CAPTURE_MEM:-1}"
SKIP_CAPTURE="${SKIP_CAPTURE:-0}"
# Prefer PCIe-ish MMIO names; drop UART/GIC flood when CAPTURE_MEM=1
NAME_FILTER="${NAME_FILTER:-pcie,nvme,e1000}"
EXCLUDE_NAME="${EXCLUDE_NAME:-pl011,gicv3,uart}"
TYPES="${TYPES:-}"
MAX_TLPS="${MAX_TLPS:-4000}"
RUNNER="${RUNNER:-zephyr}"   # zephyr | linux | none

mkdir -p "$OUT_DIR"

printf '========================================\n'
printf ' pcieshark → TLP2HDL capture / gate\n'
printf '========================================\n'
printf 'TLP2HDL : %s\n' "$TLP2HDL_ROOT"
printf 'TRACE   : %s\n' "$TRACE_LOG"
printf 'CSV     : %s\n' "$CSV_OUT"
printf 'CAPTURE_MEM=%s  RUNNER=%s  TIMEOUT=%ss\n' "$CAPTURE_MEM" "$RUNNER" "$RUN_TIMEOUT_SECONDS"
print_qemu_trace_summary

if [[ ! -d "$TLP2HDL_ROOT" ]]; then
    echo "Missing TLP2HDL at $TLP2HDL_ROOT (set TLP2HDL_ROOT=...)"
    exit 1
fi

if [[ "$SKIP_CAPTURE" != "1" && "$RUNNER" != "none" ]]; then
    export TRACE_LOG CAPTURE_MEM RUN_TIMEOUT_SECONDS QEMU_TRACE="${QEMU_TRACE:-}"
    case "$RUNNER" in
        zephyr)
            bash "${SCRIPT_DIR}/run_zephyr_ai_topology.sh"
            ;;
        linux)
            bash "${SCRIPT_DIR}/run_linux_ai_topology.sh"
            ;;
        *)
            echo "Unknown RUNNER=$RUNNER (zephyr|linux|none)"
            exit 1
            ;;
    esac
fi

if [[ ! -f "$TRACE_LOG" ]]; then
    echo "Missing trace log: $TRACE_LOG"
    echo "Set SKIP_CAPTURE=0 RUNNER=zephyr, or point TRACE_LOG at an existing log."
    exit 1
fi

EXPORT_ARGS=(python3 "${SCRIPT_DIR}/export_trace_csv.py" "$TRACE_LOG" -o "$CSV_OUT")
if [[ -n "$TYPES" ]]; then
    EXPORT_ARGS+=(--types "$TYPES")
fi
# Full export: drop noisy MMIO names only (keep all cfg + interesting mem)
if [[ -n "$EXCLUDE_NAME" ]]; then
    EXPORT_ARGS+=(--exclude-name "$EXCLUDE_NAME")
fi
"${EXPORT_ARGS[@]}"

# Mem-only slice (PCIe/NVMe/e1000 region names)
if [[ "$CAPTURE_MEM" == "1" ]] || grep -q 'memory_region_ops_' "$TRACE_LOG" 2>/dev/null; then
    MEM_CSV="${OUT_DIR}/fabric_mem.csv"
    MEM_ARGS=(python3 "${SCRIPT_DIR}/export_trace_csv.py" "$TRACE_LOG" -o "$MEM_CSV"
              --types MemRd,MemWr)
    if [[ -n "$NAME_FILTER" ]]; then
        MEM_ARGS+=(--name-filter "$NAME_FILTER")
    fi
    if [[ -n "$EXCLUDE_NAME" ]]; then
        MEM_ARGS+=(--exclude-name "$EXCLUDE_NAME")
    fi
    "${MEM_ARGS[@]}" || true
    if [[ -f "$MEM_CSV" ]]; then
        printf 'Mem CSV: %s\n' "$MEM_CSV"
    fi
fi

printf '\n--- TLP2HDL gate (full export) ---\n'
make -C "$TLP2HDL_ROOT" gate TRACE="$CSV_OUT" MAX_TLPS="$MAX_TLPS"

if [[ -f "${OUT_DIR}/fabric_mem.csv" ]] && [[ -s "${OUT_DIR}/fabric_mem.csv" ]]; then
    MEM_ROWS=$(($(wc -l < "${OUT_DIR}/fabric_mem.csv") - 1))
    if (( MEM_ROWS > 0 )); then
        printf '\n--- TLP2HDL gate (MemRd/MemWr only) ---\n'
        make -C "$TLP2HDL_ROOT" gate TRACE="${OUT_DIR}/fabric_mem.csv" MAX_TLPS="$MAX_TLPS"
    else
        printf 'No MemRd/MemWr rows after filter — skip mem-only gate.\n'
    fi
fi

printf '\nDone.\n'
printf '  Log : %s\n' "$TRACE_LOG"
printf '  CSV : %s\n' "$CSV_OUT"
printf '  Sim : %s/simulation.log\n' "$TLP2HDL_ROOT"
