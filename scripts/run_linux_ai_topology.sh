#!/usr/bin/env bash
# Linux QEMU runner: the verified x86_64 q35 command with the golden fabric.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
# shellcheck source=qemu_topology_lib.sh
source "${SCRIPT_DIR}/qemu_topology_lib.sh"

QEMU_BIN="${QEMU_BIN:-qemu-system-x86_64}"
TRACE_LOG="${TRACE_LOG:-${PWD}/linux_ai_topology_trace.log}"
RUN_TIMEOUT_SECONDS="${RUN_TIMEOUT_SECONDS:-0}"
DISK_IMAGE="${DISK_IMAGE:-}"

if [[ -z "$DISK_IMAGE" ]]; then
    for candidate in \
        "${PWD}/linux-guest.qcow2" \
        "${REPO_ROOT}/linux-guest.qcow2"; do
        if [[ -f "$candidate" ]]; then
            DISK_IMAGE="$candidate"
            break
        fi
    done
fi

printf '========================================\n'
printf ' Mode    : Linux QEMU runner\n'
printf ' Arch    : x86_64 q35\n'
printf ' Fabric  : built-in golden PCIe topology\n'
printf '========================================\n'

if ! command -v "$QEMU_BIN" >/dev/null 2>&1 && [[ ! -x "$QEMU_BIN" ]]; then
    echo "Missing QEMU binary: $QEMU_BIN"
    exit 1
fi

if [[ ! -f "$DISK_IMAGE" ]]; then
    cat <<EOF
No Linux disk image found.

  DISK_IMAGE=/path/to/linux.qcow2 $0

A local empty disk can be created with:
  qemu-img create -f qcow2 linux-guest.qcow2 2G
EOF
    exit 1
fi

printf 'Using QEMU=%s\n' "$QEMU_BIN"
printf 'Using DISK=%s\n' "$DISK_IMAGE"
printf 'Trace log: %s\n' "$TRACE_LOG"

cleanup() {
    if [[ -n "${QEMU_PID:-}" ]] && kill -0 "$QEMU_PID" 2>/dev/null; then
        kill -TERM "$QEMU_PID" 2>/dev/null || true
        sleep 1
        if kill -0 "$QEMU_PID" 2>/dev/null; then
            kill -KILL "$QEMU_PID" 2>/dev/null || true
        fi
        wait "$QEMU_PID" 2>/dev/null || true
    fi
    rm -f "${PWD}/qemu-linux.pid"
}
trap cleanup EXIT
rm -f "${PWD}/qemu-linux.pid"

disk_fmt="raw"
case "$DISK_IMAGE" in
    *.qcow2|*.qcow) disk_fmt="qcow2" ;;
esac

QEMU_ARGS=(
    -machine q35
    -cpu qemu64
    -m 2048
    -smp 2
    -pidfile qemu-linux.pid
    -display none
    -vga none
    -rtc clock=vm
    -serial file:linux_qemu_console.log
    -monitor none
    -drive "if=none,file=${DISK_IMAGE},id=hd0,format=${disk_fmt}"
    -device virtio-blk-pci,drive=hd0,bus=pcie.0,addr=04.0
)
append_golden_fabric

printf 'QEMU command:\n'
printf '  %q' "$QEMU_BIN"
printf ' %q' "${QEMU_ARGS[@]}"
printf ' %q' -trace 'pci_cfg_*'
printf '\n'

"${QEMU_BIN}" "${QEMU_ARGS[@]}" -trace pci_cfg_* 2>&1 | tee "$TRACE_LOG" &
QEMU_PID=$!

if [[ "$RUN_TIMEOUT_SECONDS" =~ ^[0-9]+$ ]] && (( RUN_TIMEOUT_SECONDS > 0 )); then
    echo "Running Linux topology for ${RUN_TIMEOUT_SECONDS}s..."
    sleep "$RUN_TIMEOUT_SECONDS"
    cleanup
    echo "Trace capture finished after ${RUN_TIMEOUT_SECONDS}s"
    printf '\nTrace output written to %s\n' "$TRACE_LOG"
    exit 0
fi

wait "$QEMU_PID"
printf '\nTrace output written to %s\n' "$TRACE_LOG"
