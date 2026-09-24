#!/usr/bin/env bash
# Boot a Linux guest on the same QEMU PCIe golden fabric used by Zephyr.
# The fabric is emulated by QEMU, so it works in a VM (KVM if available, else TCG).
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
# shellcheck source=qemu_topology_lib.sh
source "${SCRIPT_DIR}/qemu_topology_lib.sh"

ARCH="${ARCH:-aarch64}"
MEM_MB="${MEM_MB:-2048}"
SMP="${SMP:-2}"
TRACE_LOG="${TRACE_LOG:-${PWD}/linux_ai_topology_trace.log}"
PCIE_LS_LOG="${PCIE_LS_LOG:-${PWD}/linux_lspci.log}"
PCIE_LS_CAPTURE="${PCIE_LS_CAPTURE:-0}"
QEMU_CONSOLE_PORT="${QEMU_CONSOLE_PORT:-4445}"
RUN_TIMEOUT_SECONDS="${RUN_TIMEOUT_SECONDS:-0}"
TOPOLOGY_JSON="${TOPOLOGY_JSON:-}"
GEN_QEMU_ARGS="${GEN_QEMU_ARGS:-${SCRIPT_DIR}/gen_qemu_args.py}"
DISK_IMAGE="${DISK_IMAGE:-}"
KERNEL_PATH="${KERNEL_PATH:-}"
INITRD_PATH="${INITRD_PATH:-}"
APPEND="${APPEND:-}"
TOPOLOGY_MODE="${TOPOLOGY_MODE:-linux-golden}"

if [[ "$ARCH" == "x86_64" || "$ARCH" == "amd64" ]]; then
    ARCH="x86_64"
    QEMU_BIN="${QEMU_BIN:-qemu-system-x86_64}"
    MACHINE="${MACHINE:-q35}"
    CPU_MODEL="${CPU_MODEL:-qemu64}"
    SERIAL_DEV="ttyS0"
else
    ARCH="aarch64"
    QEMU_BIN="${QEMU_BIN:-qemu-system-aarch64}"
    MACHINE="${MACHINE:-virt,gic-version=3}"
    CPU_MODEL="${CPU_MODEL:-cortex-a57}"
    SERIAL_DEV="ttyAMA0"
fi

if [[ -z "$DISK_IMAGE" ]]; then
    for candidate in \
        "${PWD}/linux-guest.qcow2" \
        "${REPO_ROOT}/linux-guest.qcow2" \
        "$HOME/vm/linux-guest.qcow2" \
        "$HOME/images/linux-guest.qcow2"; do
        if [[ -f "$candidate" ]]; then
            DISK_IMAGE="$candidate"
            break
        fi
    done
fi

if [[ -z "$KERNEL_PATH" ]]; then
    for candidate in \
        "${PWD}/Image" \
        "${REPO_ROOT}/Image" \
        "$HOME/vm/Image"; do
        if [[ -f "$candidate" ]]; then
            KERNEL_PATH="$candidate"
            break
        fi
    done
fi

printf '========================================\n'
printf ' Mode    : Linux QEMU runner\n'
printf ' Arch    : %s\n' "$ARCH"
printf ' Fabric  : same built-in golden PCIe topology as Zephyr\n'
printf '========================================\n'

if ! command -v "$QEMU_BIN" >/dev/null 2>&1 && [[ ! -x "$QEMU_BIN" ]]; then
    echo "Missing QEMU binary: $QEMU_BIN"
    echo "Install qemu-system-aarch64 or qemu-system-x86_64, or set QEMU_BIN."
    exit 1
fi

if [[ ! -f "$DISK_IMAGE" && ! -f "$KERNEL_PATH" ]]; then
    cat <<EOF
No Linux guest image found.

This is possible on a VM: QEMU emulates the PCIe switches, NVMe, and NICs.
Linux inside the guest enumerates them with lspci, the same way Zephyr uses pcie ls.

Provide one of:
  DISK_IMAGE=/path/to/disk.qcow2 $0
  KERNEL_PATH=/path/to/Image INITRD_PATH=/path/to/initrd $0

x86_64 example:
  ARCH=x86_64 DISK_IMAGE=ubuntu.qcow2 $0

aarch64 example (same machine family as the Zephyr runner):
  ARCH=aarch64 KERNEL_PATH=Image INITRD_PATH=initrd.img $0
EOF
    exit 1
fi

if [[ -z "$APPEND" ]]; then
    if [[ "$ARCH" == "x86_64" ]]; then
        APPEND="console=${SERIAL_DEV},115200n8"
    else
        APPEND="console=${SERIAL_DEV} console=tty0"
    fi
    if [[ -f "$DISK_IMAGE" ]]; then
        APPEND+=" root=/dev/vda rw"
    fi
fi

printf 'Using QEMU=%s\n' "$QEMU_BIN"
printf 'Using MACHINE=%s\n' "$MACHINE"
[[ -n "$DISK_IMAGE" ]] && printf 'Using DISK=%s\n' "$DISK_IMAGE"
[[ -n "$KERNEL_PATH" ]] && printf 'Using KERNEL=%s\n' "$KERNEL_PATH"
printf 'Topology: built-in golden fabric\n'
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

QEMU_ARGS=(
    -machine "$MACHINE"
    -cpu "$CPU_MODEL"
    -m "$MEM_MB"
    -smp "$SMP"
    -pidfile qemu-linux.pid
    -display none
    -rtc clock=vm
)

if [[ -e /dev/kvm && "$ARCH" == "x86_64" ]]; then
    QEMU_ARGS+=(-enable-kvm -cpu host)
elif [[ -e /dev/kvm && "$ARCH" == "aarch64" && "$(uname -m)" == "aarch64" ]]; then
    QEMU_ARGS+=(-enable-kvm -cpu host)
fi

if [[ "$PCIE_LS_CAPTURE" == "1" ]]; then
    QEMU_ARGS+=(
        -chardev "socket,host=127.0.0.1,port=${QEMU_CONSOLE_PORT},server=on,wait=off,telnet=on,id=console"
        -serial chardev:console
        -monitor none
    )
elif [[ ! -t 0 || "${PCIE_HEADLESS:-0}" == "1" ]]; then
    QEMU_ARGS+=(
        -serial "file:${PWD}/linux_qemu_console.log"
        -monitor none
    )
else
    QEMU_ARGS+=(
        -chardev stdio,id=con,mux=on
        -serial chardev:con
        -mon chardev=con,mode=readline
    )
fi

if [[ -f "$DISK_IMAGE" ]]; then
    disk_fmt="raw"
    case "$DISK_IMAGE" in
        *.qcow2|*.qcow) disk_fmt="qcow2" ;;
    esac
    QEMU_ARGS+=(
        -drive "if=none,file=${DISK_IMAGE},id=hd0,format=${disk_fmt}"
        -device virtio-blk-pci,drive=hd0,bus=pcie.0,addr=04.0
    )
fi

if [[ -f "$KERNEL_PATH" ]]; then
    QEMU_ARGS+=(-kernel "$KERNEL_PATH")
    [[ -f "$INITRD_PATH" ]] && QEMU_ARGS+=(-initrd "$INITRD_PATH")
    QEMU_ARGS+=(-append "$APPEND")
fi

append_topology_args

if [[ "$PCIE_LS_CAPTURE" == "1" ]]; then
    "${QEMU_BIN}" "${QEMU_ARGS[@]}" > /tmp/linux_ai_qemu_stdout.log 2>&1 &
else
    "${QEMU_BIN}" "${QEMU_ARGS[@]}" -trace pci_cfg_* 2>&1 | tee "$TRACE_LOG" &
fi
QEMU_PID=$!

if [[ "$PCIE_LS_CAPTURE" == "1" ]]; then
    python3 - "$QEMU_CONSOLE_PORT" "$PCIE_LS_LOG" <<'PY'
import socket
import sys
import time

port = int(sys.argv[1])
log_path = sys.argv[2]
commands = b"\nlspci -tvnn\nlspci -nn\n"
chunks = []
for _ in range(90):
    try:
        with socket.create_connection(("127.0.0.1", port), timeout=1.0) as sock:
            sock.settimeout(1.0)
            time.sleep(2)
            sock.sendall(commands)
            end = time.time() + 15
            while time.time() < end:
                try:
                    data = sock.recv(4096)
                    if not data:
                        break
                    chunks.append(data.decode("utf-8", errors="replace"))
                except socket.timeout:
                    break
            break
    except OSError:
        time.sleep(0.5)

with open(log_path, "w", encoding="utf-8", errors="replace") as fh:
    fh.write("".join(chunks))
PY
fi

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
