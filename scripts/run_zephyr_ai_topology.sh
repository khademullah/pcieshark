#!/usr/bin/env bash
set -euo pipefail

ZEPHYR_VENV="${ZEPHYR_VENV:-$HOME/zephyrproject/.venv/bin/activate}"
ZEPHYR_BASE="${ZEPHYR_BASE:-$HOME/zephyrproject/zephyr}"
ZEPHYR_SDK_INSTALL_DIR="${ZEPHYR_SDK_INSTALL_DIR:-/home/khadem/zephyr-sdk-1.0.1}"
QEMU_BIN="${QEMU_BIN:-$ZEPHYR_SDK_INSTALL_DIR/hosttools/sysroots/x86_64-pokysdk-linux/usr/bin/qemu-system-aarch64}"
TRACE_LOG="${TRACE_LOG:-${PWD}/zephyr_ai_topology_trace.log}"
PCIE_LS_LOG="${PCIE_LS_LOG:-${PWD}/zephyr_pcie_ls.log}"
PCIE_LS_CAPTURE="${PCIE_LS_CAPTURE:-0}"
QEMU_CONSOLE_PORT="${QEMU_CONSOLE_PORT:-4444}"
RUN_TIMEOUT_SECONDS="${RUN_TIMEOUT_SECONDS:-0}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
TOPOLOGY_JSON="${TOPOLOGY_JSON:-}"
GEN_QEMU_ARGS="${GEN_QEMU_ARGS:-${SCRIPT_DIR}/gen_qemu_args.py}"
TRACE_LOG_DEFAULT="${PWD}/zephyr_ai_topology_trace.log"
TOPO_STEM="golden"

if [[ -n "$TOPOLOGY_JSON" && -f "$TOPOLOGY_JSON" ]]; then
    TOPO_STEM="$(basename "$TOPOLOGY_JSON" .json)"
    if [[ -z "${TOPOLOGY_MODE:-}" ]]; then
        TOPOLOGY_MODE="json-file"
    fi
else
    TOPOLOGY_JSON=""
    if [[ -z "${TOPOLOGY_MODE:-}" ]]; then
        TOPOLOGY_MODE="zephyr-golden"
    fi
fi

# Keep custom JSON traces out of the golden runner log unless the caller
# already chose a destination.
if [[ "${TRACE_LOG}" == "${TRACE_LOG_DEFAULT}" && "$TOPOLOGY_MODE" != "zephyr-golden" ]]; then
    TRACE_LOG="${PWD}/zephyr_${TOPO_STEM}_trace.log"
fi

if [[ "${PCIE_LS_LOG}" == "${PWD}/zephyr_pcie_ls.log" && "$TOPOLOGY_MODE" != "zephyr-golden" ]]; then
    PCIE_LS_LOG="${PWD}/zephyr_${TOPO_STEM}_pcie_ls.log"
fi

# Prefer a user-supplied path, then common local Zephyr build locations, then the
# example firmware repo used for this PCIe topology.
KERNEL_PATH="${KERNEL_PATH:-${PWD}/build/zephyr/zephyr.elf}"
if [[ ! -f "$KERNEL_PATH" ]]; then
    for candidate in \
        "$HOME/firmware-repos/firmware-on-arm-fast-models/zephyr-pcie-contrib/build/zephyr/zephyr.elf" \
        "$HOME/firmware-repos/firmware-on-arm-fast-models/zephyr-rtos-qemu/build/zephyr/zephyr.elf" \
        "$HOME/firmware-repos/firmware-on-arm-fast-models/zephyr-rtos/build/zephyr/zephyr.elf" \
        "$HOME/zephyrproject/zephyr/build/zephyr/zephyr.elf"; do
        if [[ -f "$candidate" ]]; then
            KERNEL_PATH="$candidate"
            break
        fi
    done
fi

printf '========================================\n'
if [[ "$TOPOLOGY_MODE" == "zephyr-golden" ]]; then
    printf ' Mode    : Zephyr golden runner\n'
    printf ' Fabric  : built-in golden topology\n'
else
    printf ' Mode    : Custom JSON topology\n'
    printf ' File    : %s\n' "$TOPOLOGY_JSON"
    printf ' Note    : QEMU is launched from the Zephyr script, but this is not the golden fabric\n'
fi
printf '========================================\n'

if [[ ! -f "$ZEPHYR_VENV" ]]; then
    echo "Missing Zephyr virtualenv at: $ZEPHYR_VENV"
    echo "Expected: source ~/zephyrproject/.venv/bin/activate"
    exit 1
fi

if [[ ! -d "$ZEPHYR_BASE" ]]; then
    echo "Missing Zephyr source tree at: $ZEPHYR_BASE"
    exit 1
fi

if [[ ! -d "$ZEPHYR_SDK_INSTALL_DIR" ]]; then
    echo "Missing Zephyr SDK at: $ZEPHYR_SDK_INSTALL_DIR"
    exit 1
fi

if [[ ! -x "$QEMU_BIN" ]]; then
    echo "Missing qemu-system-aarch64 at: $QEMU_BIN"
    exit 1
fi

if [[ ! -f "$KERNEL_PATH" ]]; then
    echo "Missing Zephyr kernel image: $KERNEL_PATH"
    echo "Build the Zephyr image first, then rerun this script."
    echo "Typical commands:"
    echo "  cd /home/khadem/firmware-repos/firmware-on-arm-fast-models/zephyr-pcie-contrib"
    echo "  source ~/zephyrproject/.venv/bin/activate"
    echo "  export ZEPHYR_BASE=~/zephyrproject/zephyr"
    echo "  export ZEPHYR_TOOLCHAIN_VARIANT=zephyr"
    echo "  export ZEPHYR_SDK_INSTALL_DIR=/home/khadem/zephyr-sdk-1.0.1"
    echo "  west build -b qemu_cortex_a53 ."
    exit 1
fi

# Activate the Zephyr environment.
# shellcheck disable=SC1090
source "$ZEPHYR_VENV"

export ZEPHYR_BASE
export ZEPHYR_TOOLCHAIN_VARIANT="${ZEPHYR_TOOLCHAIN_VARIANT:-zephyr}"
export ZEPHYR_SDK_INSTALL_DIR

printf 'Using ZEPHYR_BASE=%s\n' "$ZEPHYR_BASE"
printf 'Using ZEPHYR_SDK_INSTALL_DIR=%s\n' "$ZEPHYR_SDK_INSTALL_DIR"
printf 'Using QEMU=%s\n' "$QEMU_BIN"
printf 'Using KERNEL=%s\n' "$KERNEL_PATH"
if [[ -n "$TOPOLOGY_JSON" ]]; then
  printf 'Topology file: %s\n' "$TOPOLOGY_JSON"
else
  printf 'Topology: built-in golden fabric\n'
fi
printf 'Trace log: %s\n' "$TRACE_LOG"
printf 'pcie ls log: %s\n' "$PCIE_LS_LOG"
printf 'pcie ls capture: %s\n' "$PCIE_LS_CAPTURE"
printf 'console port: %s\n' "$QEMU_CONSOLE_PORT"

cleanup_stale_qemu_lock() {
    local pidfile="${PWD}/qemu.pid"
    if [[ -f "$pidfile" ]]; then
        local stale_pid
        stale_pid="$(cat "$pidfile" 2>/dev/null || true)"
        if [[ -n "$stale_pid" ]] && kill -0 "$stale_pid" 2>/dev/null; then
            kill -TERM "$stale_pid" 2>/dev/null || true
            sleep 1
            if kill -0 "$stale_pid" 2>/dev/null; then
                kill -KILL "$stale_pid" 2>/dev/null || true
            fi
        fi
        rm -f "$pidfile"
    fi
}

cleanup() {
    if [[ -n "${QEMU_PID:-}" ]] && kill -0 "$QEMU_PID" 2>/dev/null; then
        kill -TERM "$QEMU_PID" 2>/dev/null || true
        sleep 1
        if kill -0 "$QEMU_PID" 2>/dev/null; then
            kill -KILL "$QEMU_PID" 2>/dev/null || true
        fi
        wait "$QEMU_PID" 2>/dev/null || true
    fi
    rm -f "${PWD}/qemu.pid"
}
trap cleanup EXIT
cleanup_stale_qemu_lock

QEMU_ARGS=(
  -cpu cortex-a53
  -machine virt,secure=on,gic-version=3
  -pidfile qemu.pid
)

if [[ "$PCIE_LS_CAPTURE" == "1" ]]; then
  QEMU_ARGS+=(
    -chardev socket,host=127.0.0.1,port=4444,server=on,wait=off,telnet=on,id=console
    -serial chardev:console
    -monitor none
  )
elif [[ ! -t 0 || "${PCIE_HEADLESS:-0}" == "1" ]]; then
  # GUI/QProcess has no TTY; stdio chardev makes QEMU exit immediately.
  QEMU_ARGS+=(
    -serial "file:${PWD}/zephyr_qemu_console.log"
    -monitor none
  )
else
  QEMU_ARGS+=(
    -chardev stdio,id=con,mux=on
    -serial chardev:con
    -mon chardev=con,mode=readline
  )
fi

QEMU_ARGS+=(
  -display none
  -rtc clock=vm
  -net none
)

if [[ -f "$TOPOLOGY_JSON" && -f "$GEN_QEMU_ARGS" ]]; then
  mapfile -t TOPO_RAW < <(python3 "$GEN_QEMU_ARGS" "$TOPOLOGY_JSON")
  TOPO_ARGS=()
  for token in "${TOPO_RAW[@]}"; do
    [[ -z "$token" ]] && continue
    # Older generator printed "-device spec" on one line; keep that working.
    if [[ "$token" == -device\ * || "$token" == -netdev\ * ]]; then
      TOPO_ARGS+=("${token%% *}" "${token#* }")
    else
      TOPO_ARGS+=("$token")
    fi
  done
  if [[ ${#TOPO_ARGS[@]} -eq 0 ]]; then
    echo "Failed to generate QEMU topology args from $TOPOLOGY_JSON"
    exit 1
  fi
  QEMU_ARGS+=("${TOPO_ARGS[@]}")
else
  echo "Topology JSON or generator missing; using built-in golden fabric."
  QEMU_ARGS+=(
    -netdev user,id=net1 -netdev user,id=net2
    -device pcie-root-port,id=rp1,bus=pcie.0,chassis=1,slot=1,addr=01.0,multifunction=on
    -device pcie-root-port,id=rp2,bus=pcie.0,chassis=2,slot=1,addr=01.1
    -device pcie-root-port,id=rp3,bus=pcie.0,chassis=3,slot=1,addr=01.2
    -device pcie-root-port,id=rp4,bus=pcie.0,chassis=4,slot=1,addr=01.3
    -device x3130-upstream,id=switch0_up,bus=rp1,addr=00.0
    -device xio3130-downstream,id=switch0_dp0,bus=switch0_up,chassis=11,slot=0,addr=00.0,multifunction=on
    -device xio3130-downstream,id=switch0_dp1,bus=switch0_up,chassis=12,slot=1,addr=00.1
    -device nvme,id=ai1,bus=switch0_dp0,addr=00.0,serial=AI_ACCEL_01
    -device nvme,id=ai2,bus=switch0_dp1,addr=00.0,serial=AI_ACCEL_02
    -device x3130-upstream,id=switch1_up,bus=rp2,addr=00.0
    -device xio3130-downstream,id=switch1_dp0,bus=switch1_up,chassis=21,slot=0,addr=00.0,multifunction=on
    -device xio3130-downstream,id=switch1_dp1,bus=switch1_up,chassis=22,slot=1,addr=00.1
    -device nvme,id=ai3,bus=switch1_dp0,addr=00.0,serial=AI_ACCEL_03
    -device nvme,id=ai4,bus=switch1_dp1,addr=00.0,serial=AI_ACCEL_04
    -device x3130-upstream,id=switch2_up,bus=rp3,addr=00.0
    -device xio3130-downstream,id=switch2_dp0,bus=switch2_up,chassis=31,slot=0,addr=00.0,multifunction=on
    -device xio3130-downstream,id=switch2_dp1,bus=switch2_up,chassis=32,slot=1,addr=00.1
    -device nvme,id=nvme1,bus=switch2_dp0,addr=00.0,serial=DATA_POOL_01
    -device nvme,id=nvme2,bus=switch2_dp1,addr=00.0,serial=DATA_POOL_02
    -device x3130-upstream,id=switch3_up,bus=rp4,addr=00.0
    -device xio3130-downstream,id=switch3_dp0,bus=switch3_up,chassis=41,slot=0,addr=00.0,multifunction=on
    -device xio3130-downstream,id=switch3_dp1,bus=switch3_up,chassis=42,slot=1,addr=00.1
    -device e1000e,netdev=net1,bus=switch3_dp0,addr=00.0
    -device e1000e,netdev=net2,bus=switch3_dp1,addr=00.0
  )
fi

QEMU_ARGS+=(-kernel "$KERNEL_PATH")

if [[ "$PCIE_LS_CAPTURE" == "1" ]]; then
  "${QEMU_BIN}" "${QEMU_ARGS[@]}" > /tmp/zephyr_ai_qemu_stdout.log 2>&1 &
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

chunks = []
for _ in range(60):
    try:
        with socket.create_connection(("127.0.0.1", port), timeout=1.0) as sock:
            sock.settimeout(1.0)
            time.sleep(1)
            sock.sendall(b"pcie ls\n")
            end = time.time() + 10
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
    echo "Running Zephyr topology for ${RUN_TIMEOUT_SECONDS}s..."
    sleep "$RUN_TIMEOUT_SECONDS"
    cleanup
    echo "Trace capture finished after ${RUN_TIMEOUT_SECONDS}s"
    printf '\nTrace output written to %s\n' "$TRACE_LOG"
    exit 0
fi

wait "$QEMU_PID"
printf '\nTrace output written to %s\n' "$TRACE_LOG"
