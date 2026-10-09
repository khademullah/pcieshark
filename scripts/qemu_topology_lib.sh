# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (c) 2026 Khadem Ullah

# Shared golden PCIe fabric + QEMU trace helpers.
# Sourced by Zephyr / Linux runners and capture→TLP2HDL scripts.

append_golden_fabric() {
    QEMU_ARGS+=(
        -device pcie-root-port,id=rp1,bus=pcie.0,chassis=1,slot=1,addr=01.0,multifunction=on
        -device pcie-root-port,id=rp2,bus=pcie.0,chassis=2,slot=2,addr=01.1
        -device pcie-root-port,id=rp3,bus=pcie.0,chassis=3,slot=3,addr=01.2
        -device pcie-root-port,id=rp4,bus=pcie.0,chassis=4,slot=4,addr=01.3
        -device x3130-upstream,id=switch0_up,bus=rp1,addr=00.0
        -device xio3130-downstream,id=switch0_dp0,bus=switch0_up,chassis=5,slot=0,addr=00.0,multifunction=on
        -device xio3130-downstream,id=switch0_dp1,bus=switch0_up,chassis=6,slot=1,addr=00.1
        -device x3130-upstream,id=switch1_up,bus=rp2,addr=00.0
        -device xio3130-downstream,id=switch1_dp0,bus=switch1_up,chassis=7,slot=0,addr=00.0,multifunction=on
        -device xio3130-downstream,id=switch1_dp1,bus=switch1_up,chassis=8,slot=1,addr=00.1
        -device x3130-upstream,id=switch2_up,bus=rp3,addr=00.0
        -device xio3130-downstream,id=switch2_dp0,bus=switch2_up,chassis=9,slot=0,addr=00.0,multifunction=on
        -device xio3130-downstream,id=switch2_dp1,bus=switch2_up,chassis=10,slot=1,addr=00.1
        -device x3130-upstream,id=switch3_up,bus=rp4,addr=00.0
        -device xio3130-downstream,id=switch3_dp0,bus=switch3_up,chassis=11,slot=0,addr=00.0,multifunction=on
        -device xio3130-downstream,id=switch3_dp1,bus=switch3_up,chassis=12,slot=1,addr=00.1
        -device nvme,id=ai1,bus=switch0_dp0,addr=00.0,serial=AI_ACCEL_01
        -device nvme,id=ai2,bus=switch0_dp1,addr=00.0,serial=AI_ACCEL_02
        -device nvme,id=ai3,bus=switch1_dp0,addr=00.0,serial=AI_ACCEL_03
        -device nvme,id=ai4,bus=switch1_dp1,addr=00.0,serial=AI_ACCEL_04
        -device nvme,id=nvme1,bus=switch2_dp0,addr=00.0,serial=DATA_POOL_01
        -device nvme,id=nvme2,bus=switch2_dp1,addr=00.0,serial=DATA_POOL_02
        -netdev user,id=net1
        -device e1000e,id=eth1,netdev=net1,bus=switch3_dp0,addr=00.0
        -netdev user,id=net2
        -device e1000e,id=eth2,netdev=net2,bus=switch3_dp1,addr=00.0
    )
}

# Build QEMU -trace args.
#   QEMU_TRACE=...     full override (space/comma separated patterns)
#   CAPTURE_MEM=1      also enable memory_region_ops_{read,write} (noisy MMIO)
# Default: pci_cfg_* only (config-space TLPs).
qemu_trace_patterns() {
    local patterns=()
    local tok
    if [[ -n "${QEMU_TRACE:-}" ]]; then
        # shellcheck disable=SC2206
        IFS=', ' read -r -a patterns <<< "${QEMU_TRACE}"
    else
        patterns=(pci_cfg_*)
        if [[ "${CAPTURE_MEM:-0}" == "1" ]]; then
            patterns+=(memory_region_ops_read memory_region_ops_write)
        fi
    fi
    QEMU_TRACE_ARGS=()
    for tok in "${patterns[@]}"; do
        [[ -z "$tok" ]] && continue
        QEMU_TRACE_ARGS+=(-trace "$tok")
    done
}

print_qemu_trace_summary() {
    qemu_trace_patterns
    printf 'QEMU traces:'
    local a
    for a in "${QEMU_TRACE_ARGS[@]}"; do
        [[ "$a" == "-trace" ]] && continue
        printf ' %s' "$a"
    done
    printf '\n'
    if [[ "${CAPTURE_MEM:-0}" == "1" ]] || [[ "${QEMU_TRACE:-}" == *memory_region_ops* ]]; then
        printf 'Note: memory_region_ops_* is noisy; filter by region name when exporting CSV.\n'
    fi
}
