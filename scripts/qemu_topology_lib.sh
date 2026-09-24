# Shared golden PCIe fabric. Sourced by the Zephyr and Linux runners.
# These tokens match the verified qemu-system-x86_64 command.

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
