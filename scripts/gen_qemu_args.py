#!/usr/bin/env python3
"""Generate QEMU -device arguments from a pcieshark topology JSON file."""

import argparse
import json
import sys
from typing import List, Optional


def bdf_to_addr(bdf: str) -> str:
    if not bdf:
        return "00.0"
    parts = bdf.replace(":", ".").split(".")
    if len(parts) >= 3:
        return f"{int(parts[1], 16):02x}.{int(parts[2], 16)}"
    if len(parts) == 2:
        try:
            return f"{int(parts[0], 16):02x}.{int(parts[1], 16)}"
        except ValueError:
            return bdf
    return bdf


def as_root_port(raw, index: int) -> dict:
    if isinstance(raw, str):
        return {
            "id": f"rp{index + 1}",
            "bdf": raw,
            "addr": bdf_to_addr(raw),
            "label": f"Root Port {index + 1}",
        }
    rp = dict(raw)
    rp.setdefault("id", f"rp{index + 1}")
    if "addr" not in rp:
        rp["addr"] = bdf_to_addr(rp.get("bdf", f"00:{index + 1:02x}.0"))
    if "bdf" not in rp:
        rp["bdf"] = f"00:{rp['addr']}"
    return rp


def add_opt(args: List[str], flag: str, value: str) -> None:
    """Append a QEMU option as two argv tokens so mapfile/QProcess keep them split."""
    args.append(flag)
    args.append(value)


def qemu_device_for_endpoint(ep: dict, netdev_id: Optional[str]) -> str:
    ep_type = str(ep.get("type", "")).upper()
    label = ep.get("label") or ep.get("display") or "ep"
    parent = ep.get("parent") or "pcie.0"
    serial = ep.get("serial") or label.replace(" ", "_")
    if any(tok in ep_type for tok in ("NIC", "ETH", "NET", "SMARTNIC")):
        if not netdev_id:
            raise RuntimeError(f"NIC endpoint {label} has no netdev")
        return f"e1000e,id={label},netdev={netdev_id},bus={parent},addr=00.0"
    if "VIRTIO" in ep_type:
        return f"virtio-net-pci,id={label},bus={parent},addr=00.0"
    return f"nvme,id={label},bus={parent},addr=00.0,serial={serial}"


def golden_topology() -> dict:
    """Built-in AI fabric used by both Zephyr and Linux QEMU runners."""
    return {
        "topology_name": "AI golden topology",
        "root_complexes": [
            {
                "domain": "0000",
                "root_bus": "00",
                "label": "CPU Complex",
                "root_ports": [
                    {"id": "rp1", "bdf": "00:01.0", "addr": "01.0", "label": "Compute Hub 1", "secondary_bus": "01"},
                    {"id": "rp2", "bdf": "00:01.1", "addr": "01.1", "label": "Compute Hub 2", "secondary_bus": "07"},
                    {"id": "rp3", "bdf": "00:01.2", "addr": "01.2", "label": "Storage Array 1", "secondary_bus": "13"},
                    {"id": "rp4", "bdf": "00:01.3", "addr": "01.3", "label": "Storage Array 2", "secondary_bus": "19"},
                ],
            }
        ],
        "switches": [
            {"name": "switch0", "parent": "rp1", "upstream_port": "01:00.0", "downstream_ports": ["02:00.0", "02:01.0"], "p2p_allowed": True},
            {"name": "switch1", "parent": "rp2", "upstream_port": "07:00.0", "downstream_ports": ["08:00.0", "08:01.0"], "p2p_allowed": True},
            {"name": "switch2", "parent": "rp3", "upstream_port": "13:00.0", "downstream_ports": ["14:00.0", "14:01.0"], "p2p_allowed": True},
            {"name": "switch3", "parent": "rp4", "upstream_port": "19:00.0", "downstream_ports": ["20:00.0", "20:01.0"], "p2p_allowed": True},
        ],
        "endpoints": [
            {"bdf": "03:00.0", "type": "GPU_ACCEL", "label": "ai1", "display": "GPU 1", "parent": "switch0_dp0", "serial": "AI_ACCEL_01", "peer_group": 1},
            {"bdf": "05:00.0", "type": "GPU_ACCEL", "label": "ai2", "display": "GPU 2", "parent": "switch0_dp1", "serial": "AI_ACCEL_02", "peer_group": 1},
            {"bdf": "09:00.0", "type": "GPU_ACCEL", "label": "ai3", "display": "GPU 3", "parent": "switch1_dp0", "serial": "AI_ACCEL_03", "peer_group": 2},
            {"bdf": "0b:00.0", "type": "GPU_ACCEL", "label": "ai4", "display": "GPU 4", "parent": "switch1_dp1", "serial": "AI_ACCEL_04", "peer_group": 2},
            {"bdf": "15:00.0", "type": "NVME", "label": "nvme1", "display": "NVMe 1", "parent": "switch2_dp0", "serial": "DATA_POOL_01"},
            {"bdf": "17:00.0", "type": "NVME", "label": "nvme2", "display": "NVMe 2", "parent": "switch2_dp1", "serial": "DATA_POOL_02"},
            {"bdf": "21:00.0", "type": "NIC_SMART", "label": "eth1", "display": "SmartNIC", "parent": "switch3_dp0"},
            {"bdf": "23:00.0", "type": "NIC_SMART", "label": "eth2", "display": "SmartNIC", "parent": "switch3_dp1"},
        ],
    }


def generate_args(data: dict) -> List[str]:
    args = []  # type: List[str]
    chassis = 1
    rp_ids: list[str] = []
    slot_ids: list[str] = []

    for rc in data.get("root_complexes", []):
        ports = rc.get("root_ports", [])
        for idx, raw in enumerate(ports):
            rp = as_root_port(raw, idx)
            rp_id = rp["id"]
            rp_ids.append(rp_id)
            mf = ",multifunction=on" if idx == 0 else ""
            add_opt(
                args,
                "-device",
                f"pcie-root-port,id={rp_id},bus=pcie.0,chassis={chassis},"
                f"slot={idx + 1},addr={rp['addr']}{mf}",
            )
            chassis += 1

    switches = data.get("switches", [])
    for idx, sw in enumerate(switches):
        name = sw.get("name") or f"switch{idx}"
        parent = sw.get("parent") or (rp_ids[idx] if idx < len(rp_ids) else (rp_ids[0] if rp_ids else "pcie.0"))
        up_id = name if name.endswith("_up") else f"{name}_up"
        add_opt(args, "-device", f"x3130-upstream,id={up_id},bus={parent},addr=00.0")
        dports = sw.get("downstream_ports", [])
        for d_idx, _dp in enumerate(dports):
            dp_id = f"{name}_dp{d_idx}"
            mf = ",multifunction=on" if d_idx == 0 else ""
            add_opt(
                args,
                "-device",
                f"xio3130-downstream,id={dp_id},bus={up_id},chassis={chassis},"
                f"slot={d_idx},addr=00.{d_idx}{mf}",
            )
            chassis += 1
            slot_ids.append(dp_id)

    if not slot_ids:
        slot_ids = list(rp_ids)

    nic_count = 0
    next_slot = 0
    for ep in data.get("endpoints", []):
        parent = ep.get("parent")
        if not parent:
            parent = slot_ids[next_slot % len(slot_ids)] if slot_ids else "pcie.0"
            next_slot += 1
            ep = dict(ep)
            ep["parent"] = parent
        ep_type = str(ep.get("type", "")).upper()
        netdev_id = None
        if any(tok in ep_type for tok in ("NIC", "ETH", "NET", "SMARTNIC")):
            nic_count += 1
            netdev_id = f"net{nic_count}"
            add_opt(args, "-netdev", f"user,id={netdev_id}")
        add_opt(args, "-device", qemu_device_for_endpoint(ep, netdev_id))

    return args


def main() -> int:
    parser = argparse.ArgumentParser(description="Emit QEMU PCIe topology args from JSON")
    parser.add_argument("json_path", nargs="?", help="optional topology JSON; omit with --builtin-golden")
    parser.add_argument("--builtin-golden", action="store_true", help="emit the built-in AI golden fabric")
    parser.add_argument("--oneline", action="store_true", help="print a single quoted command line")
    args = parser.parse_args()

    if args.builtin_golden:
        data = golden_topology()
    elif args.json_path:
        with open(args.json_path, "r", encoding="utf-8") as fh:
            data = json.load(fh)
    else:
        parser.error("provide a JSON path or --builtin-golden")

    qemu_args = generate_args(data)
    if args.oneline:
        print(" ".join(qemu_args))
    else:
        for item in qemu_args:
            print(item)
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception as exc:  # pragma: no cover
        print(f"gen_qemu_args: {exc}", file=sys.stderr)
        sys.exit(1)
