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


def qemu_device_for_endpoint(ep: dict, netdev_id: Optional[str]) -> str:
    ep_type = str(ep.get("type", "")).upper()
    label = ep.get("label") or ep.get("display") or "ep"
    parent = ep.get("parent") or "pcie.0"
    serial = ep.get("serial") or label.replace(" ", "_")
    if any(tok in ep_type for tok in ("NIC", "ETH", "NET", "SMARTNIC")):
        if not netdev_id:
            raise RuntimeError(f"NIC endpoint {label} has no netdev")
        return f"-device e1000e,id={label},netdev={netdev_id},bus={parent},addr=00.0"
    if "VIRTIO" in ep_type:
        return f"-device virtio-net-pci,id={label},bus={parent},addr=00.0"
    return f"-device nvme,id={label},bus={parent},addr=00.0,serial={serial}"


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
            args.append(
                f"-device pcie-root-port,id={rp_id},bus=pcie.0,chassis={chassis},"
                f"slot={idx + 1},addr={rp['addr']}{mf}"
            )
            chassis += 1

    switches = data.get("switches", [])
    for idx, sw in enumerate(switches):
        name = sw.get("name") or f"switch{idx}"
        parent = sw.get("parent") or (rp_ids[idx] if idx < len(rp_ids) else (rp_ids[0] if rp_ids else "pcie.0"))
        up_id = name if name.endswith("_up") else f"{name}_up"
        args.append(f"-device x3130-upstream,id={up_id},bus={parent},addr=00.0")
        dports = sw.get("downstream_ports", [])
        for d_idx, _dp in enumerate(dports):
            dp_id = f"{name}_dp{d_idx}"
            mf = ",multifunction=on" if d_idx == 0 else ""
            args.append(
                f"-device xio3130-downstream,id={dp_id},bus={up_id},chassis={chassis},"
                f"slot={d_idx},addr=00.{d_idx}{mf}"
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
            args.append(f"-netdev user,id={netdev_id}")
        args.append(qemu_device_for_endpoint(ep, netdev_id))

    return args


def main() -> int:
    parser = argparse.ArgumentParser(description="Emit QEMU PCIe topology args from JSON")
    parser.add_argument("json_path")
    parser.add_argument("--oneline", action="store_true", help="print a single quoted command line")
    args = parser.parse_args()

    with open(args.json_path, "r", encoding="utf-8") as fh:
        data = json.load(fh)

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
