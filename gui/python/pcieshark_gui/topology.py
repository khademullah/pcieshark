"""Golden fabric and in-process lspci / diagram helpers."""

from __future__ import annotations

from html import escape
from typing import Any


def golden_topology() -> dict[str, Any]:
    return {
        "topology_name": "AI golden topology",
        "root_complexes": [{
            "domain": "0000",
            "root_bus": "00",
            "label": "CPU Complex",
            "root_ports": [
                {"id": "rp1", "bdf": "00:01.0", "addr": "01.0", "label": "Compute Hub 1", "secondary_bus": "01"},
                {"id": "rp2", "bdf": "00:01.1", "addr": "01.1", "label": "Compute Hub 2", "secondary_bus": "07"},
                {"id": "rp3", "bdf": "00:01.2", "addr": "01.2", "label": "Storage Array 1", "secondary_bus": "13"},
                {"id": "rp4", "bdf": "00:01.3", "addr": "01.3", "label": "Storage Array 2", "secondary_bus": "19"},
            ],
        }],
        "switches": [
            {"name": "switch0", "parent": "rp1", "upstream_port": "01:00.0", "downstream_ports": ["02:00.0", "02:01.0"]},
            {"name": "switch1", "parent": "rp2", "upstream_port": "07:00.0", "downstream_ports": ["08:00.0", "08:01.0"]},
            {"name": "switch2", "parent": "rp3", "upstream_port": "13:00.0", "downstream_ports": ["14:00.0", "14:01.0"]},
            {"name": "switch3", "parent": "rp4", "upstream_port": "19:00.0", "downstream_ports": ["20:00.0", "20:01.0"]},
        ],
        "endpoints": [
            {"bdf": "03:00.0", "type": "GPU_ACCEL", "label": "ai1", "display": "GPU 1", "parent": "switch0_dp0"},
            {"bdf": "05:00.0", "type": "GPU_ACCEL", "label": "ai2", "display": "GPU 2", "parent": "switch0_dp1"},
            {"bdf": "09:00.0", "type": "GPU_ACCEL", "label": "ai3", "display": "GPU 3", "parent": "switch1_dp0"},
            {"bdf": "0b:00.0", "type": "GPU_ACCEL", "label": "ai4", "display": "GPU 4", "parent": "switch1_dp1"},
            {"bdf": "15:00.0", "type": "NVME", "label": "nvme1", "display": "NVMe 1", "parent": "switch2_dp0"},
            {"bdf": "17:00.0", "type": "NVME", "label": "nvme2", "display": "NVMe 2", "parent": "switch2_dp1"},
            {"bdf": "21:00.0", "type": "NIC_SMART", "label": "eth1", "display": "SmartNIC", "parent": "switch3_dp0"},
            {"bdf": "23:00.0", "type": "NIC_SMART", "label": "eth2", "display": "SmartNIC", "parent": "switch3_dp1"},
        ],
    }


def generate_topology(root_ports: int, endpoints_per_root: int) -> dict[str, Any]:
    types = ["GPU_ACCEL", "NVME", "NIC_SMART"]
    rps = []
    switches = []
    endpoints = []
    ep_index = 0
    for i in range(root_ports):
        dev = 1 + (i // 8)
        fn = i % 8
        rps.append({
            "id": f"rp{i + 1}",
            "addr": f"{dev:02x}.{fn}",
            "bdf": f"00:{dev:02x}.{fn}",
            "label": f"Root Port {i + 1}",
        })
        name = f"switch{i}"
        dps = []
        for e in range(endpoints_per_root):
            dps.append(f"{i + 2:02x}:{e:02x}.0")
            kind = types[ep_index % 3]
            endpoints.append({
                "type": kind,
                "label": f"ep{ep_index}",
                "display": f"{kind} {ep_index}",
                "parent": f"{name}_dp{e}",
                "bdf": f"{8 + ep_index:02x}:00.0",
            })
            ep_index += 1
        switches.append({
            "name": name,
            "parent": f"rp{i + 1}",
            "upstream_port": f"{i + 1:02x}:00.0",
            "downstream_ports": dps,
        })
    return {
        "topology_name": f"custom {root_ports} root ports x {endpoints_per_root} endpoints",
        "root_complexes": [{"domain": "0000", "root_bus": "00", "label": "CPU Complex", "root_ports": rps}],
        "switches": switches,
        "endpoints": endpoints,
    }


def topology_nodes(topo: dict[str, Any]) -> list[tuple[str, str]]:
    nodes: list[tuple[str, str]] = []
    for rc in topo.get("root_complexes", []):
        for i, port in enumerate(rc.get("root_ports", [])):
            if isinstance(port, str):
                nodes.append((port, f"rp{i + 1}"))
            else:
                nodes.append((port.get("bdf", ""), port.get("id", "root-port")))
    for sw in topo.get("switches", []):
        name = sw.get("name", "switch")
        nodes.append((sw.get("upstream_port", ""), name))
        for d, dp in enumerate(sw.get("downstream_ports", [])):
            nodes.append((dp, f"{name}_dp{d}"))
    for ep in topo.get("endpoints", []):
        nodes.append((ep.get("bdf", ""), ep.get("label") or ep.get("display") or "endpoint"))
    return nodes


def _cell(title: str, sub: str, body: str, accent: str = "#64748b") -> str:
    return (
        "<td align='center' width='25%' "
        f"style='border:1px solid {accent};padding:10px 8px;vertical-align:top;min-width:140px;'>"
        f"<p style='font-weight:700;margin:0;'>[ {escape(title)} ]</p>"
        f"<p style='font-size:12px;margin:4px 0 0 0;color:#94a3b8;'>{escape(sub)}</p>"
        f"<p style='margin:4px 0 0 0;'>{escape(body)}</p></td>"
    )


def _wrap(cells: list[str], per_row: int = 4) -> str:
    if not cells:
        return ""
    html: list[str] = []
    for i in range(0, len(cells), per_row):
        chunk = cells[i:i + per_row]
        while len(chunk) < per_row:
            chunk.append("<td width='25%'></td>")
        html.append(
            "<table width='100%' cellspacing='8' cellpadding='0'>"
            f"<tr>{''.join(chunk)}</tr></table>"
        )
    return "".join(html)


def topology_html(topo: dict[str, Any]) -> str:
    name = topo.get("topology_name", "unnamed topology")
    rc_label = "CPU Complex"
    bus_label = "PCIe Bus 00"
    rp_cells: list[str] = []
    sw_cells: list[str] = []
    dp_cells: list[str] = []
    ep_cells: list[str] = []

    for rc in topo.get("root_complexes", []):
        rc_label = rc.get("label") or rc_label
        if rc.get("root_bus"):
            bus_label = f"PCIe Bus {rc['root_bus']}"
        for i, port in enumerate(rc.get("root_ports", [])):
            if isinstance(port, str):
                rp_cells.append(_cell(f"rp{i + 1}", port, "root port", "#60a5fa"))
            else:
                sub = port.get("bdf") or port.get("addr") or ""
                if port.get("secondary_bus"):
                    sub += f"  Bus {port['secondary_bus']}"
                rp_cells.append(_cell(port.get("id", f"rp{i + 1}"), sub, port.get("label", ""), "#60a5fa"))

    for sw in topo.get("switches", []):
        name_sw = sw.get("name", "switch")
        sw_cells.append(_cell(f"{name_sw}_up", sw.get("upstream_port", ""), sw.get("parent", ""), "#94a3b8"))
        for d, dp in enumerate(sw.get("downstream_ports", [])):
            dp_cells.append(_cell(f"{name_sw} dp{d}", dp, "downstream", "#7dd3fc"))

    for ep in topo.get("endpoints", []):
        kind = str(ep.get("type", "")).upper()
        if "GPU" in kind or "ACCEL" in kind:
            accent = "#3b82f6"
        elif "NVME" in kind or "STOR" in kind:
            accent = "#10b981"
        elif "NIC" in kind or "ETH" in kind or "NET" in kind:
            accent = "#f59e0b"
        else:
            accent = "#64748b"
        display = ep.get("display") or ep.get("label") or "endpoint"
        ep_cells.append(_cell(display, ep.get("bdf") or kind, ep.get("label", ""), accent))

    return (
        "<html><body style='background:#0f1117;color:#e7ebf3;"
        "font-family:\"Noto Sans Mono\",\"DejaVu Sans Mono\",monospace;'>"
        "<div style='padding:10px;'>"
        f"<p align='center' style='font-weight:700;font-size:18px;margin:8px;'>[ {escape(rc_label)} ]</p>"
        f"<p align='center' style='font-size:14px;margin:0 0 4px 0;'>[ {escape(bus_label)} ]</p>"
        f"<p align='center' style='font-size:12px;color:#94a3b8;margin:0 0 10px 0;'>{escape(name)}</p>"
        f"{_wrap(rp_cells)}"
        "<hr style='border:1px solid #334155;margin:12px 0;'>"
        f"{_wrap(sw_cells)}{_wrap(dp_cells)}{_wrap(ep_cells)}"
        "</div></body></html>"
    )


def _identity(kind: str) -> tuple[int, int, int, str]:
    r = kind.lower()
    if any(tok in r for tok in ("eth", "nic", "e1000")):
        return 0x8086, 0x10d3, 0x020000, "82574L Gigabit Network Connection"
    if any(tok in r for tok in ("nvme", "ai", "gpu")):
        return 0x1b36, 0x0010, 0x010802, "QEMU NVMe Ctrl"
    if "dp" in r or "down" in r:
        return 0x8086, 0x3438, 0x060400, "XIO3130 Downstream Port"
    if "switch" in r or r.endswith("up"):
        return 0x8086, 0x3432, 0x060400, "XIO3130 Upstream Port"
    if any(tok in r for tok in ("rp", "root", "hub")):
        return 0x1b36, 0x000c, 0x060400, "QEMU PCIe Root port"
    return 0x1b36, 0x0001, 0x060000, "QEMU PCI device"


def _class_name(class_code: int) -> str:
    return {
        0x020000: "Ethernet controller",
        0x010802: "Non-Volatile memory controller",
        0x060000: "Host bridge",
        0x060400: "PCI bridge",
    }.get(class_code, "Unknown class")


def lspci_line(bdf: str, kind: str, note: str = "") -> str:
    vendor, device, class_code, product = _identity(kind)
    extra = f"  {note}" if note else ""
    return (
        f"{bdf} {_class_name(class_code)} [{(class_code >> 8) & 0xffff:04x}]: "
        f"{product} [{vendor:04x}:{device:04x}]{extra}"
    )


def format_pci_list(topo: dict[str, Any]) -> str:
    lines = [
        f"# {topo.get('topology_name', 'topology')}",
        "# lspci -nn listing of the emulated fabric",
        "# This view is built from the topology. A Linux guest image is not required.",
        "",
        "00:00.0 Host bridge [0600]: Red Hat, Inc. QEMU Host Bridge [1b36:0008]",
    ]
    for rc in topo.get("root_complexes", []):
        for i, port in enumerate(rc.get("root_ports", [])):
            if isinstance(port, str):
                lines.append(lspci_line(port, "root-port", f"rp{i + 1}"))
            else:
                lines.append(lspci_line(port.get("bdf", ""), "root-port", port.get("label") or port.get("id", "")))
    for sw in topo.get("switches", []):
        name = sw.get("name", "switch")
        lines.append(lspci_line(sw.get("upstream_port", ""), "switch-up", name))
        for d, dp in enumerate(sw.get("downstream_ports", [])):
            lines.append(lspci_line(dp, "switch-dp", f"{name}_dp{d}"))
    for ep in topo.get("endpoints", []):
        lines.append(lspci_line(ep.get("bdf", ""), ep.get("type", "ep"), ep.get("label") or ep.get("display", "")))
    return "\n".join(lines)


def synthetic_dword(role: str, offset: int) -> int:
    vendor, device, class_code, _ = _identity(role)
    header = 0x01 if class_code == 0x060400 else 0x00
    if offset == 0x00:
        return vendor | (device << 16)
    if offset == 0x04:
        return 0x00100006
    if offset == 0x08:
        return class_code << 8
    if offset == 0x0C:
        return header << 16
    if offset == 0x10:
        return 0 if header else 0xFFFF0004
    return 0


def le_dword_payload(value: int) -> str:
    return " ".join(f"{(value >> (8 * i)) & 0xFF:02x}" for i in range(4))
