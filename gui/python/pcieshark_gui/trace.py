"""Trace parse, match analysis, CSV/pcap load, and HTML report."""

from __future__ import annotations

import csv
import io
import re
import struct
import time
from html import escape
from pathlib import Path
from typing import Iterable

PCI_CFG_RE = re.compile(
    r"^(?:(?P<ts>\d+(?:\.\d+)?)\s*:\s*)?pci_cfg_(?P<op>read|write)\s+"
    r"(?P<dev>[A-Za-z0-9_.-]+)\s+"
    r"(?P<bdf>(?:[0-9A-Fa-f]{4}:)?[0-9A-Fa-f]{2}:[0-9A-Fa-f]{2}\.[0-9A-Fa-f])\s+"
    r"@(?P<offset>0x[0-9A-Fa-f]+)\s*(?P<arrow>->|<-)\s*(?P<value>0x[0-9A-Fa-f]+)\s*$"
)

TYPE_NAMES = {"0": "MemRd", "1": "MemWr", "4": "CfgRd", "5": "CfgWr", "10": "Cpl"}
REQUEST_TYPES = {"CfgRd", "CfgRead", "MemRd", "MemRead"}
COMPLETION_TYPES = {"Cpl", "CplD", "Completion"}


def sanitize_type(value: str) -> str:
    v = value.strip()
    return TYPE_NAMES.get(v, v or "Unknown")


def normalize_dir(value: str) -> str:
    v = value.strip().upper()
    if v in {"TX", "1"}:
        return "TX"
    if v in {"RX", "2"}:
        return "RX"
    return v


def normalize_addr(value: str) -> str:
    text = value.strip().lower()
    if text.startswith("0x"):
        text = text[2:]
    return text.lstrip("0") or "0"


def parse_cfg_line(line: str) -> dict[str, str] | None:
    match = PCI_CFG_RE.match(line.strip())
    if not match:
        return None
    op = match.group("op")
    value = int(match.group("value"), 0)
    payload = " ".join(f"{(value >> (8 * i)) & 0xFF:02x}" for i in range(4))
    return {
        "ts": match.group("ts") or str(int(time.time() * 1000)),
        "direction": "TX" if op == "write" else "RX",
        "type": "CfgWr" if op == "write" else "CfgRd",
        "requester": match.group("dev"),
        "completer": match.group("bdf"),
        "tag": "0",
        "length": "4",
        "addr": match.group("offset"),
        "payload": payload,
        "match": "—",
        "pair": -1,
    }


def split_csv_line(line: str) -> list[str]:
    return next(csv.reader(io.StringIO(line)))


def load_rows(path: str) -> list[dict[str, str | int]]:
    raw = Path(path).read_bytes()
    if len(raw) >= 4 and raw[:4] in (b"\xd4\xc3\xb2\xa1", b"\xa1\xb2\xc3\xd4"):
        rows = _load_pcap(raw)
        if rows:
            return rows
    text = raw.decode("utf-8", errors="replace")
    lines = text.splitlines()
    is_csv = any("," in line and "timestamp" in line.lower() for line in lines if line.strip())
    rows: list[dict[str, str | int]] = []
    for line in lines:
        line = line.strip()
        if not line:
            continue
        if is_csv:
            if line.lower().startswith("timestamp"):
                continue
            fields = split_csv_line(line)
            if len(fields) < 9:
                continue
            rows.append({
                "ts": fields[0].strip(),
                "direction": normalize_dir(fields[1]),
                "type": sanitize_type(fields[2]),
                "requester": fields[3].strip(),
                "completer": fields[4].strip(),
                "tag": fields[5].strip(),
                "length": fields[6].strip(),
                "addr": fields[7].strip(),
                "payload": fields[8].strip(),
                "match": "—",
                "pair": -1,
            })
            continue
        parsed = parse_cfg_line(line)
        if parsed:
            rows.append(parsed)
    analyze(rows)
    return rows


def _load_pcap(data: bytes) -> list[dict[str, str | int]]:
    magic = struct.unpack_from("<I", data, 0)[0]
    if magic not in (0xA1B2C3D4, 0xD4C3B2A1):
        return []
    off = 24
    rows: list[dict[str, str | int]] = []
    while off + 16 <= len(data):
        ts_sec, ts_usec, incl_len, _ = struct.unpack_from("<IIII", data, off)
        off += 16
        body = data[off:off + incl_len]
        off += incl_len
        if len(body) < 20:
            break
        direction, type_code = body[0], body[1]
        requester, completer = struct.unpack_from("<HH", body, 2)
        tag = body[6]
        length = struct.unpack_from("<H", body, 7)[0]
        addr = struct.unpack_from("<Q", body, 9)[0]
        payload = body[17:17 + (length or 0)]
        rows.append({
            "ts": str(ts_sec * 1_000_000_000 + ts_usec * 1000),
            "direction": "RX" if direction == 2 else "TX",
            "type": sanitize_type(str(type_code)),
            "requester": str(requester),
            "completer": str(completer),
            "tag": str(tag),
            "length": str(length),
            "addr": hex(addr),
            "payload": " ".join(f"{b:02x}" for b in payload),
            "match": "—",
            "pair": -1,
        })
    analyze(rows)
    return rows


def analyze(rows: list[dict[str, str | int]]) -> None:
    pending: list[int] = []
    for i, row in enumerate(rows):
        row["match"] = "—"
        row["pair"] = -1
        kind = str(row["type"])
        if kind in REQUEST_TYPES:
            if str(row["payload"]).strip():
                row["match"] = "complete"
                continue
            pending.append(i)
            continue
        if kind not in COMPLETION_TYPES:
            continue
        match = -1
        for p, req_i in enumerate(pending):
            req = rows[req_i]
            if str(req["tag"]) != str(row["tag"]):
                continue
            ra, ca = normalize_addr(str(req["addr"])), normalize_addr(str(row["addr"]))
            if ra and ca and ra != ca:
                continue
            match = req_i
            del pending[p]
            break
        if match < 0:
            continue
        rows[match]["match"] = f"#{i + 1}"
        rows[match]["pair"] = i
        row["match"] = f"#{match + 1}"
        row["pair"] = match
    for req_i in pending:
        rows[req_i]["match"] = "unmatched"


def save_csv(path: str, rows: Iterable[dict[str, str | int]]) -> None:
    as_log = path.lower().endswith((".log", ".txt"))
    with open(path, "w", encoding="utf-8") as fh:
        if not as_log:
            fh.write("timestamp_ns,direction,type,requester_id,completer_id,tag,length,addr,payload\n")
        for row in rows:
            if as_log:
                if not row["addr"]:
                    continue
                op = "write" if row["type"] == "CfgWr" or row["direction"] == "TX" else "read"
                arrow = "<-" if op == "write" else "->"
                fh.write(f"pci_cfg_{op} {row['requester']} {row['completer']} @{row['addr']} {arrow} {row['payload']}\n")
                continue
            payload = str(row["payload"]).replace('"', '""')
            if "," in payload or '"' in payload:
                payload = f'"{payload}"'
            fh.write(
                f"{row['ts']},{row['direction']},{row['type']},{row['requester']},"
                f"{row['completer']},{row['tag']},{row['length']},{row['addr']},{payload}\n"
            )


def export_report(path: str, rows: list[dict[str, str | int]], topology_name: str = "") -> None:
    tx = sum(1 for r in rows if r["direction"] == "TX")
    rx = sum(1 for r in rows if r["direction"] == "RX")
    cfg_rd = sum(1 for r in rows if str(r["type"]) in {"CfgRd", "CfgRead"})
    cfg_wr = sum(1 for r in rows if str(r["type"]) in {"CfgWr", "CfgWrite"})
    mem_rd = sum(1 for r in rows if str(r["type"]) in {"MemRd", "MemRead"})
    mem_wr = sum(1 for r in rows if str(r["type"]) in {"MemWr", "MemWrite"})
    cpl = sum(1 for r in rows if str(r["type"]) in COMPLETION_TYPES)
    matched = sum(1 for r in rows if str(r["match"]).startswith("#")) // 2
    complete = sum(1 for r in rows if r["match"] == "complete")
    unmatched = sum(1 for r in rows if r["match"] == "unmatched")
    devices = []
    for r in rows:
        if normalize_addr(str(r["addr"])) == "0" and str(r["payload"]).strip():
            devices.append(f"<tr><td>{escape(str(r['completer']))}</td><td>{escape(str(r['payload']))}</td></tr>")
    device_rows = "".join(dict.fromkeys(devices)) or "<tr><td colspan='2'>No vendor/device DWORDs at offset 0x00.</td></tr>"
    html = f"""<!DOCTYPE html><html><head><meta charset='utf-8'><title>pcieshark analysis report</title>
<style>body{{font-family:system-ui,sans-serif;margin:32px;color:#111}}table{{border-collapse:collapse;margin:12px 0}}td,th{{border:1px solid #ccc;padding:6px 10px}}th{{background:#f3f4f6}}.muted{{color:#555}}</style>
</head><body><h1>pcieshark analysis report</h1>
<p class='muted'>Topology: {escape(topology_name or 'open trace')}</p>
<h2>Summary</h2>
<table>
<tr><th>Total</th><td>{len(rows)}</td></tr>
<tr><th>TX / RX</th><td>{tx} / {rx}</td></tr>
<tr><th>CfgRd / CfgWr</th><td>{cfg_rd} / {cfg_wr}</td></tr>
<tr><th>MemRd / MemWr</th><td>{mem_rd} / {mem_wr}</td></tr>
<tr><th>Completions</th><td>{cpl}</td></tr>
<tr><th>Matched pairs</th><td>{matched}</td></tr>
<tr><th>Complete (in-line)</th><td>{complete}</td></tr>
<tr><th>Unmatched</th><td>{unmatched}</td></tr>
</table>
<p class='muted'>Match: #N = request/completion pair. complete = QEMU one-line config access. unmatched = missing Cpl.</p>
<h2>Devices seen (config offset 0x00)</h2>
<table><tr><th>BDF</th><th>Payload</th></tr>{device_rows}</table>
<h2>Unmatched requests</h2>
<p>{"No unmatched requests." if unmatched == 0 else f"{unmatched} unmatched request(s)."}</p>
</body></html>"""
    Path(path).write_text(html, encoding="utf-8")


def hex_dump(payload: str) -> str:
    hexed = re.sub(r"\s+", "", payload)
    if not hexed:
        return "<no payload>"
    try:
        data = bytes.fromhex(hexed)
    except ValueError:
        return f"{payload}\n<not valid hex payload>"
    lines = []
    for i in range(0, len(data), 16):
        chunk = data[i:i + 16]
        hx = " ".join(f"{b:02x}" for b in chunk)
        ascii_ = "".join(chr(b) if 32 <= b <= 126 else "." for b in chunk)
        lines.append(f"{i:04x}  {hx:<48}  {ascii_}")
    return "\n".join(lines)


def parse_pci_id(value: str) -> int:
    text = value.strip()
    if re.fullmatch(r"[0-9A-Fa-f]{2}:[0-9A-Fa-f]{2}\.[0-9A-Fa-f]", text):
        bus, rest = text.split(":")
        dev, fn = rest.split(".")
        return (int(bus, 16) << 8) | (int(dev, 16) << 3) | int(fn, 16)
    try:
        return int(text, 0) & 0xFFFF
    except ValueError:
        return 0


def vendor_name(vid: int) -> str:
    return {0x10EC: "Realtek", 0x8086: "Intel", 0x1AF4: "Red Hat, Inc.", 0x1B36: "Red Hat, Inc.",
            0x10DE: "NVIDIA", 0x104C: "Texas Instruments"}.get(vid, "Unknown vendor")


def class_name(code: int) -> str:
    full = code if code > 0xFFFF else code << 8
    return {0x020000: "Ethernet controller", 0x010802: "Non-Volatile memory controller",
            0x060000: "Host bridge", 0x060400: "PCI bridge"}.get(full, "Unknown class")
