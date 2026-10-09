#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (c) 2026 Khadem Ullah

"""Export QEMU / pcieshark logs to TLP CSV for TLP2HDL.

Supports pci_cfg_* and memory_region_ops_* lines (and existing CSV).

Examples:
  python3 scripts/export_trace_csv.py zephyr_ai_topology_trace.log -o out.csv
  python3 scripts/export_trace_csv.py capture.log -o mem.csv --types MemRd,MemWr
  python3 scripts/export_trace_csv.py capture.log -o nvme.csv --name-filter nvme
"""
from __future__ import annotations

import argparse
import sys
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "gui" / "python"))

from pcieshark_gui.trace import load_rows, save_csv  # noqa: E402


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("input", type=Path, help="QEMU log or CSV")
    ap.add_argument("-o", "--output", type=Path, required=True, help="output CSV path")
    ap.add_argument(
        "--types",
        default="",
        help="comma list to keep, e.g. MemRd,MemWr,CfgRd,CfgWr,Cpl (default: all)",
    )
    ap.add_argument(
        "--name-filter",
        default="",
        help="comma substrings; keep if completer/requester matches any",
    )
    ap.add_argument(
        "--exclude-name",
        default="",
        help="comma substrings to drop (e.g. pl011,gicv3)",
    )
    ap.add_argument("--max", type=int, default=0, help="cap rows after filter (0=all)")
    ap.add_argument("-q", "--quiet", action="store_true")
    args = ap.parse_args()

    if not args.input.is_file():
        print(f"missing input: {args.input}", file=sys.stderr)
        return 1

    rows = load_rows(str(args.input))
    keep_types = {t.strip() for t in args.types.split(",") if t.strip()}
    name_keep = [s.strip().lower() for s in args.name_filter.split(",") if s.strip()]
    name_drop = [s.strip().lower() for s in args.exclude_name.split(",") if s.strip()]

    filtered = []
    for r in rows:
        kind = str(r["type"])
        if keep_types and kind not in keep_types:
            continue
        blob = f"{r.get('completer', '')} {r.get('requester', '')}".lower()
        if name_drop and any(x in blob for x in name_drop):
            continue
        if name_keep and not any(x in blob for x in name_keep):
            continue
        filtered.append(r)

    if args.max > 0:
        filtered = filtered[: args.max]

    args.output.parent.mkdir(parents=True, exist_ok=True)
    save_csv(str(args.output), filtered)

    counts = Counter(str(r["type"]) for r in filtered)
    match_c = Counter(str(r.get("match", "—")) for r in filtered)
    if not args.quiet:
        print(f"wrote {args.output}  rows={len(filtered)}")
        print("types:", dict(counts))
        print("match:", {k: v for k, v in match_c.items() if k != "—" or v})
    return 0 if filtered else 2


if __name__ == "__main__":
    raise SystemExit(main())
