"""PCI enumerate helpers used by the Python Qt UI (dummy + Linux sysfs)."""

from __future__ import annotations

import os
from pathlib import Path

ENUM_ADDRS = (0x00, 0x04, 0x08, 0x0C, 0x10, 0x14, 0x18, 0x1C)


def _sysfs_config(bdf: str) -> Path:
    name = bdf if bdf.count(":") == 2 else f"0000:{bdf}"
    return Path("/sys/bus/pci/devices") / name / "config"


def read_config_dword(backend: str, bdf: str, offset: int) -> bytes:
    if backend == "pci":
        path = _sysfs_config(bdf)
        data = path.read_bytes()
        return data[offset:offset + 4].ljust(4, b"\x00")
    # dummy: deterministic vendor/device at 0x00
    if offset == 0x00:
        return bytes((0x36, 0x1B, 0x00, 0x00))
    if offset == 0x08:
        return bytes((0x00, 0x00, 0x00, 0x06))
    return bytes(4)


def device_summary(backend: str, bdf: str) -> str:
    try:
        dword0 = int.from_bytes(read_config_dword(backend, bdf, 0x00), "little")
        dword8 = int.from_bytes(read_config_dword(backend, bdf, 0x08), "little")
    except OSError as exc:
        raise RuntimeError(f"Unable to read {bdf}: {exc}") from exc
    vendor = dword0 & 0xFFFF
    device = (dword0 >> 16) & 0xFFFF
    rev = dword8 & 0xFF
    class_code = (dword8 >> 8) & 0xFFFFFF
    return f"Vendor 0x{vendor:04x} Device 0x{device:04x} Class 0x{class_code:06x} Rev 0x{rev:02x}"


def hex_payload(data: bytes) -> str:
    return " ".join(f"{b:02x}" for b in data)
