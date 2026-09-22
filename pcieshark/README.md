# pcieshark

pcieshark is the PCIe trace analysis and inspection front-end for libpcapcie.
It gives the project a single product identity for both the command-line trace parser and the desktop GUI viewer.
<img width="1024" height="1024" alt="WhatsApp Image 2026-09-20 at 16 22 00" src="https://github.com/user-attachments/assets/52d818f8-3b58-4825-ae3f-2e46131066b4" />

## Purpose

The goal of pcieshark is to provide a simple, open, explainable way to:

- open PCIe trace files
- inspect TLP records in a packet-list view
- filter by direction, type, requester, and address
- summarize transaction counts and patterns
- build a GUI workflow that feels closer to Wireshark than to a proprietary vendor tool

This is especially useful for:

- PCIe bring-up and link validation
- debug and trace review
- compliance-oriented test runs
- offline analysis of captured TLP traffic

## Modes

pcieshark supports two entry points with the same product name:

1. CLI mode
   - best for scriptable analysis and quick summaries
   - usage: ./build/pcieshark /tmp/pcie_trace.csv
   - optional summary mode: ./build/pcieshark /tmp/pcie_trace.csv --summary

2. GUI mode
   - best for interactive trace review and filtering
   - launch from the desktop entry or from the GUI app alias
   - usage: ./build/gui/pcieshark

## Current workflow

A practical workflow is:

- capture or generate a CSV trace
- open it in pcieshark
- inspect direction, type, requester/completer IDs, address, and payload metadata
- filter rows to isolate specific transaction types
- export or archive the trace for later debugging or compliance review

## Example

```bash
cd /home/khadem/libpcapcie
cmake -S . -B build
cmake --build build
./build/pcieshark /tmp/pcie_trace.csv
```

For the GUI workflow:

```bash
./build/gui/pcieshark
```

## Relationship to libpcapcie

pcieshark is not a replacement for the library. It is the user-facing analysis layer built on top of libpcapcie.
The library creates and captures PCIe TLP data; pcieshark presents it in a readable, inspectable form.

This keeps the architecture clean:

- libpcapcie: core protocol and backend logic
- pcieshark: trace inspection and analysis experience
- future plugins or decoders: richer protocol interpretation and export paths

## Product direction

The eventual target is a lightweight, open-source PCIe analysis toolchain that is:

- open and scriptable
- trace-friendly
- suitable for offline review and compliance-style workflows
- easier to use than proprietary capture stacks
- extensible toward deeper packet decoding and export support

This makes pcieshark a practical OSS counterpart to closed vendor tooling, while still keeping the stack understandable and easy to extend.
