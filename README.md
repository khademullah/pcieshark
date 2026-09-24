<p align="center">
  <img src="docs/assets/logo.png" alt="pcieshark" width="180">
</p>

<h1 align="center">pcieshark</h1>

<p align="center">
  Open PCIe trace, enumeration, and analysis toolkit
</p>

pcieshark is a developer-facing toolkit for building, inspecting, and validating PCIe traffic. It combines a reusable C library (`libpcapcie`), example programs, a Qt GUI, and Zephyr or Linux QEMU topology flows so the same stack works on real hardware and emulated fabrics.

It is designed to be:

- open and inspectable
- backend-driven and portable
- useful on both real devices and emulated PCIe topologies
- buildable with a standard CMake workflow

## Demo

Watch the AI PCIe emulator walkthrough and the PCIe trace/performance workflow:

![AI PCIe Emulator Demo](AI_PCIe_Emulator_optimized.gif)

[Download MP4 demo](AI_PCIe_Emulator_optimized.mp4)

The demo covers live TLP viewing, AI topology enumeration, the golden fabric layout, and runtime performance status.

## Why this project exists

PCIe bring-up usually needs a mix of raw trace inspection, config-space enumeration, protocol decode, and link-performance checks. pcieshark gives those workflows a practical foundation without a closed vendor stack:

- direct PCIe backend access
- high-level TLP create/parse/filter
- GUI review of live or captured traces
- optional Zephyr or Linux QEMU topology for enumeration experiments

## Core features

- PCIe TLP creation and parsing
- Configuration-space read/write
- TLP filtering and sniffing hooks
- Link and topology inspection
- Backends for PCI, dummy, FPGA, ARM DS, and similar targets
- Trace capture and export (pcap-style or CSV)
- Qt GUI for live or offline packet browsing
- Zephyr and Linux QEMU topology execution for enumeration-style work
- Built-in golden AI fabric shared by both guests

## Repository structure

- `src/` — core library and backend implementations
- `include/pcapcie/` — public library headers
- `include/pcie_topology.h` — topology model used by the emulator
- `examples/` — CLI tools for TLP, link, capture, and topology flows
- `gui/` — Qt desktop application
- `scripts/` — QEMU helpers for Zephyr and Linux guests
- `pcieshark/` — product notes for the CLI and GUI front-end
- `docs/assets/` — project artwork

## Supported workflows

1. **Trace-only** — open a captured file, inspect TLPs, filter by direction, type, or identifier.
2. **Live trace** — run the Zephyr or Linux QEMU topology, collect config-space traffic, review packets in real time.
3. **PCI enumeration** — use a backend to inspect a target device and validate reported link information.
4. **Experimental topology** — run an emulated AI fabric, inspect enumeration, keep that path separate from the main TLP stream.

## Requirements

- Linux
- CMake 3.13+
- C/C++ toolchain
- Qt 6 development libraries for the GUI
- Zephyr SDK and a kernel image for the Zephyr topology flow, or a Linux disk/kernel image for the Linux QEMU flow

### Zephyr-backed emulation

```bash
source ~/zephyrproject/.venv/bin/activate
export ZEPHYR_BASE=~/zephyrproject/zephyr
export ZEPHYR_TOOLCHAIN_VARIANT=zephyr
export ZEPHYR_SDK_INSTALL_DIR=$HOME/zephyr-sdk-1.0.1
```

Point `KERNEL_PATH` at a built Zephyr image if it is not already available as `build/zephyr/zephyr.elf`.

## Quick start

### 1. Clone and configure

```bash
git clone git@github.com:khademullah/pcieshark.git
cd pcieshark
cmake -S . -B build
```

### 2. Build

```bash
cmake --build build -j$(nproc)
```

### 3. Launch the GUI

Run these from the repository root, not from `build/`:

```bash
./run_pcieshark.sh
# or
./build/gui/pcieshark
```

If you are already inside `build/`, the binary is `./gui/pcieshark`.

After renaming this tree (for example from `libpcapcie` to `pcieshark`), reconfigure before calling `make` again:

```bash
cmake -S . -B build
cmake --build build -j$(nproc)
```

The GUI can open and save traces, show packet details, filter rows, and run topology-related enumeration workflows.

## Build targets

```bash
./build/pcieshark
./build/enumerate_topology
./build/pci_link_check
./build/pci_link_matrix
./build/pci_link_status
./build/simple_tlp_test
./build/tlp_capture
./build/gui/pcieshark
```

## Trace workflow

- **Open** a captured trace in the GUI and inspect packets in the table view.
- **Save** the active trace for later comparison or replay.
- **Inspect a row** for timestamp, direction, TLP type, requester ID, and payload metadata.

CLI mode uses the same product name:

```bash
./build/pcieshark /tmp/pcie_trace.csv
./build/pcieshark /tmp/pcie_trace.csv --summary
```

## AI PCIe emulator

The emulator models a data-center style PCIe fabric for accelerator-heavy systems, not just a dummy traffic generator. The same view supports enumeration, trace capture, and performance measurement.

Typical fabric:

- CPU complex as the root domain
- four root ports, one fabric branch each
- upstream switch hierarchy per branch
- NVMe endpoints for storage
- GPU-like accelerator endpoints
- SmartNIC / network endpoints

### Golden AI topology

The default preset is a built-in deterministic fabric:

- root bus: `PCIe Bus 00`
- root ports: `rp1` … `rp4`
- switches with downstream ports `dp0` / `dp1`
- endpoints: GPU 1–4, NVMe 1–2, SmartNIC 1–2, plus per-branch data-path devices

This layout is intentionally fixed so benchmarks and traces stay comparable.

### Enumeration flow

1. Launch the Zephyr or Linux QEMU topology.
2. Boot the guest with the PCIe fabric model.
3. Enumerate the topology from the guest (`pcie ls` on Zephyr, `lspci` on Linux).
4. Collect bus/device information into a structured log.
5. Parse that list into a PCIe map for the GUI and analysis tools.

The guest PCI-list path stays isolated from the main TLP stream so enumeration logs do not overwrite performance or capture runs.

### Performance model

Configurable workload parameters include root ports, endpoints per root, buses, iterations, latency, tokens/sec, burst size, jitter, and drop rate.

Default golden profile:

| Parameter | Value |
| --- | --- |
| Root ports | 4 |
| Endpoints / root | 2 |
| Buses | 4 |
| Iterations | 20 |
| Latency | 80 ns |
| Tokens/sec | 500000 |
| Burst size | 32 |
| Jitter | 25 ns |
| Drop rate | 0.00 |

### Runners

The same built-in golden fabric is attached as QEMU `-device` arguments for either guest. That works on a VM: QEMU emulates the switches, NVMe stand-ins, and NICs; the guest only has to enumerate them.

```bash
./scripts/run_zephyr_ai_topology.sh
```

The Zephyr script checks the venv, source tree, SDK, QEMU binary, and kernel image, then starts the emulated topology. Override paths with `ZEPHYR_BASE`, `ZEPHYR_SDK_INSTALL_DIR`, and `KERNEL_PATH` as needed.

```bash
# aarch64 virt (same machine family as Zephyr)
ARCH=aarch64 KERNEL_PATH=/path/to/Image INITRD_PATH=/path/to/initrd.img \
  ./scripts/run_linux_ai_topology.sh

# x86_64 q35
ARCH=x86_64 DISK_IMAGE=/path/to/linux.qcow2 \
  ./scripts/run_linux_ai_topology.sh
```

The Linux script uses host `qemu-system-aarch64` or `qemu-system-x86_64`, enables KVM when `/dev/kvm` is available, and fails clearly if no disk or kernel is provided. In the GUI, pick **Linux QEMU runner** in the AI emulator to use this path.

## PCI backend notes

The built-in PCI backend reads and writes Linux sysfs config space:

```text
/sys/bus/pci/devices/<domain:bus:device.function>/config
```

This typically needs root privileges or a permission setup that allows sysfs access.

```bash
lspci -Dnn | grep -Ei 'Express|PCIe|Bridge'
```

Use a real PCIe endpoint with Express capability data. A host bridge or virtualized system device is usually the wrong target.

## Supported backends

- `dummy` — deterministic software-only mock
- `pci` — Linux sysfs PCI config space
- `fpga` — FPGA-oriented path
- `armds` — ARM DS bridge style path
- `xgig` — external vendor-style path

## Example usage

```c
pcie_ctx_t *ctx = pcie_open("pci");
if (!ctx) {
    fprintf(stderr, "Failed to open backend\n");
    return 1;
}

pcie_tlp_t cfg_rd = pcie_tlp_cfg_read(0x0);
cfg_rd.requester_id = 0x0001;

pcie_send(ctx, &cfg_rd);
pcie_close(ctx);
```

## Link capability checks

The library can inspect PCIe capability blocks and report max/negotiated link speed, width, and generation.

```c
pcie_link_status_t status = {0};
if (pcie_get_link_status(ctx, &status) == 0) {
    printf("Max link speed: %s\n",
           pcie_link_speed_name(status.max_link_speed));
    printf("Negotiated generation: %s\n",
           pcie_gen_name(status.negotiated_gen));
}
```

Minimum-target helper:

```c
int pass = 0;
if (pcie_check_link_target(ctx, PCIE_GEN_5, 1, &pass) == 0 && pass) {
    printf("Link meets the minimum Gen 5 x1 requirement\n");
}
```

## Trace capture and export

```bash
./build/tlp_capture dummy /tmp/pcie_tlps.pcap
./build/tlp_capture dummy /tmp/pcie_tlps.csv csv
```

## GUI overview

The Qt application focuses on readable packet inspection:

- open / save traces
- packet table and row metadata
- live versus captured traffic
- optional topology enumeration logs, kept separate from the main TLP view

## Release status

The core library, GUI, backends, examples, and QEMU topology tooling (Zephyr or Linux guests) form a stable baseline. Experimental AI topology and performance flows are supported as extensions, not the definition of the first release.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). Useful areas include backends, parsing/filtering, visualization, topology validation, and examples.

## License

[MIT](LICENSE)
