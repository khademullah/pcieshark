# pcieshark

pcieshark is a PCIe trace, enumeration, and analysis toolkit for building, inspecting, and validating PCIe traffic in a transparent, developer-friendly way. It combines a reusable C library, example programs, a Qt-based GUI, and a Zephyr/QEMU-backed topology flow to support both practical hardware bring-up and trace-driven investigation.

The project is designed to be:
- open and inspectable
- backend-driven and portable
- useful for both real hardware and emulated PCIe environments
- buildable with a standard CMake workflow
- suitable for PCIe analysis, enumeration experiments, and link-validation workflows

<img width="1024" height="1024" alt="WhatsApp Image 2026-09-20 at 16 22 00" src="https://github.com/user-attachments/assets/dffa6458-1808-46da-81ba-68accb09879e" />

## Demo

Watch the AI PCIe emulator walkthrough and the PCIe trace/performance workflow in the demo below.

![AI PCIe Emulator Demo](AI_PCIe_Emulator_optimized.gif)

[Download MP4 demo](AI_PCIe_Emulator_optimized.mp4)

This demo highlights:
- live PCIe trace viewing
- AI topology enumeration flow
- golden AI fabric layout
- performance measurement and runtime status

## Why this project exists

PCIe bring-up and validation often requires a mix of:
- raw trace inspection
- config-space enumeration
- protocol understanding
- link-performance analysis
- hardware/software integration checks

libpcapcie provides a practical foundation for these tasks without depending on a closed vendor stack or a complex proprietary toolchain. It supports direct PCIe backend access, high-level TLP analysis, and a GUI workflow for trace review.

## Project focus

The current project is centered on the complete software stack:
- a reusable PCIe library
- backend abstraction for different access methods
- trace capture and parsing
- GUI inspection and filtering
- Zephyr-based QEMU topology support for realistic enumeration scenarios
- optional experimental AI topology flows separate from the core project

This is the stable baseline for the project, while AI-specific topology work remains an extension rather than the primary release definition.

## Core features

- PCIe TLP creation and parsing
- Configuration-space read/write support
- TLP filtering and sniffing hooks
- Library-level link and topology inspection
- Local backend abstraction for PCI, dummy, FPGA-focused, ARM DS, and similar targets
- Trace capture and export workflows
- Qt-based GUI for live or offline trace browsing
- Zephyr/QEMU topology execution for real enumeration-style exercises
- CMake-based build and local example tooling

## Repository structure

- `src/` — core library and backend implementations
- `include/pcapcie/` — public headers
- `examples/` — sample executables for TLP and backend flows
- `gui/` — Qt desktop application for trace visualization and workflow controls
- `scripts/` — runtime and topology helper scripts
- `pcieshark/` — project-specific trace-analysis documentation and UI notes
- `build/` — local generated build artifacts

## Supported workflow

The project supports several practical usage models:

1. Trace-only workflow
   - open a captured trace
   - inspect TLPs in the table view
   - filter by direction, type, or identifier
   - inspect packet-level details

2. Live trace workflow
   - run the Zephyr/QEMU-backed topology
   - collect config-space traffic
   - review TLPs in real time

3. PCI enumeration workflow
   - use the backend abstraction to enumerate or inspect a target PCIe device
   - validate links and reported device information

4. Experimental topology workflow
   - run an emulated Zephyr AI topology
   - inspect enumeration behavior and topology layout
   - keep it separate from the core trace-analysis path

## Requirements

### Minimum system requirements

- Linux environment
- CMake 3.10+
- C/C++ toolchain
- Qt 6 development libraries for the GUI
- Zephyr toolchain if using the emulated topology flow

### Recommended environment for Zephyr-backed emulation

```bash
source ~/zephyrproject/.venv/bin/activate
export ZEPHYR_BASE=~/zephyrproject/zephyr
export ZEPHYR_TOOLCHAIN_VARIANT=zephyr
export ZEPHYR_SDK_INSTALL_DIR=/home/khadem/zephyr-sdk-1.0.1
```

You will also need a valid Zephyr kernel image available for the local target setup, e.g. a build under a Zephyr firmware project such as `build/zephyr/zephyr.elf`.

## Quick start

### 1. Clone and configure

```bash
git clone https://github.com/khademullah/pcieshark
cd libpcapcie
cmake -S . -B build
```

### 2. Build the project

```bash
cmake --build build -j$(nproc)
```

### 3. Launch the GUI

```bash
./build/gui/pcieshark
```

The GUI supports:
- opening a trace file
- saving traces
- viewing packet details
- filtering and looking through rows
- running topology-related enumeration workflows

## Build targets

The project builds a set of tools and examples, including:

```bash
./build/pcieshark
./build/pci_link_check
./build/pci_link_matrix
./build/pci_link_status
./build/simple_tlp_test
./build/tlp_capture
./build/gui/pcieshark
```

## Trace workflow

### Open a trace file

Use the GUI to load a previously captured trace file and inspect the packets in a table-based view.

### Save a trace

The GUI allows exporting the active trace to a local file so it can be shared, compared, or replayed later.

### Examine a row

Selecting a packet entry reveals details such as:
- timestamp
- direction
- TLP type
- requester ID
- payload and metadata where available

## AI PCIe emulator

The AI PCIe emulator is the project’s higher-level workload model for realistic PCIe topology validation in AI and accelerator-heavy environments. It is built around a fixed golden topology that reflects a data-center style PCIe fabric, rather than a synthetic dummy-only path.

The emulator is designed to model the topology used by accelerator-heavy systems:
- CPU complex as the root domain
- four root ports, each representing a PCIe fabric branch
- upstream switch hierarchy per branch
- NVMe endpoints for storage and data-path traffic
- GPU-like accelerator endpoints for compute placement
- SmartNIC or network endpoints for fabric connectivity

This is not just a traffic generator. It is a topology-aware emulation model that supports enumeration, trace capture, and performance measurement from the same system view.

### Golden AI topology

The default preset uses a deterministic AI fabric layout:

- root bus: `PCIe Bus 00`
- root ports: `rp1`, `rp2`, `rp3`, `rp4`
- upstream switches: `switch0_up` to `switch3_up`
- downstream ports: `dp0`, `dp1` on each switch
- endpoints:
  - GPU 1..4
  - NVMe 1..2
  - SmartNIC 1..2
  - data-path and acceleration devices per branch

This topology is intentionally fixed and sane for benchmarking and trace-driven validation. It gives a repeatable baseline before introducing custom tuning or scenario-specific modifications.

### Enumeration flow

The AI emulator supports real-device-style enumeration as part of the flow, not just log generation. The workflow is:

1. launch the Zephyr/QEMU topology
2. boot the guest image with the PCIe fabric model
3. enumerate the topology from the guest side
4. collect bus and device information in a structured log
5. parse the device list into a readable PCIe map for the GUI and analysis tools

This is how the project moves beyond a dummy backend toward a real topology-aware environment for AI workloads.

The separate `pcie ls` path is intentionally kept isolated from the main TLP trace stream so that:
- the primary trace remains readable and stable
- enumeration data can be inspected independently
- performance runs and trace captures do not overwrite one another

### Performance model

The AI PCIe emulator also supports a performance-oriented scenario model with configurable workload parameters, including:
- root ports
- endpoints per root
- buses
- iterations
- latency
- tokens/sec
- burst size
- jitter
- drop rate

These parameters allow the project to emulate realistic AI data-plane characteristics, where the fabric is evaluated not only for enumeration correctness but also for end-to-end behavior under a controlled PCIe load pattern.

Typical performance questions this model helps answer:
- how much fabric latency is introduced by the topology?
- what is the effective throughput under sustained traffic?
- how does the workload behave under bursty transfers and jitter?
- what is the effect of link contention or packet loss at the fabric layer?

### Default performance preset

The current golden topology ships with a default AI performance profile tuned for a realistic accelerator-system baseline:

- root ports: 4
- endpoints/root: 2
- buses: 4
- iterations: 20
- latency (ns): 80
- tokens/sec: 500000
- burst size: 32
- jitter (ns): 25
- drop rate: 0.00

This acts as a clean starting point for AI workload modeling and is meant to be a stable baseline before advanced customization.

### Runner behavior

The project includes a dedicated runner at:

```bash
./scripts/run_zephyr_ai_topology.sh
```

It validates the environment and starts the emulated topology with safe startup checks, including:
- Zephyr virtual environment
- Zephyr source tree
- SDK installation
- QEMU availability
- kernel image presence
- stale QEMU lock cleanup

The runner is designed to keep the normal trace path intact while optionally collecting separate enumeration logs when needed.

### Reference command

The underlying QEMU topology is started through the Zephyr environment, but the important point is not the raw command itself; the real value is the AI PCIe topology and model it creates.

```bash
./scripts/run_zephyr_ai_topology.sh
```

This is the supported entry point for the AI-enabled enumeration and performance workflow.

## PCI backend notes

The built-in PCI backend reads and writes Linux sysfs PCI config data:

```text
/sys/bus/pci/devices/<domain:bus:device.function>/config
```

This typically requires:
- root privileges, or
- a kernel/device permission setup that permits direct sysfs access

To identify a likely candidate device:

```bash
lspci -Dnn | grep -Ei 'Express|PCIe|Bridge'
```

A real PCIe endpoint will generally expose Express-related capability information; a host bridge or virtualized system device is not the right target when validating a real endpoint path.

## Supported backends

- `dummy` — deterministic software-only mock backend
- `pci` — Linux sysfs access to PCI config space
- `fpga` — FPGA-oriented backend path
- `armds` — ARM DS bridge style backend path
- `xgig` — external vendor-style backend path

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

The library can inspect PCIe capability blocks and report key link state information, including the maximum and negotiated link speed/width and the resulting PCIe generation. This is useful for validation and bring-up work where the link must meet a target generation or lane width.

```c
pcie_link_status_t status = {0};
if (pcie_get_link_status(ctx, &status) == 0) {
    printf("Max link speed: %s\n",
           pcie_link_speed_name(status.max_link_speed));
    printf("Negotiated generation: %s\n",
           pcie_gen_name(status.negotiated_gen));
}
```

A simple minimum-target helper is also available:

```c
int pass = 0;
if (pcie_check_link_target(ctx, PCIE_GEN_5, 1, &pass) == 0 && pass) {
    printf("Link meets the minimum Gen 5 x1 requirement\n");
}
```

## Trace capture and export

The library can record TLPs and export them to a host-friendly format for later review.

### Pcap-style export

```bash
./build/tlp_capture dummy /tmp/pcie_tlps.pcap
hexdump -C /tmp/pcie_tlps.pcap | head
```

### CSV export

```bash
./build/tlp_capture dummy /tmp/pcie_tlps.csv csv
```

This provides a practical workflow for offline analysis, channel debugging, and GUI review.

## GUI overview

The Qt application provides a visual interface for:
- opening a trace file
- saving a trace
- viewing a packet table
- examining packet metadata
- comparing live versus captured traffic
- exploring topology-driven enumeration logs when needed

The GUI is designed to focus on clear, readable packet inspection and to keep the main trace flow separate from extra guest-side logs such as `pcie ls`.

## Release status

This project is a complete, stable baseline for the core PCIe analysis and GUI workflow. It includes the foundational library, GUI, backend support, examples, and the Zephyr/QEMU topology tooling required for realistic enumeration experiments.

Experimental AI topology and performance-oriented flows are supported as extensions, but they are not the primary definition of the first stable project baseline.

## Contributing

Contributions are welcome for:
- backend improvements
- better parsing and filtering
- trace visualization enhancements
- PCIe topology validation improvements
- documentation and examples

Pull requests should keep the project readable, well-documented, and aligned with the existing project focus.

## License

This project is released under the repository license in the top-level project files. Please review the license before redistribution or commercial use.
