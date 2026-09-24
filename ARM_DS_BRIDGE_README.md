# ARM Development Studio PCIe TLP Bridge

> **Planned / untested.** This backend is not part of the current release. The source stays in `src/backend_armds.c` for later hardware bring-up.

This setup allows you to send PCIe TLPs from libpcapcie to your FPGA through ARM Development Studio.

## Architecture

```
libpcapcie (Linux) ←→ ARM DS Bridge Server (Windows) ←→ ARM DS ←→ FPGA
```

## Setup Steps

### 1. Build libpcapcie with ARM DS Backend

```bash
cd /home/khadem/libpcapcie/build
make
```

### 2. Build ARM DS Bridge Server (Windows)

Compile `armds_bridge_server.c` on Windows with MinGW or Visual Studio:

```cmd
# With MinGW
gcc armds_bridge_server.c -o armds_bridge_server.exe -lws2_32

# Or with Visual Studio cl.exe
cl armds_bridge_server.c /link ws2_32.lib
```

### 3. Configure ARM DS Communication

Edit `src/backend_armds.c` to match your ARM DS setup:

```c
#define ARM_DS_HOST "127.0.0.1"  // ARM DS IP address
#define ARM_DS_PORT 12345        // Bridge server port
#define FPGA_DEVICE_ID 0x1234    // Your FPGA device ID
```

### 4. Implement ARM DS Communication

In `armds_bridge_server.c`, implement the ARM DS communication functions:

```c
int arm_ds_send_tlp(const pcie_tlp_t *tlp) {
    // Use ARM DS SDK or JTAG commands to send TLP to FPGA
    // Example: ARM DS API calls, register writes, etc.
    return 0;
}

int arm_ds_receive_tlp(pcie_tlp_t *tlp) {
    // Check for incoming TLPs from FPGA via ARM DS
    // Return 0 if TLP received, -1 if no data
    return -1;
}
```

## Usage

### Start ARM DS Bridge Server (Windows)

```cmd
armds_bridge_server.exe 12345
```

### Run libpcapcie Test (Linux)

```bash
cd /home/khadem/libpcapcie/build
sudo ./simple_tlp_test armds
```

## ARM DS Integration Options

### Option 1: ARM DS SDK
If ARM DS provides an SDK, use it for direct communication:

```c
#include <arm_ds_sdk.h>

int arm_ds_send_tlp(const pcie_tlp_t *tlp) {
    // Use ARM DS SDK functions
    arm_ds_write_fpga_register(FPGA_TLP_REG, tlp_data);
    return 0;
}
```

### Option 2: JTAG Commands
Send JTAG commands through ARM DS:

```c
int arm_ds_send_tlp(const pcie_tlp_t *tlp) {
    // Send JTAG commands to write to FPGA registers
    char jtag_cmd[256];
    sprintf(jtag_cmd, "write_memory 0x%x 0x%x", FPGA_TLP_REG, tlp_data);
    arm_ds_execute_jtag_command(jtag_cmd);
    return 0;
}
```

### Option 3: Debug Scripts
Use ARM DS debug scripts to interface with FPGA:

```c
int arm_ds_send_tlp(const pcie_tlp_t *tlp) {
    // Execute ARM DS script that writes to FPGA
    arm_ds_run_script("send_tlp_to_fpga.py", tlp);
    return 0;
}
```

## FPGA Register Interface

Your FPGA should expose registers for TLP communication:

- **TLP Send Register**: Write TLP data here to transmit
- **TLP Receive Register**: Read received TLP data
- **Status Register**: Check ready/busy/data available flags
- **Control Register**: Reset and enable controls

## Testing

### Send Test TLP

```bash
# This sends a memory write TLP to address 0x80000000
sudo ./simple_tlp_test armds
```

### Monitor ARM DS Bridge Output

The Windows bridge server will show:
- Connection status
- TLP transmission confirmations
- Any received responses

## Troubleshooting

### Connection Issues
- Verify ARM DS bridge server is running on correct port
- Check Windows firewall settings
- Ensure ARM DS has network access

### TLP Transmission Issues
- Verify FPGA register addresses in bridge server
- Check ARM DS to FPGA communication
- Monitor ARM DS debug output

### No Response TLPs
- FPGA may not be programmed to send responses
- ARM DS polling may need adjustment
- Check FPGA TLP receive logic

## Advanced Configuration

### Multiple FPGA Devices
Modify `FPGA_DEVICE_ID` to support different FPGAs:

```c
#define FPGA_DEVICE_A 0x1234
#define FPGA_DEVICE_B 0x5678
```

### Custom TLP Processing
Add TLP preprocessing in the bridge server:

```c
int arm_ds_send_tlp(const pcie_tlp_t *tlp) {
    // Convert libpcapcie TLP format to FPGA format
    uint32_t fpga_tlp = convert_tlp_format(tlp);
    return arm_ds_write_fpga(fpga_tlp);
}
```

## Performance Considerations

- **Latency**: Network + ARM DS + FPGA processing
- **Throughput**: Limited by slowest link in chain
- **Reliability**: Add error checking and retransmission
- **Buffering**: Implement queues for high-throughput scenarios

This setup provides a flexible way to send PCIe TLPs to your FPGA through ARM Development Studio! 