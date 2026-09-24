# FPGA PCIe TLP Backend Configuration

> **Planned / untested.** This backend is not part of the current release. The source stays in `src/backend_fpga.c` for later hardware bring-up.

This guide shows how to configure the FPGA backend for your specific FPGA board to send and receive PCIe TLPs.

## Current FPGA Backend Setup

The FPGA backend in `src/backend_fpga.c` is configured with these defaults:

```c
#define FPGA_DEVICE "/dev/mem"           // Direct memory access
#define FPGA_BAR_ADDR 0xC0000000         // FPGA BAR base address
#define FPGA_BAR_SIZE (4 * 1024 * 1024)  // 4MB BAR size

// Register offsets (modify these for your FPGA)
#define FPGA_REG_TLP_SEND     0x0000     // Write TLP data here
#define FPGA_REG_TLP_STATUS   0x0004     // Status register
#define FPGA_REG_TLP_RECV     0x0008     // Read received TLP data
#define FPGA_REG_CONTROL      0x000C     // Control register
```

## How to Configure for Your FPGA Board

### Step 1: Find Your FPGA's PCIe BAR Address

You need to determine the physical address of your FPGA's PCIe BAR. You can find this by:

**On Linux:**
```bash
lspci -v | grep -A 10 "your FPGA device"
# Look for "Memory at ..." lines
```

**Example output:**
```
Memory at c0000000 (32-bit, non-prefetchable) [size=4M]
```

### Step 2: Update FPGA Configuration

Edit `src/backend_fpga.c` and modify these defines:

```c
#define FPGA_BAR_ADDR 0xC0000000  // Change to your BAR address
#define FPGA_BAR_SIZE (4 * 1024 * 1024)  // Change to your BAR size
```

### Step 3: Configure Register Offsets

Modify the register offset defines to match your FPGA's register map:

```c
#define FPGA_REG_TLP_SEND     0x0000  // Where to write TLP data
#define FPGA_REG_TLP_STATUS   0x0004  // Status register offset
#define FPGA_REG_TLP_RECV     0x0008  // Where to read received TLP data
#define FPGA_REG_CONTROL      0x000C  // Control register offset
```

### Step 4: Update TLP Data Format

The current code packs TLP data like this:

```c
uint32_t tlp_word0 = (t->type << 24) | (t->length << 16) | t->requester_id;
uint32_t tlp_word1 = (uint32_t)(t->mem.addr & 0xFFFFFFFF);
uint32_t tlp_word2 = (uint32_t)((t->mem.addr >> 32) & 0xFFFFFFFF);
uint32_t tlp_word3 = t->tag;
```

Modify the `fpga_send()` and `fpga_recv()` functions to match your FPGA's expected TLP format.

### Step 5: Update Status Register Bits

Modify these defines to match your FPGA's status register:

```c
#define STATUS_READY      (1 << 0)  // FPGA ready to accept TLP
#define STATUS_DATA_AVAIL (1 << 1)  // Received data available
```

## Testing Your Configuration

### Build and Test

```bash
cd build
make
sudo ./simple_tlp_test fpga
```

### Expected Behavior

1. **Send Test**: The program sends a memory write TLP to address 0x80000000
2. **Receive Test**: Attempts to read any response TLP from the FPGA

### Debug Output

Enable debug logging:
```bash
export PCIE_LOG_LEVEL=DEBUG
sudo ./simple_tlp_test fpga
```

## FPGA Hardware Requirements

Your FPGA should implement:

1. **PCIe Endpoint** with at least one BAR
2. **Register Interface** for TLP data exchange
3. **TLP Generation Logic** that can create PCIe TLPs from register data
4. **TLP Reception Logic** that can capture incoming TLPs and make them available via registers

## Example FPGA Register Map

```
Offset    Register          Description
0x0000    TLP_SEND_WORD0    TLP header word 0 (type, length, requester_id)
0x0004    TLP_SEND_WORD1    TLP address low
0x0008    TLP_SEND_WORD2    TLP address high
0x000C    TLP_SEND_WORD3    TLP tag and other fields
0x0010+   TLP_DATA          Payload data (if any)
0x1000    TLP_STATUS        Status register
0x1004    TLP_RECV_WORD0    Received TLP header word 0
0x1008+   TLP_RECV_DATA     Received TLP data
0x2000    CONTROL           Control register (reset, enable)
```

## Troubleshooting

### Common Issues

1. **Permission Denied**: Run with `sudo` or configure device permissions
2. **Invalid BAR Address**: Double-check your FPGA's BAR address with `lspci`
3. **No Response**: FPGA may not be programmed or registers may be wrong
4. **Timeout**: FPGA status register not updating properly

### Debug Steps

1. Verify BAR address: `lspci -v`
2. Check /dev/mem access: `sudo head -c 4 /dev/mem` (should not crash)
3. Test register access: Add debug prints in the FPGA backend
4. Monitor FPGA side: Use FPGA debugging tools to verify register writes

## Next Steps

Once basic TLP send/receive works:

1. **Add More TLP Types**: Memory read, configuration space access
2. **Implement Completion Handling**: For memory reads
3. **Add Error Checking**: CRC, sequence numbers
4. **Performance Optimization**: DMA for large payloads
5. **Multiple Outstanding TLPs**: Pipeline multiple transactions
