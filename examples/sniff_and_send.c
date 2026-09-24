#include <stdio.h>
#include "pcapcie/pcapcie.h"

void on_mem_read(pcie_tlp_t *t, void *user)
{
    unsigned long *count = user;
    (*count)++;
}

int main(void)
{
    pcie_ctx_t *ctx = pcie_open("dummy");
    

    unsigned long rx_cb_count = 0;

    pcie_sniff(ctx,
               PCIE_MATCH_TYPE(PCIE_TLP_MEM_READ),
               on_mem_read,
               &rx_cb_count);

    uint8_t data[4] = {0xde, 0xad, 0xbe, 0xef};

    /* Send 1000 TLPs */
    for (int i = 0; i < 1000; i++) {
        pcie_tlp_t wr =
            pcie_tlp_mem_write(0x80000000 + i * 4,
                               4,
                               data);
        pcie_send(ctx, &wr);
    }

    /* Receive until backend stops */
    pcie_loop(ctx);

    const pcie_stats_t *s = pcie_stats(ctx);

    pcie_log(PCIE_LOG_INFO,
             "==== PCIe Session Summary ====");

    pcie_log(PCIE_LOG_INFO,
             "TX packets        : %lu", s->sent);

    pcie_log(PCIE_LOG_INFO,
             "RX packets        : %lu", s->received);

    pcie_log(PCIE_LOG_INFO,
             "Callback matches  : %lu", rx_cb_count);

    pcie_log(PCIE_LOG_INFO,
         "RX address range  : 0x%lx - 0x%lx",
         pcie_rx_addr_min(ctx),
         pcie_rx_addr_max(ctx));

    pcie_close(ctx);
    return 0;
}