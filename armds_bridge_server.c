/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2026 Khadem Ullah
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <winsock2.h>
#include <windows.h>
#include <stdint.h>

// ARM Development Studio TLP Bridge Server
// Runs on Windows and bridges between libpcapcie and FPGA via ARM DS

#pragma comment(lib, "ws2_32.lib")

#define DEFAULT_PORT 12345
#define BUFFER_SIZE 4096

// TLP structure (must match libpcapcie)
typedef enum {
    PCIE_TLP_MEM_READ  = 0x00,
    PCIE_TLP_MEM_WRITE = 0x01,
    PCIE_TLP_CFG_READ  = 0x04,
    PCIE_TLP_CFG_WRITE = 0x05,
    PCIE_TLP_CPL       = 0x0A
} pcie_tlp_type_t;

typedef struct {
    uint64_t addr;
    uint8_t *data;
} pcie_mem_t;

typedef struct {
    pcie_tlp_type_t type;
    uint16_t requester_id;
    uint16_t completer_id;
    uint8_t  tag;
    uint16_t length;
    union {
        pcie_mem_t mem;
    };
} pcie_tlp_t;

// ARM DS communication functions
// These would need to be implemented based on your ARM DS setup
int arm_ds_send_tlp(const pcie_tlp_t *tlp) {
    // TODO: Implement ARM DS communication
    // This should send the TLP to your FPGA via ARM DS
    printf("ARM DS: Sending TLP type=%d, addr=0x%llx, len=%d\n",
           tlp->type, tlp->mem.addr, tlp->length);

    // Placeholder - replace with actual ARM DS communication
    // For example: use ARM DS SDK functions, JTAG commands, etc.

    return 0; // Success
}

int arm_ds_receive_tlp(pcie_tlp_t *tlp) {
    // TODO: Implement ARM DS communication
    // This should check for and receive TLPs from FPGA via ARM DS

    // Placeholder - replace with actual ARM DS communication
    // For now, return -1 (no data available)
    return -1;
}

void cleanup_winsock() {
    WSACleanup();
}

int main(int argc, char *argv[]) {
    WSADATA wsaData;
    SOCKET listen_socket = INVALID_SOCKET;
    SOCKET client_socket = INVALID_SOCKET;
    struct sockaddr_in server_addr;
    char recvbuf[BUFFER_SIZE];
    int recvbuflen = BUFFER_SIZE;
    int port = DEFAULT_PORT;

    if (argc > 1) {
        port = atoi(argv[1]);
    }

    printf("ARM Development Studio TLP Bridge Server\n");
    printf("Listening on port %d\n", port);
    printf("Press Ctrl+C to exit\n\n");

    // Initialize Winsock
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        printf("WSAStartup failed: %d\n", WSAGetLastError());
        return 1;
    }

    atexit(cleanup_winsock);

    // Create listening socket
    listen_socket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (listen_socket == INVALID_SOCKET) {
        printf("socket failed: %d\n", WSAGetLastError());
        return 1;
    }

    // Setup server address
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(port);

    // Bind socket
    if (bind(listen_socket, (struct sockaddr *)&server_addr, sizeof(server_addr)) == SOCKET_ERROR) {
        printf("bind failed: %d\n", WSAGetLastError());
        closesocket(listen_socket);
        return 1;
    }

    // Listen for connections
    if (listen(listen_socket, SOMAXCONN) == SOCKET_ERROR) {
        printf("listen failed: %d\n", WSAGetLastError());
        closesocket(listen_socket);
        return 1;
    }

    printf("Waiting for libpcapcie connection...\n");

    // Accept client connection
    client_socket = accept(listen_socket, NULL, NULL);
    if (client_socket == INVALID_SOCKET) {
        printf("accept failed: %d\n", WSAGetLastError());
        closesocket(listen_socket);
        return 1;
    }

    printf("Client connected! Bridge active.\n\n");

    // Close listening socket (we only accept one client)
    closesocket(listen_socket);

    // Receive device ID
    uint32_t device_id;
    int result = recv(client_socket, (char *)&device_id, sizeof(device_id), 0);
    if (result != sizeof(device_id)) {
        printf("Failed to receive device ID\n");
        closesocket(client_socket);
        return 1;
    }
    printf("Device ID: 0x%08X\n\n", device_id);

    // Main bridge loop
    while (1) {
        pcie_tlp_t tlp;
        int bytes_received;

        // Check for TLP from libpcapcie
        bytes_received = recv(client_socket, (char *)&tlp, sizeof(pcie_tlp_t), 0);
        if (bytes_received == 0) {
            printf("Client disconnected\n");
            break;
        } else if (bytes_received < 0) {
            if (WSAGetLastError() == WSAEWOULDBLOCK) {
                // No data available, continue
                Sleep(1); // Small delay to prevent busy waiting
                continue;
            }
            printf("Receive error: %d\n", WSAGetLastError());
            break;
        } else if (bytes_received != sizeof(pcie_tlp_t)) {
            printf("Incomplete TLP header received (%d bytes)\n", bytes_received);
            continue;
        }

        printf("Received TLP from libpcapcie: type=%d, addr=0x%llx, len=%d\n",
               tlp.type, tlp.mem.addr, tlp.length);

        // Receive payload data if present
        if (tlp.length > 0) {
            tlp.mem.data = (uint8_t *)malloc(tlp.length);
            if (!tlp.mem.data) {
                printf("Memory allocation failed\n");
                break;
            }

            int payload_received = recv(client_socket, (char *)tlp.mem.data, tlp.length, MSG_WAITALL);
            if (payload_received != tlp.length) {
                printf("Incomplete TLP payload received (%d/%d bytes)\n", payload_received, tlp.length);
                free(tlp.mem.data);
                continue;
            }
        }

        // Send TLP to FPGA via ARM DS
        if (arm_ds_send_tlp(&tlp) == 0) {
            printf("✓ TLP forwarded to FPGA\n");
        } else {
            printf("✗ Failed to send TLP to FPGA\n");
        }

        // Clean up payload data
        if (tlp.length > 0 && tlp.mem.data) {
            free(tlp.mem.data);
            tlp.mem.data = NULL;
        }

        // Check for response TLP from FPGA
        pcie_tlp_t response_tlp;
        if (arm_ds_receive_tlp(&response_tlp) == 0) {
            printf("Received response TLP from FPGA: type=%d, addr=0x%llx, len=%d\n",
                   response_tlp.type, response_tlp.mem.addr, response_tlp.length);

            // Send response back to libpcapcie
            if (send(client_socket, (char *)&response_tlp, sizeof(pcie_tlp_t), 0) != sizeof(pcie_tlp_t)) {
                printf("Failed to send response to client\n");
                break;
            }

            // Send payload if present
            if (response_tlp.length > 0 && response_tlp.mem.data) {
                if (send(client_socket, (char *)response_tlp.mem.data, response_tlp.length, 0) != response_tlp.length) {
                    printf("Failed to send response payload to client\n");
                    break;
                }
                free(response_tlp.mem.data);
            }

            printf("✓ Response sent to libpcapcie\n");
        }
    }

    // Cleanup
    closesocket(client_socket);
    printf("Bridge server stopped.\n");
    return 0;
}