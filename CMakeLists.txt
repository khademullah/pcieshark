cmake_minimum_required(VERSION 3.13)
project(pcapcie LANGUAGES C CXX)

set(CMAKE_C_STANDARD 11)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

option(PCIE_BUILD_GUI "Build the optional C++ Qt GUI (the product GUI is Python/PySide6)" OFF)

include_directories(include)

add_library(pcapcie
    src/pcapcie.c
    src/tlp.c
    src/filter.c
    src/pcie_topology.c
    src/backend_dummy.c
    src/backend_fpga.c
    src/backend_armds.c
    src/backend_pci.c
)

add_executable(sniff_and_send
    examples/sniff_and_send.c
)

add_executable(simple_tlp_test
    examples/simple_tlp_test.c
)

add_executable(pci_link_status
    examples/pci_link_status.c
)

add_executable(pci_link_check
    examples/pci_link_check.c
)

add_executable(pci_link_matrix
    examples/pci_link_matrix.c
)

add_executable(tlp_capture
    examples/tlp_capture.c
)

add_executable(pcieshark
    examples/pshark.c
)

add_executable(enumerate_topology
    examples/enumerate_topology.c
)

add_executable(pshark ALIAS pcieshark)

target_link_libraries(sniff_and_send pcapcie)
target_link_libraries(simple_tlp_test pcapcie)
target_link_libraries(pci_link_status pcapcie)
target_link_libraries(pci_link_check pcapcie)
target_link_libraries(pci_link_matrix pcapcie)
target_link_libraries(tlp_capture pcapcie)
target_link_libraries(pcieshark pcapcie)
target_link_libraries(enumerate_topology pcapcie)

if (PCIE_BUILD_GUI)
    add_subdirectory(gui)
endif()
