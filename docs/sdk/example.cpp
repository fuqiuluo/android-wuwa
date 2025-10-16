/**
 * WuWa SDK usage example
 *
 * Compile: g++ -std=c++17 -o example example.cpp
 * Run: sudo ./example
 */

#include "wuwa.hpp"
#include <iostream>
#include <iomanip>

int main() {
    wuwa::WuWaDriver driver;

    // Connect to driver
    if (!driver.connect()) {
        std::cerr << "Failed to connect to WuWa driver. Are you root?" << std::endl;
        return 1;
    }
    std::cout << "Connected to WuWa driver" << std::endl;

    // Find target process
    const char* target_name = "com.kurogame.wutheringwaves";
    auto pid_opt = driver.find_process(target_name);
    if (!pid_opt) {
        std::cerr << "Process not found: " << target_name << std::endl;
        return 1;
    }
    pid_t pid = *pid_opt;
    std::cout << "Found process: " << target_name << " (PID: " << pid << ")" << std::endl;

    // Check if alive
    auto alive = driver.is_process_alive(pid);
    std::cout << "Process alive: " << (alive && *alive ? "yes" : "no") << std::endl;

    // Get module base
    auto base = driver.get_module_base(pid, "libUE4.so", 0x4); // VM_EXEC
    if (!base) {
        std::cerr << "Failed to get module base" << std::endl;
        return 1;
    }
    std::cout << "libUE4.so base: 0x" << std::hex << *base << std::dec << std::endl;

    // Read memory example
    uint32_t value;
    auto addr = *base + 0x1000;
    auto result = driver.read_physical_memory(pid, addr, &value, sizeof(value));
    if (result) {
        std::cout << "Read from 0x" << std::hex << addr << ": 0x"
                  << value << std::dec << std::endl;
    }

    // Type-safe read
    auto val_opt = driver.read<uint32_t>(pid, addr);
    if (val_opt) {
        std::cout << "Type-safe read: 0x" << std::hex << *val_opt << std::dec << std::endl;
    }

    // Write memory example
    uint32_t new_value = 0x12345678;
    if (driver.write(pid, addr, new_value)) {
        std::cout << "Wrote 0x" << std::hex << new_value << " to 0x"
                  << addr << std::dec << std::endl;
    }

    // VA -> PA translation
    auto phy_addr = driver.at_s1e0r(pid, addr);
    if (phy_addr) {
        std::cout << "Physical address of 0x" << std::hex << addr
                  << ": 0x" << *phy_addr << std::dec << std::endl;
    }

    // Get debug info
    auto debug = driver.get_debug_info(pid);
    if (debug) {
        std::cout << "\nDebug info:" << std::endl;
        std::cout << "  TTBR0_EL1: 0x" << std::hex << debug->ttbr0_el1 << std::endl;
        std::cout << "  task_struct: 0x" << debug->task_struct << std::endl;
        std::cout << "  mm_struct: 0x" << debug->mm_struct << std::endl;
        std::cout << "  pgd_addr: 0x" << debug->pgd_addr << std::dec << std::endl;
    }

    // Page info
    auto page = driver.get_page_info(pid, addr);
    if (page) {
        std::cout << "\nPage info for 0x" << std::hex << addr << ":" << std::endl;
        std::cout << "  flags: 0x" << page->flags << std::endl;
        std::cout << "  refcount: " << std::dec << page->refcount << std::endl;
        std::cout << "  phy_addr: 0x" << std::hex << page->phy_addr << std::dec << std::endl;
    }

    // DMA-BUF example (zero-copy memory sharing)
    auto dma_fd = driver.create_dma_buf(pid, addr, 4096);
    if (dma_fd) {
        std::cout << "\nCreated DMA-BUF fd: " << *dma_fd << std::endl;
        // Can now mmap() this fd for zero-copy access
        close(*dma_fd);
    }

    // BindProc example (efficient sequential access via ioctl)
    std::cout << "\n=== BindProc Example ===" << std::endl;
    auto bindproc = driver.bind_process(pid);
    if (bindproc && bindproc->is_valid()) {
        std::cout << "Bound to process " << pid << std::endl;

        // Set memory type (optional, defaults to WMT_NORMAL)
        bindproc->set_memory_type(wuwa::WMT_NORMAL);

        // Efficient read - uses cached ioremap pages internally via ioctl
        auto val1 = bindproc->read<uint32_t>(*base + 0x1000);
        auto val2 = bindproc->read<uint32_t>(*base + 0x1008);
        auto val3 = bindproc->read<uint32_t>(*base + 0x1010);

        if (val1 && val2 && val3) {
            std::cout << "Read via BindProc:" << std::endl;
            std::cout << "  0x" << std::hex << (*base + 0x1000) << ": 0x" << *val1 << std::endl;
            std::cout << "  0x" << (*base + 0x1008) << ": 0x" << *val2 << std::endl;
            std::cout << "  0x" << (*base + 0x1010) << ": 0x" << *val3 << std::dec << std::endl;
        }

        // Raw buffer read
        char buffer[256];
        ssize_t bytes = bindproc->read(*base + 0x2000, buffer, sizeof(buffer));
        if (bytes > 0) {
            std::cout << "Read " << bytes << " bytes from 0x"
                      << std::hex << (*base + 0x2000) << std::dec << std::endl;
        }

        // Write example
        uint32_t new_val = 0xdeadbeef;
        if (bindproc->write(*base + 0x3000, new_val)) {
            std::cout << "Wrote 0x" << std::hex << new_val
                      << " to 0x" << (*base + 0x3000) << std::dec << std::endl;
        }

        // BindProc automatically closes fd on destruction
    }

    // Escalate to root (if not already root)
    if (getuid() != 0) {
        if (driver.give_root()) {
            std::cout << "\nEscalated to root: uid=" << getuid()
                      << " gid=" << getgid() << std::endl;
        }
    }

    return 0;
}
