/**
 * WuWa kernel driver SDK for ARM64 Android 6.1+
 *
 * Single-header library. Provides userspace bindings to WuWa kernel module
 * via hijacked socket protocol family.
 *
 * Discovery:
 *   1. Probe uncommon AF_* families with SOCK_SEQPACKET
 *   2. Driver responds with -ENOKEY
 *   3. Create SOCK_RAW socket on identified family
 *   4. Issue ioctl commands on the socket fd
 *
 * Usage:
 *   #include "wuwa.hpp"
 *
 *   wuwa::WuWaDriver driver;
 *   if (!driver.connect()) return -1;
 *
 *   auto pid = driver.find_process("target_app");
 *   auto base = driver.get_module_base(*pid, "lib.so", 0x4);
 *   uint32_t val = *driver.read<uint32_t>(*pid, *base + 0x1000);
 *
 * Safety:
 *   Direct physical memory access and kernel-level process manipulation.
 *   Requires root or CAP_NET_RAW. For defensive security research only.
 */

#pragma once

#include <sys/socket.h>
#include <sys/ioctl.h>
#include <linux/if_alg.h>
#include <unistd.h>
#include <cstdint>
#include <cstring>
#include <string>
#include <optional>
#include <vector>

namespace wuwa {

// Forward declarations for ioctl macros
struct WuwaAddrTranslateCmd;
struct WuwaDebugInfoCmd;
struct WuwaAtS1e0rCmd;
struct WuwaPageInfoCmd;
struct WuwaDmaBufCreateCmd;
struct WuwaPteMappingCmd;
struct WuwaPageTableWalkCmd;
struct WuwaCopyProcessCmd;
struct WuwaReadPhysicalMemoryCmd;
struct WuwaGetModuleBaseCmd;
struct WuwaFindProcCmd;
struct WuwaWritePhysicalMemoryCmd;
struct WuwaIsProcAliveCmd;
struct WuwaHideProcCmd;
struct WuwaGiveRootCmd;
struct WuwaReadPhysicalMemoryIoremapCmd;
struct WuwaWritePhysicalMemoryIoremapCmd;
struct WuwaBindProcCmd;

// IOCTL command definitions (magic number 'W')
// Must use actual struct types for correct command number calculation
#define WUWA_IOCTL_ADDR_TRANSLATE _IOWR('W', 1, WuwaAddrTranslateCmd)
#define WUWA_IOCTL_DEBUG_INFO _IOR('W', 2, WuwaDebugInfoCmd)
#define WUWA_IOCTL_AT_S1E0R _IOWR('W', 3, WuwaAtS1e0rCmd)
#define WUWA_IOCTL_PAGE_INFO _IOWR('W', 4, WuwaPageInfoCmd)
#define WUWA_IOCTL_DMA_BUF_CREATE _IOWR('W', 5, WuwaDmaBufCreateCmd)
#define WUWA_IOCTL_PTE_MAPPING _IOWR('W', 6, WuwaPteMappingCmd)
#define WUWA_IOCTL_PAGE_TABLE_WALK _IOWR('W', 7, WuwaPageTableWalkCmd)
#define WUWA_IOCTL_COPY_PROCESS _IOWR('W', 8, WuwaCopyProcessCmd)
#define WUWA_IOCTL_READ_MEMORY _IOWR('W', 9, WuwaReadPhysicalMemoryCmd)
#define WUWA_IOCTL_GET_MODULE_BASE _IOWR('W', 10, WuwaGetModuleBaseCmd)
#define WUWA_IOCTL_FIND_PROCESS _IOWR('W', 11, WuwaFindProcCmd)
#define WUWA_IOCTL_WRITE_MEMORY _IOWR('W', 12, WuwaWritePhysicalMemoryCmd)
#define WUWA_IOCTL_IS_PROCESS_ALIVE _IOWR('W', 13, WuwaIsProcAliveCmd)
#define WUWA_IOCTL_HIDE_PROCESS _IOWR('W', 14, WuwaHideProcCmd)
#define WUWA_IOCTL_GIVE_ROOT _IOWR('W', 15, WuwaGiveRootCmd)
#define WUWA_IOCTL_READ_MEMORY_IOREMAP _IOWR('W', 16, WuwaReadPhysicalMemoryIoremapCmd)
#define WUWA_IOCTL_WRITE_MEMORY_IOREMAP _IOWR('W', 17, WuwaWritePhysicalMemoryIoremapCmd)
#define WUWA_IOCTL_BIND_PROC _IOWR('W', 18, WuwaBindProcCmd)

// Command structures matching kernel definitions

struct WuwaAddrTranslateCmd {
    uint64_t phy_addr;
    pid_t pid;
    uintptr_t va;
};

struct WuwaDebugInfoCmd {
    uint64_t ttbr0_el1;
    uint64_t task_struct;
    uint64_t mm_struct;
    uint64_t pgd_addr;
    uint64_t pgd_phys_addr;
    uint64_t mm_asid;
    uint32_t mm_right;
};

struct WuwaAtS1e0rCmd {
    uint64_t phy_addr;
    pid_t pid;
    uintptr_t va;
};

union PageUnion {
    int32_t mapcount;
    uint32_t page_type;
};

struct KernelPage {
    uint64_t flags;
    PageUnion union_field;
    int32_t refcount;
    uint64_t phy_addr;
};

struct WuwaPageInfoCmd {
    pid_t pid;
    uintptr_t va;
    KernelPage page;
};

struct WuwaDmaBufCreateCmd {
    pid_t pid;
    uintptr_t va;
    size_t size;
    int fd;
};

struct WuwaPteMappingCmd {
    pid_t pid;
    uintptr_t start_addr;
    size_t num_pages;
    int hide;
};

struct WuwaPageTableWalkCmd {
    pid_t pid;
};

struct WuwaCopyProcessCmd {
    pid_t pid;
    void* fn_ptr;
    void* child_stack;
    size_t child_stack_size;
    uint64_t flags;
    void* arg;
    int* child_tid;
};

struct WuwaReadPhysicalMemoryCmd {
    pid_t pid;
    uintptr_t src_va;
    uintptr_t dst_va;
    size_t size;
    uintptr_t phy_addr;
};

struct WuwaWritePhysicalMemoryCmd {
    pid_t pid;
    uintptr_t src_va;
    uintptr_t dst_va;
    size_t size;
    uintptr_t phy_addr;
};

struct WuwaGetModuleBaseCmd {
    pid_t pid;
    char name[256];
    uintptr_t base;
    int vm_flag;
};

struct WuwaFindProcCmd {
    pid_t pid;
    char name[256];
};

struct WuwaIsProcAliveCmd {
    pid_t pid;
    int alive;
};

struct WuwaHideProcCmd {
    pid_t pid;
    int hide;
};

struct WuwaGiveRootCmd {
    int result;
};

struct WuwaReadPhysicalMemoryIoremapCmd {
    pid_t pid;
    uintptr_t src_va;
    uintptr_t dst_va;
    size_t size;
    uintptr_t phy_addr;
    int prot;
};

struct WuwaWritePhysicalMemoryIoremapCmd {
    pid_t pid;
    uintptr_t src_va;
    uintptr_t dst_va;
    size_t size;
    uintptr_t phy_addr;
    int prot;
};

struct WuwaBindProcCmd {
    pid_t pid;
    int fd;
};

// Memory type constants for ioremap operations
enum WuwaMemoryType {
    WMT_NORMAL = 0,          // Normal cached memory
    WMT_NORMAL_TAGGED = 1,   // Normal with MTE tags
    WMT_NORMAL_NC = 2,       // Non-cacheable
    WMT_NORMAL_WT = 3,       // Write-through
    WMT_DEVICE_nGnRnE = 4,   // Device memory, no gather/reorder/early-ack
    WMT_DEVICE_nGnRE = 5,    // Device memory, no gather/reorder
    WMT_DEVICE_GRE = 6,      // Device memory, gather/reorder/early-ack
    WMT_NORMAL_iNC_oWB = 7   // Inner non-cacheable, outer write-back
};

// BindProc command structures
struct BpReadMemoryCmd {
    uintptr_t src_va;  // Virtual address to read from
    uintptr_t dst_va;  // Virtual address to write to (userspace buffer)
    size_t size;
};

struct BpWriteMemoryCmd {
    uintptr_t src_va;  // Virtual address to read from (userspace buffer)
    uintptr_t dst_va;  // Virtual address to write to
    size_t size;
};

// BindProc ioctl commands
#define WUWA_BP_IOCTL_SET_MEMORY_PROT _IOWR('B', 1, int)
#define WUWA_BP_IOCTL_READ_MEMORY _IOWR('B', 2, BpReadMemoryCmd)
#define WUWA_BP_IOCTL_WRITE_MEMORY _IOWR('B', 3, BpWriteMemoryCmd)

/**
 * Bound process handle for efficient memory access
 *
 * Wraps a file descriptor returned by bind_process(). Provides:
 * - Efficient reads via cached ioremap pages
 * - Configurable memory type (cached/device/etc)
 * - RAII fd management
 */
class BindProc {
public:
    BindProc() : fd_(-1) {}

    explicit BindProc(int fd) : fd_(fd) {}

    ~BindProc() {
        if (fd_ >= 0) {
            close(fd_);
        }
    }

    // Non-copyable
    BindProc(const BindProc&) = delete;
    BindProc& operator=(const BindProc&) = delete;

    // Movable
    BindProc(BindProc&& other) noexcept : fd_(other.fd_) {
        other.fd_ = -1;
    }

    BindProc& operator=(BindProc&& other) noexcept {
        if (this != &other) {
            if (fd_ >= 0) {
                close(fd_);
            }
            fd_ = other.fd_;
            other.fd_ = -1;
        }
        return *this;
    }

    bool is_valid() const { return fd_ >= 0; }

    /**
     * Read from target process virtual address
     * Uses kernel-side ioremap with page caching for efficiency
     *
     * @param va Virtual address in target process
     * @param buf Destination buffer
     * @param size Number of bytes to read (max 64KB)
     * @return Number of bytes read, or -1 on error
     */
    ssize_t read(uintptr_t va, void* buf, size_t size) {
        if (fd_ < 0) return -1;

        BpReadMemoryCmd cmd = {
            va,
            reinterpret_cast<uintptr_t>(buf),
            size
        };

        int ret = ioctl(fd_, WUWA_BP_IOCTL_READ_MEMORY, &cmd);
        return ret < 0 ? -1 : ret;
    }

    /**
     * Write to target process virtual address
     *
     * @param va Virtual address in target process
     * @param buf Source buffer
     * @param size Number of bytes to write (max 64KB)
     * @return Number of bytes written, or -1 on error
     */
    ssize_t write(uintptr_t va, const void* buf, size_t size) {
        if (fd_ < 0) return -1;

        BpWriteMemoryCmd cmd = {
            reinterpret_cast<uintptr_t>(buf),
            va,
            size
        };

        int ret = ioctl(fd_, WUWA_BP_IOCTL_WRITE_MEMORY, &cmd);
        return ret < 0 ? -1 : ret;
    }

    /**
     * Type-safe read from target process
     */
    template<typename T>
    std::optional<T> read(uintptr_t va) {
        T buffer;
        ssize_t ret = read(va, &buffer, sizeof(T));
        if (ret != sizeof(T)) {
            return std::nullopt;
        }
        return buffer;
    }

    /**
     * Type-safe write to target process
     */
    template<typename T>
    bool write(uintptr_t va, const T& value) {
        ssize_t ret = write(va, &value, sizeof(T));
        return ret == sizeof(T);
    }

    /**
     * Set memory type for future ioremap operations
     *
     * @param mem_type One of WMT_* constants
     * @return true on success
     */
    bool set_memory_type(WuwaMemoryType mem_type) {
        if (fd_ < 0) return false;

        int prot = static_cast<int>(mem_type);
        return ioctl(fd_, WUWA_BP_IOCTL_SET_MEMORY_PROT, &prot) >= 0;
    }

    /**
     * Get underlying file descriptor (for advanced use)
     */
    int raw_fd() const { return fd_; }

private:
    int fd_;
};

/**
 * WuWa driver connection handle with RAII socket management
 */
class WuWaDriver {
public:
    WuWaDriver() : sock_fd_(-1) {}

    ~WuWaDriver() {
        if (sock_fd_ >= 0) {
            close(sock_fd_);
        }
    }

    // Non-copyable
    WuWaDriver(const WuWaDriver&) = delete;
    WuWaDriver& operator=(const WuWaDriver&) = delete;

    // Movable
    WuWaDriver(WuWaDriver&& other) noexcept : sock_fd_(other.sock_fd_) {
        other.sock_fd_ = -1;
    }

    WuWaDriver& operator=(WuWaDriver&& other) noexcept {
        if (this != &other) {
            if (sock_fd_ >= 0) {
                close(sock_fd_);
            }
            sock_fd_ = other.sock_fd_;
            other.sock_fd_ = -1;
        }
        return *this;
    }

    /**
     * Discover and connect to WuWa driver. Requires root or CAP_NET_RAW.
     */
    bool connect() {
        constexpr int families[] = {
            AF_DECnet, AF_NETBEUI, AF_SECURITY, AF_KEY, AF_NETLINK,
            AF_PACKET, AF_ASH, AF_ECONET, AF_ATMSVC, AF_RDS,
            AF_SNA, AF_IRDA, AF_PPPOX, AF_WANPIPE, AF_LLC,
            AF_CAN, AF_TIPC, AF_BLUETOOTH, AF_IUCV, AF_RXRPC,
            AF_ISDN, AF_PHONET, AF_IEEE802154, AF_CAIF, AF_ALG, AF_VSOCK
        };

        for (int af : families) {
            int probe_fd = socket(af, SOCK_SEQPACKET, 0);
            if (probe_fd >= 0) {
                close(probe_fd);
                continue;
            }

            if (errno == ENOKEY) {
                sock_fd_ = socket(af, SOCK_RAW, 0);
                if (sock_fd_ >= 0) {
                    return true;
                }
            }
        }
        return false;
    }

    bool is_connected() const { return sock_fd_ >= 0; }

    /**
     * Software page table walk: VA -> PA translation
     */
    std::optional<uint64_t> addr_translate(pid_t pid, uintptr_t va) {
        WuwaAddrTranslateCmd cmd = {0, pid, va};
        if (!do_ioctl(WUWA_IOCTL_ADDR_TRANSLATE, &cmd)) {
            return std::nullopt;
        }
        return cmd.phy_addr;
    }

    /**
     * Get process debug info (TTBR0, task_struct, mm_struct, pgd)
     */
    std::optional<WuwaDebugInfoCmd> get_debug_info(pid_t pid) {
        WuwaDebugInfoCmd cmd = {};
        if (!do_ioctl(WUWA_IOCTL_DEBUG_INFO, &cmd)) {
            return std::nullopt;
        }
        return cmd;
    }

    /**
     * Hardware AT S1E0R instruction: VA -> PA (faster than software walk)
     */
    std::optional<uint64_t> at_s1e0r(pid_t pid, uintptr_t va) {
        WuwaAtS1e0rCmd cmd = {0, pid, va};
        if (!do_ioctl(WUWA_IOCTL_AT_S1E0R, &cmd)) {
            return std::nullopt;
        }
        return cmd.phy_addr;
    }

    /**
     * Query page flags, refcount, mapcount at VA
     */
    std::optional<KernelPage> get_page_info(pid_t pid, uintptr_t va) {
        WuwaPageInfoCmd cmd = {pid, va, {}};
        if (!do_ioctl(WUWA_IOCTL_PAGE_INFO, &cmd)) {
            return std::nullopt;
        }
        return cmd.page;
    }

    /**
     * Export process memory region as dma-buf fd for zero-copy sharing
     */
    std::optional<int> create_dma_buf(pid_t pid, uintptr_t va, size_t size) {
        WuwaDmaBufCreateCmd cmd = {pid, va, size, -1};
        if (!do_ioctl(WUWA_IOCTL_DMA_BUF_CREATE, &cmd)) {
            return std::nullopt;
        }
        return cmd.fd;
    }

    /**
     * Direct PTE manipulation (hide/unhide pages)
     */
    bool pte_mapping(pid_t pid, uintptr_t start_addr, size_t num_pages, bool hide) {
        WuwaPteMappingCmd cmd = {pid, start_addr, num_pages, hide ? 1 : 0};
        return do_ioctl(WUWA_IOCTL_PTE_MAPPING, &cmd);
    }

    /**
     * Dump complete page table to dmesg
     */
    bool page_table_walk(pid_t pid) {
        WuwaPageTableWalkCmd cmd = {pid};
        return do_ioctl(WUWA_IOCTL_PAGE_TABLE_WALK, &cmd);
    }

    /**
     * Read physical memory via phys_to_virt (max 50MB per call)
     */
    std::optional<uintptr_t> read_physical_memory(pid_t pid, uintptr_t src_va,
                                                   void* dst_buf, size_t size) {
        WuwaReadPhysicalMemoryCmd cmd = {
            pid, src_va, reinterpret_cast<uintptr_t>(dst_buf), size, 0
        };
        if (!do_ioctl(WUWA_IOCTL_READ_MEMORY, &cmd)) {
            return std::nullopt;
        }
        return cmd.phy_addr;
    }

    /**
     * Write physical memory via phys_to_virt (max 50MB per call)
     */
    std::optional<uintptr_t> write_physical_memory(pid_t pid, const void* src_buf,
                                                    uintptr_t dst_va, size_t size) {
        WuwaWritePhysicalMemoryCmd cmd = {
            pid, reinterpret_cast<uintptr_t>(src_buf), dst_va, size, 0
        };
        if (!do_ioctl(WUWA_IOCTL_WRITE_MEMORY, &cmd)) {
            return std::nullopt;
        }
        return cmd.phy_addr;
    }

    /**
     * Type-safe read of arbitrary struct from target process
     */
    template<typename T>
    std::optional<T> read(pid_t pid, uintptr_t addr) {
        T buffer;
        auto result = read_physical_memory(pid, addr, &buffer, sizeof(T));
        if (!result) return std::nullopt;
        return buffer;
    }

    /**
     * Type-safe write of arbitrary struct to target process
     */
    template<typename T>
    bool write(pid_t pid, uintptr_t addr, const T& value) {
        auto result = write_physical_memory(pid, &value, addr, sizeof(T));
        return result.has_value();
    }

    /**
     * Read Unreal Engine FString from target process
     */
    std::optional<std::string> read_fstring(pid_t pid, uintptr_t addr) {
        auto len_opt = read<uint32_t>(pid, addr + 8);
        if (!len_opt || *len_opt == 0) {
            return std::string();
        }

        auto ptr_opt = read<uintptr_t>(pid, addr);
        if (!ptr_opt) return std::nullopt;

        std::string result;
        if (!read_to_utf8(pid, *ptr_opt, result, *len_opt - 1)) {
            return std::nullopt;
        }
        return result;
    }

    /**
     * Read FString with length limit
     */
    std::optional<std::string> read_fstring_limit(pid_t pid, uintptr_t addr, size_t max_len) {
        auto len_opt = read<uint32_t>(pid, addr + 8);
        if (!len_opt || *len_opt == 0) {
            return std::string();
        }

        if (*len_opt > max_len) {
            return std::nullopt;
        }

        auto ptr_opt = read<uintptr_t>(pid, addr);
        if (!ptr_opt) return std::nullopt;

        std::string result;
        if (!read_to_utf8(pid, *ptr_opt, result, *len_opt - 1)) {
            return std::nullopt;
        }
        return result;
    }

    /**
     * Get module/library base address in target process
     * @param vm_flag VM flags to filter (e.g., 0x4 for VM_EXEC)
     */
    std::optional<uintptr_t> get_module_base(pid_t pid, const std::string& name, int vm_flag) {
        WuwaGetModuleBaseCmd cmd = {pid, {}, 0, vm_flag};
        size_t copy_len = std::min(name.size(), sizeof(cmd.name) - 1);
        memcpy(cmd.name, name.c_str(), copy_len);
        cmd.name[copy_len] = '\0';

        if (!do_ioctl(WUWA_IOCTL_GET_MODULE_BASE, &cmd)) {
            return std::nullopt;
        }
        return cmd.base;
    }

    /**
     * Find process by name, returns PID
     */
    std::optional<pid_t> find_process(const std::string& name) {
        WuwaFindProcCmd cmd = {0, {}};
        size_t copy_len = std::min(name.size(), sizeof(cmd.name) - 1);
        memcpy(cmd.name, name.c_str(), copy_len);
        cmd.name[copy_len] = '\0';

        if (!do_ioctl(WUWA_IOCTL_FIND_PROCESS, &cmd)) {
            return std::nullopt;
        }
        if (cmd.pid == 0) {
            return std::nullopt;
        }
        return cmd.pid;
    }

    /**
     * Check if process is alive
     */
    std::optional<bool> is_process_alive(pid_t pid) {
        WuwaIsProcAliveCmd cmd = {pid, 0};
        if (!do_ioctl(WUWA_IOCTL_IS_PROCESS_ALIVE, &cmd)) {
            return std::nullopt;
        }
        return cmd.alive != 0;
    }

    /**
     * Hide/unhide process from system visibility
     */
    bool hide_process(pid_t pid, bool hide) {
        WuwaHideProcCmd cmd = {pid, hide ? 1 : 0};
        return do_ioctl(WUWA_IOCTL_HIDE_PROCESS, &cmd);
    }

    /**
     * Escalate current process to root (uid=0, gid=0)
     */
    bool give_root() {
        WuwaGiveRootCmd cmd = {0};
        if (!do_ioctl(WUWA_IOCTL_GIVE_ROOT, &cmd)) {
            return false;
        }
        return cmd.result >= 0;
    }

    /**
     * Read physical memory via ioremap with memory attribute control
     * @param prot Memory type (use MT_* constants from kernel)
     */
    std::optional<uintptr_t> read_physical_memory_ioremap(pid_t pid, uintptr_t src_va,
                                                           void* dst_buf, size_t size, int prot) {
        WuwaReadPhysicalMemoryIoremapCmd cmd = {
            pid, src_va, reinterpret_cast<uintptr_t>(dst_buf), size, 0, prot
        };
        if (!do_ioctl(WUWA_IOCTL_READ_MEMORY_IOREMAP, &cmd)) {
            return std::nullopt;
        }
        return cmd.phy_addr;
    }

    /**
     * Write physical memory via ioremap with memory attribute control
     * @param prot Memory type (use MT_* constants from kernel)
     */
    std::optional<uintptr_t> write_physical_memory_ioremap(pid_t pid, const void* src_buf,
                                                            uintptr_t dst_va, size_t size, int prot) {
        WuwaWritePhysicalMemoryIoremapCmd cmd = {
            pid, reinterpret_cast<uintptr_t>(src_buf), dst_va, size, 0, prot
        };
        if (!do_ioctl(WUWA_IOCTL_WRITE_MEMORY_IOREMAP, &cmd)) {
            return std::nullopt;
        }
        return cmd.phy_addr;
    }

    /**
     * Bind process for efficient memory access
     *
     * Returns a BindProc handle that uses kernel-side ioremap with page caching.
     * More efficient than repeated read_physical_memory() calls for sequential access.
     *
     * @param pid Target process ID
     * @return BindProc object on success, nullopt on failure
     */
    std::optional<BindProc> bind_process(pid_t pid) {
        WuwaBindProcCmd cmd = {pid, -1};
        if (!do_ioctl(WUWA_IOCTL_BIND_PROC, &cmd)) {
            return std::nullopt;
        }
        return BindProc(cmd.fd);
    }

    /**
     * Copy process with custom function pointer and stack
     */
    bool copy_process(pid_t pid, void* fn_ptr, void* child_stack,
                     size_t child_stack_size, uint64_t flags, void* arg) {
        WuwaCopyProcessCmd cmd = {
            pid, fn_ptr, child_stack, child_stack_size, flags, arg, nullptr
        };
        return do_ioctl(WUWA_IOCTL_COPY_PROCESS, &cmd);
    }

private:
    int sock_fd_;

    bool do_ioctl(unsigned long cmd, void* arg) {
        return ioctl(sock_fd_, cmd, arg) >= 0;
    }

    /**
     * Convert UTF-16 in target process to UTF-8
     */
    bool read_to_utf8(pid_t pid, uintptr_t ptr, std::string& out, size_t length) {
        std::vector<uint8_t> buf;
        uintptr_t current = ptr;

        for (size_t i = 0; i < length; i++) {
            auto char_opt = read<uint16_t>(pid, current);
            if (!char_opt) return false;

            uint16_t c = *char_opt;
            if (c <= 0x007F) {
                buf.push_back(static_cast<uint8_t>(c));
            } else if (c <= 0x07FF) {
                buf.push_back(static_cast<uint8_t>((c >> 6) | 0xC0));
                buf.push_back(static_cast<uint8_t>((c & 0x3F) | 0x80));
            } else {
                buf.push_back(static_cast<uint8_t>((c >> 12) | 0xE0));
                buf.push_back(static_cast<uint8_t>(((c >> 6) & 0x3F) | 0x80));
                buf.push_back(static_cast<uint8_t>((c & 0x3F) | 0x80));
            }
            current += sizeof(uint16_t);
        }

        out.assign(buf.begin(), buf.end());
        return true;
    }
};

} // namespace wuwa
