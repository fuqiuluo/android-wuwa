# WuWa SDK

Userspace SDKs for the WuWa kernel driver.

## Files

- **wuwa.rs** - Rust SDK with full type safety
- **wuwa.hpp** - Single-header C++ SDK (header-only)
- **example.cpp** - C++ usage example

## C++ SDK (wuwa.hpp)

Single-header library. Just `#include "wuwa.hpp"` and you're ready.

### Requirements

- C++17 or later
- Linux headers (for ioctl definitions)
- Root privileges or CAP_NET_RAW capability

### Quick Start

```cpp
#include "wuwa.hpp"

int main() {
    wuwa::WuWaDriver driver;

    // Connect to driver
    if (!driver.connect()) {
        return -1;
    }

    // Find process
    auto pid = driver.find_process("target_app");
    if (!pid) return -1;

    // Get module base
    auto base = driver.get_module_base(*pid, "libnative.so", 0x4);
    if (!base) return -1;

    // Read memory
    uint32_t value = *driver.read<uint32_t>(*pid, *base + 0x1000);

    // Write memory
    driver.write(*pid, *base + 0x1000, value + 1);

    return 0;
}
```

### Compile Example

```bash
# Desktop build
g++ -std=c++17 -o example example.cpp

# Android NDK build
$NDK/toolchains/llvm/prebuilt/linux-x86_64/bin/aarch64-linux-android33-clang++ \
    -std=c++17 -static-libstdc++ -o example example.cpp
```

### API Reference

#### Connection

- `bool connect()` - Discover and connect to WuWa driver

#### Address Translation

- `std::optional<uint64_t> addr_translate(pid_t, uintptr_t)` - Software VA->PA walk
- `std::optional<uint64_t> at_s1e0r(pid_t, uintptr_t)` - Hardware AT instruction (faster)

#### Memory Access

- `std::optional<T> read<T>(pid_t, uintptr_t)` - Type-safe read
- `bool write<T>(pid_t, uintptr_t, const T&)` - Type-safe write
- `read_physical_memory()` - Raw read with buffer
- `write_physical_memory()` - Raw write with buffer
- `read_physical_memory_ioremap()` - Read via ioremap with memory type control
- `write_physical_memory_ioremap()` - Write via ioremap with memory type control

#### Process Management

- `std::optional<pid_t> find_process(string)` - Find PID by name
- `std::optional<bool> is_process_alive(pid_t)` - Check process liveness
- `bool hide_process(pid_t, bool)` - Hide/unhide from system
- `bool give_root()` - Escalate current process to uid=0

#### Module/Memory Info

- `std::optional<uintptr_t> get_module_base(pid_t, string, int)` - Get library base
- `std::optional<KernelPage> get_page_info(pid_t, uintptr_t)` - Query page metadata
- `std::optional<WuwaDebugInfoCmd> get_debug_info(pid_t)` - TTBR0/pgd/mm_struct

#### Advanced Features

- `std::optional<int> create_dma_buf(pid_t, uintptr_t, size_t)` - Export memory as dma-buf fd
- `bool pte_mapping(pid_t, uintptr_t, size_t, bool)` - Direct PTE manipulation
- `bool page_table_walk(pid_t)` - Dump page tables to dmesg
- `std::optional<BindProc> bind_process(pid_t)` - Bind process for efficient access
- `bool copy_process(...)` - Clone process with custom entry point

#### BindProc Class

Efficient handle for repeated memory access to a single process via ioctl interface:

```cpp
auto bindproc = driver.bind_process(pid);

// Set memory type (optional)
bindproc->set_memory_type(wuwa::WMT_NORMAL);

// Read operations use cached ioremap pages internally (via ioctl)
auto val = bindproc->read<uint32_t>(addr);
if (val) {
    std::cout << "Read: 0x" << std::hex << *val << std::endl;
}

// Raw buffer read (max 64KB per call)
char buf[256];
ssize_t bytes = bindproc->read(addr, buf, sizeof(buf));

// Write operations
uint32_t new_val = 0x12345678;
bindproc->write(addr, new_val);

// Raw buffer write
bindproc->write(addr, buf, sizeof(buf));
```

**BindProc IOCTLs**:
- `WUWA_BP_IOCTL_SET_MEMORY_PROT` - Set memory type (WMT_*)
- `WUWA_BP_IOCTL_READ_MEMORY` - Read from target process
- `WUWA_BP_IOCTL_WRITE_MEMORY` - Write to target process

**Memory Types** (WuwaMemoryType enum):
- `WMT_NORMAL` - Normal cached memory (default)
- `WMT_NORMAL_NC` - Non-cacheable
- `WMT_NORMAL_WT` - Write-through cache
- `WMT_DEVICE_nGnRnE` - Device memory (strictest ordering)
- `WMT_DEVICE_nGnRE` - Device memory
- `WMT_DEVICE_GRE` - Device memory (relaxed ordering)

**Performance**: BindProc caches ioremap'd pages on kernel side, making sequential reads ~10x faster than repeated `read_physical_memory()` calls. Limits: 64KB per operation, 16 pages max per call.

#### Unreal Engine Helpers

- `std::optional<string> read_fstring(pid_t, uintptr_t)` - Read FString
- `std::optional<string> read_fstring_limit(pid_t, uintptr_t, size_t)` - Read with limit

## Rust SDK (wuwa.rs)

Full-featured SDK with Result types and proper error handling.

### Quick Start

```rust
use wuwa::WuWaDriver;

fn main() -> Result<(), anyhow::Error> {
    let driver = WuWaDriver::new()?;

    let pid = driver.find_process("target_app")?;
    let base = driver.get_module_base(pid, "lib.so", 0x4)?;

    let value: u32 = driver.read(pid, base + 0x1000)?;
    driver.write(pid, base + 0x1000, &(value + 1))?;

    Ok(())
}
```

## Driver Discovery

Both SDKs use the same discovery algorithm:

1. Probe uncommon protocol families (AF_DECnet, AF_NETBEUI, etc.) with SOCK_SEQPACKET
2. Driver responds with `-ENOKEY` when found
3. Create SOCK_RAW socket on identified family
4. Issue ioctl commands on the socket fd

This stealth technique avoids traditional `/dev/*` character devices.

## Safety Notes

These SDKs provide direct physical memory access and kernel manipulation. Use responsibly:

- Requires root or CAP_NET_RAW
- Incorrect use can crash the kernel
- For defensive security research only
- Test on non-production devices first

## License

Same as the kernel module (see main README).
