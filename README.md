[![Ask DeepWiki](https://deepwiki.com/badge.svg)](https://deepwiki.com/fuqiuluo/android-wuwa)

> Join OICQ Group: 943577597
> 
> 
> 
> Kernel Driver Development Kit: [Ylarod/ddk](https://github.com/Ylarod/ddk)

# Features

## Kernel Protection Bypass
- [x] **CFI Bypass** - Automatically patch kernel CFI check functions to disable Control Flow Integrity protection
- [x] **Kprobe Blacklist Disable** - Clear kprobe blacklist to allow hooking protected kernel functions (kernel 6.1+)

## Address Translation
- [x] **Virtual Address Translation** - Software page table walking for virtual to physical address translation
- [x] **Hardware Address Translation** - Using ARM64 AT instruction for faster and more accurate translation
- [x] **PTE Direct Mapping** - Create mappings directly in page tables bypassing VMA, supports stealth mode
- [x] **Page Table Walk** - Traverse complete process page tables and dump to dmesg

## Memory Access
- [x] **Physical Memory R/W** - Direct access via phys_to_virt, up to 50MB per operation
- [x] **ioremap R/W** - Support multiple memory types (Normal/Device/Write-Through, etc.)

## Process Management
- [x] **Find Process** - Locate process PID by name
- [x] **Liveness Check** - Check if process is alive
- [x] **Privilege Escalation** - Elevate current process to root
- [x] **Get Module Base** - Query module load address in target process
- [ ] **Hide Process** - Set process invisible flag
- [x] **Hide Module** - Hide kernel module from system

## Advanced Features
- [x] **DMA Buffer Export** - Export process memory as dma-buf fd for zero-copy sharing
- [x] **Page Info Query** - Retrieve page flags/refcount/mapcount information
- [x] **Debug Info** - Get kernel structures like TTBR0/task_struct/mm_struct/pgd
- [x] **Custom Protocol Family** - Socket-based userspace communication interface
- [ ] **Remote Thread Creation** - Create new thread in target process (not implemented yet)

# Build Instructions

## Option 1: Use DDK (Recommended)

[DDK (Kernel Driver Development Kit)](https://github.com/Ylarod/ddk) provides a containerized build environment with pre-configured kernel sources.

### Prerequisites

- Docker installed and running
- DDK tool installed

### Install DDK

```bash
sudo curl -fsSL https://raw.githubusercontent.com/Ylarod/ddk/main/scripts/ddk -o /usr/local/bin/ddk
sudo chmod +x /usr/local/bin/ddk
```

### Build with DDK

The build script supports multiple commands and options (supports Chinese/English based on system locale):

**Commands:**
```bash
./scripts/build-ddk.sh build [target]    # Build kernel module
./scripts/build-ddk.sh clean [target]    # Clean build artifacts
./scripts/build-ddk.sh compdb [target]   # Generate compile_commands.json for IDE
./scripts/build-ddk.sh list              # List installed DDK images
```

**Build Examples:**
```bash
# Build with default target (android12-5.10)
./scripts/build-ddk.sh build

# Build for specific target
./scripts/build-ddk.sh build android14-6.1

# Build with stripped debug symbols (smaller file size)
./scripts/build-ddk.sh build -t android14-6.1 --strip

# Clean build artifacts
./scripts/build-ddk.sh clean android12-5.10

# Generate compile_commands.json for IDE support
./scripts/build-ddk.sh compdb
```

Available targets: Check [DDK Container Versions](https://github.com/Ylarod/ddk/pkgs/container/ddk/versions)

**Note**: On some systems, Docker requires root privileges. If you encounter permission errors, run the script with `sudo`.

## Option 2: Download from CI

Pre-built kernel modules are available from GitHub Actions CI builds:

1. Go to [Actions tab](../../actions)
2. Select the latest successful workflow run
3. Download the build artifact for your kernel version

## Option 3: Manual Build

If you have your own Android kernel source tree:

```bash
# Set kernel source path
export KERNEL_SRC=/path/to/android/kernel/source

# Build the module
make

# Clean build artifacts
make clean
```

**Note**: Manual builds are only tested on kernel 6.1. No guarantees on other versions.

# How to Connect to the WuWa Driver

[Click me](docs/FindDriver.md) for the connection guide.

# Heads-up

- Tested only on my device running kernel 6.1.
- No guarantees on other versions; treat this as a proof of concept.
- Everything not explicitly marked “planned” has been run and verified on my setup—use at your own risk.

# Thanks

- [Diamorphine](https://github.com/m0nad/Diamorphine)
- [kernel-inline-hook-framework](https://github.com/WeiJiLab/kernel-inline-hook-framework)
