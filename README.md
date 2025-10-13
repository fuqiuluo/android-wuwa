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

# How to Connect to the WuWa Driver

[Click me](docs/FindDriver.md) for the connection guide.

# Heads-up

- Tested only on my device running kernel 6.1.
- No guarantees on other versions; treat this as a proof of concept.
- Everything not explicitly marked “planned” has been run and verified on my setup—use at your own risk.

# Thanks

- [Diamorphine](https://github.com/m0nad/Diamorphine)
- [kernel-inline-hook-framework](https://github.com/WeiJiLab/kernel-inline-hook-framework)
