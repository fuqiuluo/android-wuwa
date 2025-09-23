Join Group: 943577597

# Features

- [x] Custom protocol family for user-space (EL0) 
- [x] Virtual ⇄ physical address translation for any process
- [x] Physical page descriptor lookup (flags, ref_count, and friends)
- [x] One-step mapping of a process’s virtual memory into a DMA-BUF fd
- [x] Page-table injections that bypass VMA
- [x] Dump a process’s memory map straight to dmesg for easy inspection
- [ ] Low-level page-table permission tweaks plus VMA permission masking 
- [x] Arbitrary physical memory read/write 
- [ ] Memory-scan traps for stealthy injection protection 
- [ ] Cross-process memory remap to build shared memory
- [ ] EL1 channel based on exception vectors
- [x] Kprobe blacklist bypass/disable
- [x] Determine if the process is alive
- [x] Get Module Base Addr
- [x] Get process PID

# Heads-up

- Tested only on my device running kernel 6.1.
- No guarantees on other versions; treat this as a proof of concept.
- Everything not explicitly marked “planned” has been run and verified on my setup—use at your own risk.
