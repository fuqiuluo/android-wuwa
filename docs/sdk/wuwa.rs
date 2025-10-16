//! WuWa kernel driver SDK for ARM64 Android 6.1+
//!
//! Provides userspace bindings to the WuWa kernel module via hijacked socket protocol family.
//!
//! # Discovery
//!
//! The driver registers as a custom socket protocol family. Discovery algorithm:
//! 1. Probe uncommon AF_* families with SOCK_SEQPACKET
//! 2. Driver responds with -ENOKEY
//! 3. Create SOCK_RAW socket on identified family
//! 4. Issue ioctl commands on the socket fd
//!
//! # Usage
//!
//! ```no_run
//! let driver = WuWaDriver::new()?;
//! let pid = driver.find_process("target_app")?;
//! let base = driver.get_module_base(pid, "lib.so", 0x4)?;
//! let val: u32 = driver.read(pid, base + 0x1000)?;
//! ```
//!
//! # Safety
//!
//! This SDK provides direct physical memory access and kernel-level process manipulation.
//! Requires root or CAP_NET_RAW. For defensive security research only.

use std::ffi::c_void;
use std::os::fd::{AsFd, AsRawFd, OwnedFd};
use anyhow::anyhow;
use std::mem::{MaybeUninit, size_of};
use std::ptr::NonNull;
use log::{debug, error, info, log_enabled, Level};
use nix::errno::Errno;
use nix::{libc, NixPath};
use nix::libc::{c_int, free, getsockopt, ioctl, malloc, mmap, size_t, sockaddr_in, socklen_t, pid_t, _IOWR, _IOR, Ioctl};
use nix::sys::socket::{socket, AddressFamily, SockFlag, SockType};

// IOCTL command definitions (magic number 'W')
const WUWA_IOCTL_ADDR_TRANSLATE: Ioctl = _IOWR::<WuwaAddrTranslateCmd>(b'W' as u32, 1);
const WUWA_IOCTL_DEBUG_INFO: Ioctl = _IOR::<WuwaDebugInfoCmd>(b'W' as u32, 2);
const WUWA_IOCTL_AT_S1E0R: Ioctl = _IOWR::<WuwaAtS1e0rCmd>(b'W' as u32, 3);
const WUWA_IOCTL_PAGE_INFO: Ioctl = _IOWR::<WuwaPageInfoCmd>(b'W' as u32, 4);
const WUWA_IOCTL_DMA_BUF_CREATE: Ioctl = _IOWR::<WuwaDmaBufCreateCmd>(b'W' as u32, 5);
const WUWA_IOCTL_PTE_MAPPING: Ioctl = _IOWR::<WuwaPteMappingCmd>(b'W' as u32, 6);
const WUWA_IOCTL_PAGE_TABLE_WALK: Ioctl = _IOWR::<WuwaPageTableWalkCmd>(b'W' as u32, 7);
const WUWA_IOCTL_COPY_PROCESS: Ioctl = _IOWR::<WuwaCopyProcessCmd>(b'W' as u32, 8);
const WUWA_IOCTL_READ_MEMORY: Ioctl = _IOWR::<WuwaReadPhysicalMemoryCmd>(b'W' as u32, 9);
const WUWA_IOCTL_GET_MODULE_BASE: Ioctl = _IOWR::<WuwaGetModuleBaseCmd>(b'W' as u32, 10);
const WUWA_IOCTL_FIND_PROCESS: Ioctl = _IOWR::<WuwaFindProcCmd>(b'W' as u32, 11);
const WUWA_IOCTL_WRITE_MEMORY: Ioctl = _IOWR::<WuwaWritePhysicalMemoryCmd>(b'W' as u32, 12);
const WUWA_IOCTL_IS_PROCESS_ALIVE: Ioctl = _IOWR::<WuwaIsProcAliveCmd>(b'W' as u32, 13);
const WUWA_IOCTL_HIDE_PROCESS: Ioctl = _IOWR::<WuwaHideProcCmd>(b'W' as u32, 14);
const WUWA_IOCTL_GIVE_ROOT: Ioctl = _IOWR::<WuwaGiveRootCmd>(b'W' as u32, 15);
const WUWA_IOCTL_READ_MEMORY_IOREMAP: Ioctl = _IOWR::<WuwaReadPhysicalMemoryIoremapCmd>(b'W' as u32, 16);
const WUWA_IOCTL_WRITE_MEMORY_IOREMAP: Ioctl = _IOWR::<WuwaWritePhysicalMemoryIoremapCmd>(b'W' as u32, 17);
const WUWA_IOCTL_BIND_PROC: Ioctl = _IOWR::<WuwaBindProcCmd>(b'W' as u32, 18);

// Command structures matching kernel definitions

#[repr(C)]
pub struct WuwaAddrTranslateCmd {
    pub phy_addr: u64,
    pub pid: pid_t,
    pub va: usize,
}

#[repr(C)]
pub struct WuwaDebugInfoCmd {
    pub ttbr0_el1: u64,
    pub task_struct: u64,
    pub mm_struct: u64,
    pub pgd_addr: u64,
    pub pgd_phys_addr: u64,
    pub mm_asid: u64,
    pub mm_right: u32,
}

#[repr(C)]
pub struct WuwaAtS1e0rCmd {
    pub phy_addr: u64,
    pub pid: pid_t,
    pub va: usize,
}

#[repr(C)]
pub union PageUnion {
    pub mapcount: i32,
    pub page_type: u32,
}

#[repr(C)]
pub struct KernelPage {
    pub flags: u64,
    pub union_field: PageUnion,
    pub refcount: i32,
    pub phy_addr: u64,
}

#[repr(C)]
pub struct WuwaPageInfoCmd {
    pub pid: pid_t,
    pub va: usize,
    pub page: KernelPage,
}

#[repr(C)]
pub struct WuwaDmaBufCreateCmd {
    pub pid: pid_t,
    pub va: usize,
    pub size: size_t,
    pub fd: c_int,
}

#[repr(C)]
pub struct WuwaPteMappingCmd {
    pub pid: pid_t,
    pub start_addr: usize,
    pub num_pages: size_t,
    pub hide: c_int,
}

#[repr(C)]
pub struct WuwaPageTableWalkCmd {
    pub pid: pid_t,
}

#[repr(C)]
pub struct WuwaCopyProcessCmd {
    pub pid: pid_t,
    pub fn_ptr: *mut c_void,
    pub child_stack: *mut c_void,
    pub child_stack_size: size_t,
    pub flags: u64,
    pub arg: *mut c_void,
    pub child_tid: *mut c_int,
}

#[repr(C)]
pub struct WuwaReadPhysicalMemoryCmd {
    pub pid: pid_t,
    pub src_va: usize,
    pub dst_va: usize,
    pub size: size_t,
    pub phy_addr: usize,
}

#[repr(C)]
pub struct WuwaWritePhysicalMemoryCmd {
    pub pid: pid_t,
    pub src_va: usize,
    pub dst_va: usize,
    pub size: size_t,
    pub phy_addr: usize,
}

#[repr(C)]
pub struct WuwaGetModuleBaseCmd {
    pub pid: pid_t,
    pub name: [u8; 256],
    pub base: usize,
    pub vm_flag: c_int,
}

#[repr(C)]
pub struct WuwaFindProcCmd {
    pub pid: pid_t,
    pub name: [u8; 256],
}

#[repr(C)]
pub struct WuwaIsProcAliveCmd {
    pub pid: pid_t,
    pub alive: i32,
}

#[repr(C)]
pub struct WuwaHideProcCmd {
    pub pid: pid_t,
    pub hide: i32,
}

#[repr(C)]
pub struct WuwaGiveRootCmd {
    pub result: i32,
}

#[repr(C)]
pub struct WuwaReadPhysicalMemoryIoremapCmd {
    pub pid: pid_t,
    pub src_va: usize,
    pub dst_va: usize,
    pub size: size_t,
    pub phy_addr: usize,
    pub prot: c_int,
}

#[repr(C)]
pub struct WuwaWritePhysicalMemoryIoremapCmd {
    pub pid: pid_t,
    pub src_va: usize,
    pub dst_va: usize,
    pub size: size_t,
    pub phy_addr: usize,
    pub prot: c_int,
}

#[repr(C)]
pub struct WuwaBindProcCmd {
    pub pid: pid_t,
    pub fd: c_int,
}

/// WuWa driver connection handle
pub struct WuWaDriver {
    sock: OwnedFd,
}

impl WuWaDriver {
    /// Discover driver by probing address families
    fn driver_id() -> Result<OwnedFd, anyhow::Error> {
        let address_families = [
            AddressFamily::Decnet,
            AddressFamily::NetBeui,
            AddressFamily::Security,
            AddressFamily::Key,
            AddressFamily::Netlink,
            AddressFamily::Packet,
            AddressFamily::Ash,
            AddressFamily::Econet,
            AddressFamily::AtmSvc,
            AddressFamily::Rds,
            AddressFamily::Sna,
            AddressFamily::Irda,
            AddressFamily::Pppox,
            AddressFamily::Wanpipe,
            AddressFamily::Llc,
            AddressFamily::Can,
            AddressFamily::Tipc,
            AddressFamily::Bluetooth,
            AddressFamily::Iucv,
            AddressFamily::RxRpc,
            AddressFamily::Isdn,
            AddressFamily::Phonet,
            AddressFamily::Ieee802154,
            AddressFamily::Caif,
            AddressFamily::Alg,
            AddressFamily::Vsock,
        ];

        for af in address_families.iter() {
            match socket(
                *af,
                SockType::SeqPacket,
                SockFlag::empty(),
                None,
            ) {
                Ok(_) => {
                    continue
                }
                Err(Errno::ENOKEY) => {
                    match socket(
                        *af,
                        SockType::Raw,
                        SockFlag::empty(),
                        None,
                    ) {
                        Ok(fd) => {
                            if log_enabled!(Level::Debug) {
                                debug!("WuWa driver found on {:?}", af);
                            }
                            return Ok(fd);
                        }
                        Err(_) => continue,
                    }
                }
                Err(_) => continue,
            }
        }
        Err(anyhow!("WuWa driver not found"))
    }

    /// Connect to WuWa driver. Requires root or CAP_NET_RAW.
    pub fn new() -> Result<Self, anyhow::Error> {
        let sock = Self::driver_id()?;
        Ok(Self { sock })
    }

    /// Software page table walk: VA -> PA translation
    pub fn addr_translate(&self, pid: pid_t, va: usize) -> Result<u64, anyhow::Error> {
        let mut cmd = WuwaAddrTranslateCmd {
            phy_addr: 0,
            pid,
            va,
        };

        unsafe {
            let result = ioctl(self.sock.as_raw_fd(), WUWA_IOCTL_ADDR_TRANSLATE, &mut cmd as *mut _ as *mut c_void);
            if result < 0 {
                return Err(anyhow!("VA->PA translation failed"));
            }
        }

        Ok(cmd.phy_addr)
    }

    /// Get process debug info (TTBR0, task_struct, mm_struct, pgd)
    pub fn get_debug_info(&self, pid: pid_t) -> Result<WuwaDebugInfoCmd, anyhow::Error> {
        let mut cmd = WuwaDebugInfoCmd {
            ttbr0_el1: 0,
            task_struct: 0,
            mm_struct: 0,
            pgd_addr: 0,
            pgd_phys_addr: 0,
            mm_asid: 0,
            mm_right: 0,
        };

        unsafe {
            let result = ioctl(self.sock.as_raw_fd(), WUWA_IOCTL_DEBUG_INFO, &mut cmd as *mut _ as *mut c_void);
            if result < 0 {
                return Err(anyhow!("Failed to get debug info"));
            }
        }

        Ok(cmd)
    }

    /// Hardware AT S1E0R instruction: VA -> PA (faster than software walk)
    pub fn at_s1e0r(&self, pid: pid_t, va: usize) -> Result<u64, anyhow::Error> {
        let mut cmd = WuwaAtS1e0rCmd {
            phy_addr: 0,
            pid,
            va,
        };

        unsafe {
            let result = ioctl(self.sock.as_raw_fd(), WUWA_IOCTL_AT_S1E0R, &mut cmd as *mut _ as *mut c_void);
            if result < 0 {
                return Err(anyhow!("AT S1E0R failed"));
            }
        }

        Ok(cmd.phy_addr)
    }

    /// Query page flags, refcount, mapcount at VA
    pub fn get_page_info(&self, pid: pid_t, va: usize) -> Result<KernelPage, anyhow::Error> {
        let mut cmd = WuwaPageInfoCmd {
            pid,
            va,
            page: KernelPage {
                flags: 0,
                union_field: PageUnion { mapcount: 0 },
                refcount: 0,
                phy_addr: 0,
            },
        };

        unsafe {
            let result = ioctl(self.sock.as_raw_fd(), WUWA_IOCTL_PAGE_INFO, &mut cmd as *mut _ as *mut c_void);
            if result < 0 {
                return Err(anyhow!("Failed to get page info"));
            }
        }

        Ok(cmd.page)
    }

    /// Export process memory region as dma-buf fd for zero-copy sharing
    pub fn create_dma_buf(&self, pid: pid_t, va: usize, size: size_t) -> Result<c_int, anyhow::Error> {
        let mut cmd = WuwaDmaBufCreateCmd {
            pid,
            va,
            size,
            fd: -1,
        };

        unsafe {
            let result = ioctl(self.sock.as_raw_fd(), WUWA_IOCTL_DMA_BUF_CREATE, &mut cmd as *mut _ as *mut c_void);
            if result < 0 {
                return Err(anyhow!("DMA-BUF creation failed"));
            }
        }

        Ok(cmd.fd)
    }

    /// Direct PTE manipulation (hide/unhide pages)
    pub fn pte_mapping(&self, pid: pid_t, start_addr: usize, num_pages: size_t, hide: bool) -> Result<(), anyhow::Error> {
        let mut cmd = WuwaPteMappingCmd {
            pid,
            start_addr,
            num_pages,
            hide: if hide { 1 } else { 0 },
        };

        unsafe {
            let result = ioctl(self.sock.as_raw_fd(), WUWA_IOCTL_PTE_MAPPING, &mut cmd as *mut _ as *mut c_void);
            if result < 0 {
                return Err(anyhow!("PTE mapping failed"));
            }
        }

        Ok(())
    }

    /// Dump complete page table to dmesg
    pub fn page_table_walk(&self, pid: pid_t) -> Result<(), anyhow::Error> {
        let mut cmd = WuwaPageTableWalkCmd { pid };

        unsafe {
            let result = ioctl(self.sock.as_raw_fd(), WUWA_IOCTL_PAGE_TABLE_WALK, &mut cmd as *mut _ as *mut c_void);
            if result < 0 {
                return Err(anyhow!("Page table walk failed"));
            }
        }

        Ok(())
    }

    /// Read physical memory via phys_to_virt (max 50MB per call)
    pub fn read_physical_memory(&self, pid: pid_t, src_va: usize, dst_va: usize, size: size_t) -> Result<usize, anyhow::Error> {
        let mut cmd = WuwaReadPhysicalMemoryCmd {
            pid,
            src_va,
            dst_va,
            size,
            phy_addr: 0,
        };

        unsafe {
            let result = ioctl(self.sock.as_raw_fd(), WUWA_IOCTL_READ_MEMORY, &mut cmd as *mut _ as *mut c_void);
            if result < 0 {
                return Err(anyhow!("Physical memory read failed: va=0x{:x} size={}", src_va, size));
            }
        }

        Ok(cmd.phy_addr)
    }

    /// Write physical memory via phys_to_virt (max 50MB per call)
    pub fn write_physical_memory(&self, pid: pid_t, src_va: usize, dst_va: usize, size: size_t) -> Result<usize, anyhow::Error> {
        let mut cmd = WuwaWritePhysicalMemoryCmd {
            pid,
            src_va,
            dst_va,
            size,
            phy_addr: 0,
        };

        unsafe {
            let result = ioctl(self.sock.as_raw_fd(), WUWA_IOCTL_WRITE_MEMORY, &mut cmd as *mut _ as *mut c_void);
            if result < 0 {
                return Err(anyhow!("Physical memory write failed: va=0x{:x} size={}", src_va, size));
            }
        }

        Ok(cmd.phy_addr)
    }

    /// Type-safe read of arbitrary struct from target process
    pub fn read<T: Sized>(&self, pid: pid_t, src_va: usize) -> Result<T, anyhow::Error> {
        let mut buffer: MaybeUninit<T> = MaybeUninit::uninit();
        let buffer_ptr = buffer.as_mut_ptr() as usize;
        let size = size_of::<T>();

        self.read_physical_memory(pid, src_va, buffer_ptr, size)?;

        unsafe {
            Ok(buffer.assume_init())
        }
    }

    /// Type-safe write of arbitrary struct to target process
    pub fn write<T: Sized>(&self, pid: pid_t, dst_va: usize, value: &T) -> Result<(), anyhow::Error> {
        let value_ptr = value as *const T as usize;
        let size = size_of::<T>();

        self.write_physical_memory(pid, value_ptr, dst_va, size)?;

        Ok(())
    }

    /// Read Unreal Engine FString from target process
    pub fn read_fstring(&self, pid: pid_t, addr: usize) -> Result<String, anyhow::Error> {
        let len = self.read::<u32>(pid, addr + 8)? as usize;
        if len == 0 {
            return Ok("".to_string());
        }
        let player_name_private = self.read::<usize>(pid, addr)?;
        let mut player_name = vec![];
        unsafe { self.read_to_utf8(pid, player_name_private as *const u16, &mut player_name, len - 1)?; }
        String::from_utf8(player_name).map_err(|e| anyhow!("FString decode failed: {:?}", e))
    }

    /// Read FString with length limit
    pub fn read_fstring_limit(&self, pid: pid_t, addr: usize, max_len: usize) -> Result<String, anyhow::Error> {
        let len = self.read::<u32>(pid, addr + 8)? as usize;
        if len == 0 {
            return Ok("".to_string());
        }

        if len > max_len {
            return Err(anyhow!("FString length {} exceeds limit {}", len, max_len));
        }

        let player_name_private = self.read::<usize>(pid, addr)?;
        let mut player_name = vec![];
        unsafe { self.read_to_utf8(pid, player_name_private as *const u16, &mut player_name, len - 1)?; }
        String::from_utf8(player_name).map_err(|e| anyhow!("FString decode failed: {:?}", e))
    }

    /// Convert UTF-16 in target process to UTF-8 in local buffer
    pub unsafe fn read_to_utf8(&self, pid: pid_t, ptr: *const u16, buf: &mut Vec<u8>, length: usize) -> Result<(), anyhow::Error> {
        let mut temp_utf16 = ptr;
        let end = ptr.add(length);

        while temp_utf16 < end {
            let utf16_char = self.read::<u16>(pid, temp_utf16 as usize)?;

            if utf16_char <= 0x007F {
                buf.push(utf16_char as u8);
            } else if utf16_char <= 0x07FF {
                buf.push(((utf16_char >> 6) | 0xC0) as u8);
                buf.push(((utf16_char & 0x3F) | 0x80) as u8);
            } else {
                buf.push(((utf16_char >> 12) | 0xE0) as u8);
                buf.push(((utf16_char >> 6 & 0x3F) | 0x80) as u8);
                buf.push(((utf16_char & 0x3F) | 0x80) as u8);
            }

            temp_utf16 = temp_utf16.add(1);
        }
        Ok(())
    }

    /// Get module/library base address in target process
    ///
    /// # Arguments
    /// * `vm_flag` - VM flags to filter (e.g., 0x4 for VM_EXEC)
    pub fn get_module_base(&self, pid: pid_t, name: &str, vm_flag: c_int) -> Result<usize, anyhow::Error> {
        let mut cmd = WuwaGetModuleBaseCmd {
            pid,
            name: [0; 256],
            base: 0,
            vm_flag,
        };

        let name_bytes = name.as_bytes();
        let copy_len = std::cmp::min(name_bytes.len(), 255);
        cmd.name[..copy_len].copy_from_slice(&name_bytes[..copy_len]);

        unsafe {
            let result = ioctl(self.sock.as_raw_fd(), WUWA_IOCTL_GET_MODULE_BASE, &mut cmd as *mut _ as *mut c_void);
            if result < 0 {
                return Err(anyhow!("Module base query failed"));
            }
        }

        Ok(cmd.base)
    }

    /// Find process by name, returns PID
    pub fn find_process(&self, name: &str) -> Result<pid_t, anyhow::Error> {
        let mut cmd = WuwaFindProcCmd {
            pid: 0,
            name: [0; 256],
        };

        let name_bytes = name.as_bytes();
        let copy_len = std::cmp::min(name_bytes.len(), 255);
        cmd.name[..copy_len].copy_from_slice(&name_bytes[..copy_len]);

        unsafe {
            let result = ioctl(self.sock.as_raw_fd(), WUWA_IOCTL_FIND_PROCESS, &mut cmd as *mut _ as *mut c_void);
            if result < 0 {
                return Err(anyhow!("Process search failed"));
            }
        }

        if cmd.pid == 0 {
            return Err(anyhow!("Process not found"));
        }

        Ok(cmd.pid)
    }

    /// Check if process is alive
    pub fn is_process_alive(&self, pid: pid_t) -> Result<bool, anyhow::Error> {
        let mut cmd = WuwaIsProcAliveCmd {
            pid,
            alive: 0,
        };

        unsafe {
            let result = ioctl(self.sock.as_raw_fd(), WUWA_IOCTL_IS_PROCESS_ALIVE, &mut cmd as *mut _ as *mut c_void);
            if result < 0 {
                return Err(anyhow!("Process liveness check failed"));
            }
        }

        Ok(cmd.alive != 0)
    }

    /// Hide/unhide process from system visibility
    pub fn hide_process(&self, pid: pid_t, hide: bool) -> Result<(), anyhow::Error> {
        let mut cmd = WuwaHideProcCmd {
            pid,
            hide: if hide { 1 } else { 0 },
        };

        unsafe {
            let result = ioctl(self.sock.as_raw_fd(), WUWA_IOCTL_HIDE_PROCESS, &mut cmd as *mut _ as *mut c_void);
            if result < 0 {
                return Err(anyhow!("Process hide/unhide failed"));
            }
        }

        Ok(())
    }

    /// Escalate current process to root (uid=0, gid=0)
    pub fn give_root(&self) -> Result<(), anyhow::Error> {
        let mut cmd = WuwaGiveRootCmd {
            result: 0,
        };

        unsafe {
            let result = ioctl(self.sock.as_raw_fd(), WUWA_IOCTL_GIVE_ROOT, &mut cmd as *mut _ as *mut c_void);
            if result < 0 {
                return Err(anyhow!("Root escalation failed"));
            }
        }

        if cmd.result < 0 {
            return Err(anyhow!("Root escalation rejected: error {}", cmd.result));
        }

        Ok(())
    }

    /// Read physical memory via ioremap with memory attribute control
    ///
    /// # Arguments
    /// * `prot` - Memory type (use MT_* constants from kernel)
    pub fn read_physical_memory_ioremap(&self, pid: pid_t, src_va: usize, dst_va: usize, size: size_t, prot: c_int) -> Result<usize, anyhow::Error> {
        let mut cmd = WuwaReadPhysicalMemoryIoremapCmd {
            pid,
            src_va,
            dst_va,
            size,
            phy_addr: 0,
            prot,
        };

        unsafe {
            let result = ioctl(self.sock.as_raw_fd(), WUWA_IOCTL_READ_MEMORY_IOREMAP, &mut cmd as *mut _ as *mut c_void);
            if result < 0 {
                return Err(anyhow!("ioremap read failed: va=0x{:x} size={}", src_va, size));
            }
        }

        Ok(cmd.phy_addr)
    }

    /// Write physical memory via ioremap with memory attribute control
    ///
    /// # Arguments
    /// * `prot` - Memory type (use MT_* constants from kernel)
    pub fn write_physical_memory_ioremap(&self, pid: pid_t, src_va: usize, dst_va: usize, size: size_t, prot: c_int) -> Result<usize, anyhow::Error> {
        let mut cmd = WuwaWritePhysicalMemoryIoremapCmd {
            pid,
            src_va,
            dst_va,
            size,
            phy_addr: 0,
            prot,
        };

        unsafe {
            let result = ioctl(self.sock.as_raw_fd(), WUWA_IOCTL_WRITE_MEMORY_IOREMAP, &mut cmd as *mut _ as *mut c_void);
            if result < 0 {
                return Err(anyhow!("ioremap write failed: va=0x{:x} size={}", src_va, size));
            }
        }

        Ok(cmd.phy_addr)
    }

    /// Bind process, returns anonymous file descriptor
    pub fn bind_process(&self, pid: pid_t) -> Result<c_int, anyhow::Error> {
        let mut cmd = WuwaBindProcCmd {
            pid,
            fd: -1,
        };

        unsafe {
            let result = ioctl(self.sock.as_raw_fd(), WUWA_IOCTL_BIND_PROC, &mut cmd as *mut _ as *mut c_void);
            if result < 0 {
                return Err(anyhow!("Process bind failed"));
            }
        }

        Ok(cmd.fd)
    }

    /// Copy process with custom function pointer and stack
    pub fn copy_process(&self, pid: pid_t, fn_ptr: *mut c_void, child_stack: *mut c_void, child_stack_size: size_t, flags: u64, arg: *mut c_void) -> Result<c_int, anyhow::Error> {
        let mut cmd = WuwaCopyProcessCmd {
            pid,
            fn_ptr,
            child_stack,
            child_stack_size,
            flags,
            arg,
            child_tid: std::ptr::null_mut(),
        };

        unsafe {
            let result = ioctl(self.sock.as_raw_fd(), WUWA_IOCTL_COPY_PROCESS, &mut cmd as *mut _ as *mut c_void);
            if result < 0 {
                return Err(anyhow!("Process copy failed"));
            }
        }

        Ok(0)
    }
}
