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

// ioctl命令常量 - 使用libc标准函数生成
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


// 数据结构定义
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

pub struct WuWaDriver {
    sock: OwnedFd,
}

impl WuWaDriver {
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
                                debug!("WuWaDriver accept family: {:?}", af);
                            }
                            return Ok(fd);
                        }
                        Err(_) => continue,
                    }
                }
                Err(_) => continue,
            }
        }
        Err(anyhow!("无法找到Wuwa协议!"))
    }

    pub fn new() -> Result<Self, anyhow::Error> {
        let sock = Self::driver_id()?;
        Ok(Self {
            sock,
        })
    }

    pub fn addr_translate(&self, pid: pid_t, va: usize) -> Result<u64, anyhow::Error> {
        let mut cmd = WuwaAddrTranslateCmd {
            phy_addr: 0,
            pid,
            va,
        };

        unsafe {
            let result = ioctl(self.sock.as_raw_fd(), WUWA_IOCTL_ADDR_TRANSLATE, &mut cmd as *mut _ as *mut c_void);
            if result < 0 {
                return Err(anyhow!("地址转换失败"));
            }
        }

        Ok(cmd.phy_addr)
    }

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
                return Err(anyhow!("获取调试信息失败"));
            }
        }

        Ok(cmd)
    }

    pub fn at_s1e0r(&self, pid: pid_t, va: usize) -> Result<u64, anyhow::Error> {
        let mut cmd = WuwaAtS1e0rCmd {
            phy_addr: 0,
            pid,
            va,
        };

        unsafe {
            let result = ioctl(self.sock.as_raw_fd(), WUWA_IOCTL_AT_S1E0R, &mut cmd as *mut _ as *mut c_void);
            if result < 0 {
                return Err(anyhow!("AT S1E0R操作失败"));
            }
        }

        Ok(cmd.phy_addr)
    }

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
                return Err(anyhow!("获取页信息失败"));
            }
        }

        Ok(cmd.page)
    }

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
                return Err(anyhow!("创建DMA缓冲区失败"));
            }
        }

        Ok(cmd.fd)
    }

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
                return Err(anyhow!("PTE映射操作失败"));
            }
        }

        Ok(())
    }

    pub fn page_table_walk(&self, pid: pid_t) -> Result<(), anyhow::Error> {
        let mut cmd = WuwaPageTableWalkCmd { pid };

        unsafe {
            let result = ioctl(self.sock.as_raw_fd(), WUWA_IOCTL_PAGE_TABLE_WALK, &mut cmd as *mut _ as *mut c_void);
            if result < 0 {
                return Err(anyhow!("页表遍历失败"));
            }
        }

        Ok(())
    }

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
                return Err(anyhow!("读取物理内存失败: ptr={:x}, size={}", src_va, size));
            }
        }

        Ok(cmd.phy_addr)
    }

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
                return Err(anyhow!("写入物理内存失败: ptr={:x}, size={}", src_va, size));
            }
        }

        Ok(cmd.phy_addr)
    }

    pub fn read<T: Sized>(&self, pid: pid_t, src_va: usize) -> Result<T, anyhow::Error> {
        let mut buffer: MaybeUninit<T> = MaybeUninit::uninit();
        let buffer_ptr = buffer.as_mut_ptr() as usize;
        let size = size_of::<T>();

        self.read_physical_memory(pid, src_va, buffer_ptr, size)?;

        unsafe {
            Ok(buffer.assume_init())
        }
    }

    pub fn write<T: Sized>(&self, pid: pid_t, dst_va: usize, value: &T) -> Result<(), anyhow::Error> {
        let value_ptr = value as *const T as usize;
        let size = size_of::<T>();

        self.write_physical_memory(pid, value_ptr, dst_va, size)?;

        Ok(())
    }

    pub fn read_fstring(&self, pid: pid_t, addr: usize) -> Result<String, anyhow::Error> {
        let len = self.read::<u32>(pid, addr + 8)? as usize;
        if len == 0 {
            return Ok("".to_string());
        }
        let player_name_private = self.read::<usize>(pid, addr)?;
        let mut player_name = vec![];
        unsafe { self.read_to_utf8(pid, player_name_private as *const u16, &mut player_name, len - 1)?; }
        String::from_utf8(player_name).map_err(|e| anyhow!("read fstring failed: {:?}", e))
    }

    pub fn read_fstring_limit(&self, pid: pid_t, addr: usize, max_len: usize) -> Result<String, anyhow::Error> {
        let len = self.read::<u32>(pid, addr + 8)? as usize;
        if len == 0 {
            return Ok("".to_string());
        }

        if len > max_len {
            return Err(anyhow!("fstring length {} exceeds max limit {}", len, max_len));
        }

        let player_name_private = self.read::<usize>(pid, addr)?;
        let mut player_name = vec![];
        unsafe { self.read_to_utf8(pid, player_name_private as *const u16, &mut player_name, len - 1)?; }
        String::from_utf8(player_name).map_err(|e| anyhow!("read fstring failed: {:?}", e))
    }

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
                return Err(anyhow!("获取模块基地址失败"));
            }
        }

        Ok(cmd.base)
    }

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
                return Err(anyhow!("查找进程失败"));
            }
        }

        if cmd.pid == 0 {
            return Err(anyhow!("未找到指定进程"));
        }

        Ok(cmd.pid)
    }

    pub fn is_process_alive(&self, pid: pid_t) -> Result<bool, anyhow::Error> {
        let mut cmd = WuwaIsProcAliveCmd {
            pid,
            alive: 0,
        };

        unsafe {
            let result = ioctl(self.sock.as_raw_fd(), WUWA_IOCTL_IS_PROCESS_ALIVE, &mut cmd as *mut _ as *mut c_void);
            if result < 0 {
                return Err(anyhow!("检查进程存活状态失败"));
            }
        }

        Ok(cmd.alive != 0)
    }
}