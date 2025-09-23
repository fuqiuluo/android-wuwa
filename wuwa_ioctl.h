#ifndef WUWA_IOCTL_H
#define WUWA_IOCTL_H

#include "wuwa_common.h"

struct wuwa_addr_translate_cmd {
    phys_addr_t phy_addr; /* Output: Physical address after translation */
    pid_t pid; /* Input: Process ID owning the virtual address */
    uintptr_t va; /* Input: Virtual address to translate */
};

struct wuwa_debug_info_cmd {
    u64 ttbr0_el1; /* Translation Table Base Register 0 */
    u64 task_struct;
    u64 mm_struct; /* Memory Management Structure */
    u64 pgd_addr; /* Page Global Directory address */
    u64 pgd_phys_addr;
    u64 mm_asid; /* Address Space ID */
    u32 mm_right;
};

struct wuwa_at_s1e0r_cmd {
    phys_addr_t phy_addr;
    pid_t pid;
    uintptr_t va;
};

struct kernel_page {
	unsigned long flags;		/* Atomic flags, some possibly */
    union {		/* This union is 4 bytes in size. */
        /*
         * If the page can be mapped to userspace, encodes the number
         * of times this page is referenced by a page table.
         */
        atomic_t _mapcount;

        /*
         * If the page is neither PageSlab nor mappable to userspace,
         * the value stored here may help determine what this page
         * is used for.  See page-flags.h for a list of page types
         * which are currently stored here.
         */
        unsigned int page_type;
    };

    /* Usage count. *DO NOT USE DIRECTLY*. See page_ref.h */
    atomic_t _refcount;

    phys_addr_t phy_addr;
};

struct wuwa_page_info_cmd {
    pid_t pid;
    uintptr_t va;

    struct kernel_page page; /* Output: Page information */
};

struct wuwa_dma_buf_create_cmd {
    pid_t pid;
    uintptr_t va;
    size_t size;
    int fd;
};

struct wuwa_pte_mapping_cmd {
    pid_t pid;
    uintptr_t start_addr;
    size_t num_pages;
    int hide; /* Hide the page if true */
};

struct wuwa_page_table_walk_cmd {
    pid_t pid;
};

struct wuwa_copy_process_cmd {
    pid_t pid;
    int (* __user fn)(void*);
    void* __user child_stack;
    size_t child_stack_size;
    u64 flags;
    void* __user arg;

    int __user* child_tid;
};

struct wuwa_read_physical_memory_cmd {
    pid_t pid; /* Input: Process ID owning the virtual address */
    uintptr_t src_va; /* Input: Virtual address to access */
    uintptr_t dst_va; /* Input: Virtual address to write */
    size_t size; /* Input: Size of memory to read */
    uintptr_t phy_addr; /* Output: Physical address of the source virtual address */
};

struct wuwa_write_physical_memory_cmd {
	pid_t pid; /* Input: Process ID owning the virtual address */
	uintptr_t src_va; /* Input: Virtual address to access */
	uintptr_t dst_va; /* Input: Virtual address to write */
	size_t size; /* Input: Size of memory to read */
	uintptr_t phy_addr; /* Output: Physical address of the source virtual address */
};

struct wuwa_get_module_base_cmd {
    pid_t pid; /* Input: Process ID */
    char name[256]; /* Input: Module name */
    uintptr_t base; /* Output: Base address of the module */
    int vm_flag; /* Input: VM flag to filter (e.g., VM_EXEC) */
};

struct wuwa_find_proc_cmd {
    pid_t pid; /* Output: Process ID */
    char name[256]; /* Input: Process name */
};

struct wuwa_is_proc_alive_cmd {
    pid_t pid; /* Output: Process ID */
    int alive; /* Output: 1 if alive, 0 if not */
};

/* IOCTL command for virtual to physical address translation */
#define WUWA_IOCTL_ADDR_TRANSLATE       _IOWR('W', 1, struct wuwa_addr_translate_cmd)
/* IOCTL command for debugging information */
#define WUWA_IOCTL_DEBUG_INFO   _IOR('W', 2, struct wuwa_debug_info_cmd)
/* * IOCTL command for va to phys translation */
#define WUWA_IOCTL_AT_S1E0R        _IOWR('W', 3, struct wuwa_at_s1e0r_cmd)
/* IOCTL command for getting page information at a specific virtual address */
#define WUWA_IOCTL_PAGE_INFO  _IOWR('W', 4, struct wuwa_page_info_cmd)
/* IOCTL command for creating a DMA buffer at a specific virtual address */
#define WUWA_IOCTL_DMA_BUF_CREATE _IOWR('W', 5, struct wuwa_dma_buf_create_cmd)
/* IOCTL command for getting PTE mapping information */
#define WUWA_IOCTL_PTE_MAPPING _IOWR('W', 6, struct wuwa_pte_mapping_cmd)
/* IOCTL command for page table walk */
#define WUWA_IOCTL_PAGE_TABLE_WALK _IOWR('W', 7, struct wuwa_page_table_walk_cmd)
#define WUWA_IOCTL_COPY_PROCESS _IOWR('W', 8, struct wuwa_copy_process_cmd)
#define WUWA_IOCTL_READ_MEMORY _IOWR('W', 9, struct wuwa_read_physical_memory_cmd)
#define WUWA_IOCTL_GET_MODULE_BASE _IOWR('W', 10, struct wuwa_get_module_base_cmd)
#define WUWA_IOCTL_FIND_PROCESS _IOWR('W', 11, struct wuwa_find_proc_cmd)
#define WUWA_IOCTL_WRITE_MEMORY _IOWR('W', 12, struct wuwa_write_physical_memory_cmd)
#define WUWA_IOCTL_IS_PROCESS_ALIVE _IOWR('W', 13, struct wuwa_is_proc_alive_cmd)


int do_vaddr_translate(struct socket *sock, void __user * arg);
int do_debug_info(struct socket *sock, void __user * arg);
int do_at_s1e0r(struct socket *sock, void __user * arg);
int do_get_page_info(struct socket *sock, void __user * arg);
int do_create_dma_buf(struct socket *sock, void __user * arg);
int do_pte_mapping(struct socket *sock, void __user * arg);
int do_page_table_walk(struct socket *sock, void __user * arg);
int do_copy_process(struct socket *sock, void __user * arg);
int do_read_physical_memory(struct socket *sock, void __user * arg);
int do_get_module_base(struct socket *sock, void __user * arg);
int do_find_process(struct socket *sock, void __user * arg);
int do_write_physical_memory(struct socket *sock, void __user * arg);
int do_is_process_alive(struct socket *sock, void __user * arg);

typedef int (*ioctl_handler_t)(struct socket *sock, void __user * arg);

static const struct ioctl_cmd_map {
    unsigned int cmd;
    ioctl_handler_t handler;
} ioctl_handlers[] = {
    { .cmd = WUWA_IOCTL_ADDR_TRANSLATE, .handler = do_vaddr_translate },
    { .cmd = WUWA_IOCTL_DEBUG_INFO, .handler = do_debug_info },
    { .cmd = WUWA_IOCTL_AT_S1E0R, .handler = do_at_s1e0r }, /* Reusing the same handler for AT VA */
    { .cmd = WUWA_IOCTL_PAGE_INFO, .handler = do_get_page_info },
    { .cmd = WUWA_IOCTL_DMA_BUF_CREATE, .handler = do_create_dma_buf },
    { .cmd = WUWA_IOCTL_PTE_MAPPING, .handler = do_pte_mapping },
    { .cmd = WUWA_IOCTL_PAGE_TABLE_WALK, .handler = do_page_table_walk },
    { .cmd = WUWA_IOCTL_COPY_PROCESS, .handler = do_copy_process },
    { .cmd = WUWA_IOCTL_READ_MEMORY, .handler = do_read_physical_memory },
    { .cmd = WUWA_IOCTL_GET_MODULE_BASE, .handler = do_get_module_base },
    { .cmd = WUWA_IOCTL_FIND_PROCESS, .handler = do_find_process },
    { .cmd = WUWA_IOCTL_WRITE_MEMORY, .handler = do_write_physical_memory },
    { .cmd = WUWA_IOCTL_IS_PROCESS_ALIVE, .handler = do_is_process_alive },
    { .cmd = 0, .handler = NULL } /* Sentinel to mark end of array */
};

#endif //WUWA_IOCTL_H
