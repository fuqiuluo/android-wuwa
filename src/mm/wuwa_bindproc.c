#include "wuwa_bindproc.h"
#include <linux/kernel.h>
#include <linux/mm.h>
#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/scatterlist.h>
#include <linux/slab.h>
#include <linux/version.h>
#include "asm-generic/errno-base.h"
#include "karray_list.h"
#include "linux/anon_inodes.h"
#include "linux/compiler_types.h"
#include "linux/sched/task.h"
#include "linux/types.h"
#include "wuwa_common.h"
#include "wuwa_ioctl.h"
#include "wuwa_page_walk.h"
#include "wuwa_utils.h"

struct wuwa_mapped_page_info {
    uintptr_t phys_addr; /* Physical page address (page-aligned) */
    void* mapped_ptr; /* Kernel virtual address from ioremap */
};

struct wuwa_bindproc_private {
    pid_t pid;
    pgprot_t prot; /* Memory protection type (use WMT_*) */
    struct karray_list* mapped_pages; /* of struct wuwa_mapped_page_info * */
    struct mutex lock; /* Protects mapped_pages access */
};

/* Helper: Find cached mapping for physical page */
static void* find_cached_mapping(struct wuwa_bindproc_private* priv, uintptr_t phys_page) {
    size_t i;
    for (i = 0; i < priv->mapped_pages->size; i++) {
        struct wuwa_mapped_page_info* info = arraylist_get(priv->mapped_pages, i);
        if (info && info->phys_addr == phys_page) {
            return info->mapped_ptr;
        }
    }
    return NULL;
}

/* Helper: Add new mapping to cache */
static int add_cached_mapping(struct wuwa_bindproc_private* priv, uintptr_t phys_page, void* mapped) {
    struct wuwa_mapped_page_info* info = kmalloc(sizeof(*info), GFP_KERNEL);
    if (!info) {
        return -ENOMEM;
    }
    info->phys_addr = phys_page;
    info->mapped_ptr = mapped;

    if (arraylist_add(priv->mapped_pages, info) < 0) {
        kfree(info);
        return -ENOMEM;
    }
    return 0;
}

static ssize_t bindproc_read(struct file* f, char __user* dest_va, size_t size, loff_t* src_va) { return -EINVAL; }

static ssize_t bindproc_write(struct file* f, const char __user* data, size_t size, loff_t* offset) { return -EINVAL; }

struct bp_read_memory_cmd {
    uintptr_t src_va; /* Input: Virtual address to read from */
    uintptr_t dst_va; /* Input: Virtual address to write to */
    size_t size; /* Input: Size of memory to read */
};

struct bp_write_memory_cmd {
    uintptr_t src_va; /* Input: Virtual address to read from */
    uintptr_t dst_va; /* Input: Virtual address to write to */
    size_t size; /* Input: Size of memory to write */
};

#define WUWA_BP_IOCTL_SET_MEMORY_PROT _IOWR('B', 1, int) /* arg: int (WMT_*) */
#define WUWA_BP_IOCTL_READ_MEMORY _IOWR('B', 2, struct bp_read_memory_cmd)
#define WUWA_BP_IOCTL_WRITE_MEMORY _IOWR('B', 3, struct bp_write_memory_cmd)

static long bindproc_ioctl(struct file* f, unsigned int cmd, unsigned long arg) {
    struct wuwa_bindproc_private* private_data = f->private_data;
    int ret = 0;
    if (!private_data) {
        return -EINVAL;
    }

    switch (cmd) {
    case WUWA_BP_IOCTL_SET_MEMORY_PROT:
        {
            int prot;
            pgprot_t new_prot;

            if (copy_from_user(&prot, (int __user*)arg, sizeof(prot))) {
                return -EFAULT;
            }

            if (prot < WMT_NORMAL || prot > WMT_DEVICE_nGnRnE) {
                return -EINVAL;
            }

            if (convert_wmt_to_pgprot(prot, &new_prot) < 0) {
                return -EINVAL;
            }

            if(pgprot_val(new_prot) != pgprot_val(private_data->prot)) {
                /* Clear existing mappings if protection changes */
                size_t i;

                mutex_lock(&private_data->lock);

                for (i = 0; i < private_data->mapped_pages->size; i++) {
                    struct wuwa_mapped_page_info* info = arraylist_get(private_data->mapped_pages, i);
                    if (info) {
                        if (info->mapped_ptr) {
                            iounmap(info->mapped_ptr);
                        }
                        kfree(info);
                    }
                }
                arraylist_clear(private_data->mapped_pages);

                mutex_unlock(&private_data->lock);
            }

            wuwa_info("set memory prot to %d for pid %d\n", prot, private_data->pid);
            return ret;
        }
    case WUWA_BP_IOCTL_READ_MEMORY:
        {
            struct bp_read_memory_cmd cmd;
            if (copy_from_user(&cmd, (struct bp_read_memory_cmd __user*)arg, sizeof(cmd))) {
                return -EFAULT;
            }
            if (cmd.size == 0 || cmd.size > 0x10000) {
                return -EINVAL;
            }
            if (!cmd.src_va || !cmd.dst_va) {
                return -EINVAL;
            }

            uintptr_t va, pa;
            uintptr_t offset, page_start;
            void* mapped;
            size_t bytes_to_read, total_read = 0;

            // Validate size: allow reads up to reasonable limit
            if (cmd.size == 0 || cmd.size > (PAGE_SIZE * 16)) {
                wuwa_err("invalid read size: %zu\n", cmd.size);
                return -EINVAL;
            }

            va = cmd.src_va;
            //wuwa_info("bindproc_read: pid=%d, va=0x%lx, size=%zu\n", private_data->pid, va, cmd.size);

            while (total_read < cmd.size) {
                /* Translate current virtual address to physical */
                ret = translate_process_vaddr(private_data->pid, va + total_read, &pa);
                if (ret < 0) {
                    wuwa_err("failed to translate VA 0x%lx: %d\n", va + total_read, ret);
                    goto out;
                }

                /* Calculate page-aligned address and offset */
                offset = pa & ~PAGE_MASK;
                page_start = pa & PAGE_MASK;

                /* Determine how many bytes we can read from this page */
                bytes_to_read = min_t(size_t, cmd.size - total_read, PAGE_SIZE - offset);

                //wuwa_info("Reading %zu bytes from VA 0x%lx (PA 0x%lx)\n", bytes_to_read, va + total_read, pa);
                //wuwa_info("  Page start: 0x%lx, Offset: 0x%lx\n", page_start, offset);

                /* Check cache for existing mapping */
                mapped = find_cached_mapping(private_data, page_start);
                if (!mapped) {
                    /* Not cached, create new mapping */
                    mapped = wuwa_ioremap_prot(page_start, PAGE_SIZE, private_data->prot);
                    if (!mapped) {
                        wuwa_err("failed to ioremap physical address 0x%lx\n", page_start);
                        ret = -ENOMEM;
                        goto out;
                    }

                    /* Add to cache */
                    ret = add_cached_mapping(private_data, page_start, mapped);
                    if (ret < 0) {
                        wuwa_err("failed to cache mapping for PA 0x%lx\n", page_start);
                        iounmap(mapped);
                        goto out;
                    }
                }

                /* Copy data to userspace */
                ret = copy_to_user(cmd.dst_va + total_read, mapped + offset, bytes_to_read);
                if (ret != 0) {
                    wuwa_err("copy_to_user failed: %d bytes not copied\n", ret);
                    ret = -EFAULT;
                    goto out;
                }

                total_read += bytes_to_read;
            }

            ret = total_read;

        out:
            return ret;
        }
    case WUWA_BP_IOCTL_WRITE_MEMORY:
        {
            struct bp_write_memory_cmd cmd;
            if (copy_from_user(&cmd, (struct bp_write_memory_cmd __user*)arg, sizeof(cmd))) {
                return -EFAULT;
            }
            if (cmd.size == 0 || cmd.size > 0x10000) {
                return -EINVAL;
            }
            if (!cmd.src_va || !cmd.dst_va) {
                return -EINVAL;
            }

            uintptr_t va, pa;
            uintptr_t offset, page_start;
            void* mapped;
            size_t bytes_to_write, total_written = 0;

            // Validate size: allow writes up to reasonable limit
            if (cmd.size == 0 || cmd.size > (PAGE_SIZE * 16)) {
                wuwa_err("invalid write size: %zu\n", cmd.size);
                return -EINVAL;
            }

            va = cmd.dst_va;

            while (total_written < cmd.size) {
                /* Translate current virtual address to physical */
                ret = translate_process_vaddr(private_data->pid, va + total_written, &pa);
                if (ret < 0) {
                    wuwa_err("failed to translate VA 0x%lx: %d\n", va + total_written, ret);
                    goto out_write;
                }

                /* Calculate page-aligned address and offset */
                offset = pa & ~PAGE_MASK;
                page_start = pa & PAGE_MASK;

                /* Determine how many bytes we can write to this page */
                bytes_to_write = min_t(size_t, cmd.size - total_written, PAGE_SIZE - offset);

                /* Check cache for existing mapping */
                mapped = find_cached_mapping(private_data, page_start);
                if (!mapped) {
                    /* Not cached, create new mapping */
                    mapped = wuwa_ioremap_prot(page_start, PAGE_SIZE, private_data->prot);
                    if (!mapped) {
                        wuwa_err("failed to ioremap physical address 0x%lx\n", page_start);
                        ret = -ENOMEM;
                        goto out_write;
                    }

                    /* Add to cache */
                    ret = add_cached_mapping(private_data, page_start, mapped);
                    if (ret < 0) {
                        wuwa_err("failed to cache mapping for PA 0x%lx\n", page_start);
                        iounmap(mapped);
                        goto out_write;
                    }
                }

                /* Copy data from userspace to target process memory */
                ret = copy_from_user(mapped + offset, (void __user*)(cmd.src_va + total_written), bytes_to_write);
                if (ret != 0) {
                    wuwa_err("copy_from_user failed: %d bytes not copied\n", ret);
                    ret = -EFAULT;
                    goto out_write;
                }

                total_written += bytes_to_write;
            }

            ret = total_written;

        out_write:
            return ret;
        }
    default:
        wuwa_err("unknown ioctl cmd: 0x%x\n", cmd);
        return -ENOTTY;
    }

    return -EINVAL;
}

static int bindproc_mmap(struct file* f, struct vm_area_struct* vma) { return -EINVAL; }

static int bindproc_release(struct inode* inode, struct file* f) {
    struct wuwa_bindproc_private* private_data = f->private_data;
    if (private_data) {
        size_t i;

        mutex_lock(&private_data->lock);

        /* Unmap all cached pages */
        for (i = 0; i < private_data->mapped_pages->size; i++) {
            struct wuwa_mapped_page_info* info = arraylist_get(private_data->mapped_pages, i);
            if (info) {
                if (info->mapped_ptr) {
                    iounmap(info->mapped_ptr);
                }
                kfree(info);
            }
        }

        arraylist_destroy(private_data->mapped_pages);

        mutex_unlock(&private_data->lock);
        mutex_destroy(&private_data->lock);

        kfree(private_data);
        f->private_data = NULL;
    }
    return 0;
}

loff_t bindproc_llseek(struct file* file, loff_t offset, int whence) {
    switch (whence) {
    case SEEK_SET:
        if (offset < 0)
            return -EINVAL;
        file->f_pos = offset;
        break;
    case SEEK_CUR:
        if (file->f_pos + offset < 0)
            return -EINVAL;
        file->f_pos += offset;
        break;
    case SEEK_END:
        return -EINVAL; /* Not supported */
    default:
        return -EINVAL;
    }
    return file->f_pos;
}

static const struct file_operations bindproc_fops = {
    .owner = THIS_MODULE,
    .release = bindproc_release,
    .read = bindproc_read,
    .write = bindproc_write,
    .unlocked_ioctl = bindproc_ioctl,
    .mmap = bindproc_mmap,
    .llseek = bindproc_llseek,
};


int do_bind_proc(struct socket* sock, void __user* arg) {
    struct wuwa_bind_proc_cmd cmd;
    struct wuwa_bindproc_private* private_data = NULL;
    struct file* filp = NULL;
    int fd = -1;
    int ret = 0;

    /* Copy command from userspace */
    if (copy_from_user(&cmd, arg, sizeof(cmd))) {
        return -EFAULT;
    }

    /* Validate PID */
    if (cmd.pid <= 0) {
        wuwa_err("invalid pid: %d\n", cmd.pid);
        return -EINVAL;
    }

    /* Verify target process exists */
    struct task_struct* task = get_target_task(cmd.pid);
    if (!task) {
        wuwa_err("failed to find task for pid: %d\n", cmd.pid);
        return -ESRCH;
    }
    put_task_struct(task);

    /* Allocate private data structure */
    private_data = kmalloc(sizeof(*private_data), GFP_KERNEL);
    if (!private_data) {
        wuwa_err("failed to allocate memory for private_data\n");
        return -ENOMEM;
    }

    private_data->pid = cmd.pid;
    mutex_init(&private_data->lock);
    private_data->prot = __pgprot(PROT_NORMAL); /* Default to normal memory */

    private_data->mapped_pages = arraylist_create(16);
    if (!private_data->mapped_pages) {
        wuwa_err("failed to create mapped_pages arraylist\n");
        ret = -ENOMEM;
        goto err_free_private;
    }

    /* Allocate file descriptor */
    fd = get_unused_fd_flags(O_RDWR | O_CLOEXEC);
    if (fd < 0) {
        wuwa_err("failed to get unused fd: %d\n", fd);
        ret = fd;
        goto err_free_private;
    }

    /* Create anonymous inode file */
    filp = anon_inode_getfile("[wuwa_bindproc]", &bindproc_fops, private_data, O_RDWR | O_CLOEXEC);
    if (IS_ERR(filp)) {
        wuwa_err("failed to create anon inode file: %ld\n", PTR_ERR(filp));
        ret = PTR_ERR(filp);
        goto err_put_fd;
    }

    /* Copy result back to userspace before installing fd */
    cmd.fd = fd;
    if (copy_to_user(arg, &cmd, sizeof(cmd))) {
        wuwa_err("failed to copy cmd back to user\n");
        ret = -EFAULT;
        goto err_fput;
    }

    /* Install fd only after successful copy_to_user */
    fd_install(fd, filp);

    return 0;

err_fput:
    /* File not yet installed, safe to fput (releases private_data via bindproc_release) */
    fput(filp);
    /* Fall through to put_unused_fd */
err_put_fd:
    put_unused_fd(fd);
    return ret;

err_free_private:
    /* Only reached if file creation failed */
    mutex_destroy(&private_data->lock);
    kfree(private_data);
    return ret;
}