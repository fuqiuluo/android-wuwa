#include "wuwa_proc_dmabuf.h"

#include <linux/dma-buf.h>
#include <linux/kernel.h>
#include <linux/mm.h>
#include <linux/module.h>
#include <linux/scatterlist.h>
#include <linux/slab.h>
#include <linux/version.h>

#include "wuwa_common.h"
#include "wuwa_ioctl.h"
#include "wuwa_page_walk.h"
#include "wuwa_utils.h"

struct wuwa_dmabuf_private {
    struct sg_table* sgt;
};

/**
 * wuwa_dmabuf_map_dma_buf - Map DMA buffer for device access
 * @attachment: DMA buffer attachment
 * @dir: DMA data direction
 *
 * Returns the scatter-gather table stored in the private data.
 * This is a simple implementation that just returns the pre-existing sg_table.
 *
 * Return: Pointer to sg_table
 */
static struct sg_table* wuwa_dmabuf_map_dma_buf(struct dma_buf_attachment* attachment, enum dma_data_direction dir) {
    struct wuwa_dmabuf_private* priv = attachment->dmabuf->priv;
    return priv->sgt;
}

/**
 * wuwa_dmabuf_unmap_dma_buf - Unmap DMA buffer after device access
 * @attachment: DMA buffer attachment
 * @sgt: Scatter-gather table
 * @dir: DMA data direction
 *
 * No-op implementation as we don't need to do any cleanup on unmap.
 */
static void wuwa_dmabuf_unmap_dma_buf(struct dma_buf_attachment* attachment, struct sg_table* sgt,
                                      enum dma_data_direction dir) {}

/**
 * wuwa_dmabuf_release - Release DMA buffer resources
 * @dmabuf: DMA buffer to release
 *
 * Frees all resources associated with the DMA buffer:
 * - Decrements page reference counts
 * - Frees scatter-gather table
 * - Frees private data structure
 */
static void wuwa_dmabuf_release(struct dma_buf* dmabuf) {
    struct wuwa_dmabuf_private* priv = dmabuf->priv;
    if (!priv) {
        return;
    }

    wuwa_info("releasing dmabuf private data\n");
    if (priv->sgt) {
        struct scatterlist* sg;
        int i;

        for_each_sg(priv->sgt->sgl, sg, priv->sgt->nents, i) {
            struct page* page = sg_page(sg);
            if (page) {
                put_page(page);
            }
        }

        sg_free_table(priv->sgt);
        kfree(priv->sgt);
    }

    kfree(priv);
}

/**
 * wuwa_dmabuf_begin_cpu_access - Begin CPU access to DMA buffer
 * @dmabuf: DMA buffer
 * @dir: DMA data direction
 *
 * Called before CPU accesses the buffer. Currently a no-op.
 *
 * Return: 0 on success
 */
static int wuwa_dmabuf_begin_cpu_access(struct dma_buf* dmabuf, enum dma_data_direction dir) { return 0; }

/**
 * wuwa_dmabuf_end_cpu_access - End CPU access to DMA buffer
 * @dmabuf: DMA buffer
 * @dir: DMA data direction
 *
 * Called after CPU finishes accessing the buffer. Currently a no-op.
 *
 * Return: 0 on success
 */
static int wuwa_dmabuf_end_cpu_access(struct dma_buf* dmabuf, enum dma_data_direction dir) { return 0; }

/**
 * wuwa_dmabuf_mmap - Map DMA buffer into userspace
 * @dmabuf: DMA buffer
 * @vma: Virtual memory area to map into
 *
 * Maps the physical page backing this DMA buffer into userspace.
 * Only supports single-page buffers (enforced by check).
 *
 * The VMA is configured with:
 * - VM_DONTEXPAND: Prevents the VMA from being extended
 * - VM_DONTDUMP: Excludes the VMA from core dumps
 *
 * Note: Cache coherency settings are not modified. If uncached access
 * is needed, uncomment the pgprot_noncached() line, but be aware this
 * may cause cache/memory consistency issues.
 *
 * Return: 0 on success, negative error code on failure
 */
static int wuwa_dmabuf_mmap(struct dma_buf* dmabuf, struct vm_area_struct* vma) {
    struct wuwa_dmabuf_private* priv = dmabuf->priv;
    struct page* page;
    unsigned long pfn;

    // make sure there is only one page
    if (priv->sgt->nents != 1) {
        wuwa_err("invalid number of sg entries: %d\n", priv->sgt->nents);
        return -EINVAL;
    }

    page = sg_page(priv->sgt->sgl);
    if (!page) {
        wuwa_err("failed to get page from sg_table\n");
        return -EINVAL;
    }

    pfn = page_to_pfn(page);
#if (LINUX_VERSION_CODE < KERNEL_VERSION(5, 19, 0))
    vma->vm_flags |= VM_DONTEXPAND | VM_DONTDUMP;
#else
    vm_flags_set(vma, vma->vm_flags | VM_DONTEXPAND | VM_DONTDUMP);
#endif
    // vma->vm_page_prot = pgprot_noncached(vma->vm_page_prot);
    // Turning this on will cause the cache and main memory to be out of sync

    wuwa_debug("remapping PFN %lx to vma start %lx\n", pfn, vma->vm_start);
    return remap_pfn_range(vma, vma->vm_start, pfn, vma->vm_end - vma->vm_start, vma->vm_page_prot);
}

/**
 * DMA buffer operations structure
 *
 * Defines the set of callbacks for DMA buffer operations.
 * These callbacks are invoked by the kernel's dma-buf framework
 * when processes interact with the exported buffer.
 */
static const struct dma_buf_ops wuwa_dmabuf_ops = {
    .map_dma_buf = wuwa_dmabuf_map_dma_buf,
    .unmap_dma_buf = wuwa_dmabuf_unmap_dma_buf,
    .release = wuwa_dmabuf_release,
    .begin_cpu_access = wuwa_dmabuf_begin_cpu_access,
    .end_cpu_access = wuwa_dmabuf_end_cpu_access,
    .mmap = wuwa_dmabuf_mmap,
};

/**
 * do_create_proc_dma_buf - Create a DMA buffer from a process virtual address
 * @sock: Socket for session management
 * @arg: User-space pointer to wuwa_dma_buf_create_cmd
 *
 * Creates a DMA buffer from a process's virtual address. The workflow:
 * 1. Copy command structure from userspace
 * 2. Find the target process and get its mm_struct
 * 3. Translate virtual address to physical page
 * 4. Increment page reference count
 * 5. Create scatter-gather table from the page
 * 6. Allocate and initialize private data structure
 * 7. Export as dma-buf with proper flags
 * 8. Create file descriptor for the dma-buf
 * 9. Return FD to userspace
 *
 * The resulting file descriptor can be shared with other processes or
 * hardware devices for zero-copy memory access.
 *
 * Return: 0 on success, negative error code on failure
 */
int do_create_proc_dma_buf(struct socket* sock, void* arg) {
    struct wuwa_dma_buf_create_cmd cmd;
    struct sg_table* sgt;
    struct wuwa_dmabuf_private* priv;
    DEFINE_DMA_BUF_EXPORT_INFO(exp_info);

    if (copy_from_user(&cmd, arg, sizeof(cmd))) {
        return -EFAULT;
    }

    struct pid* pid_struct = find_get_pid(cmd.pid);
    if (!pid_struct) {
        wuwa_warn("failed to find pid_struct: %d\n", cmd.pid);
        return -ESRCH;
    }

    struct task_struct* task = get_pid_task(pid_struct, PIDTYPE_PID);
    put_pid(pid_struct);
    if (!task) {
        wuwa_warn("failed to get task: %d\n", cmd.pid);
        return -ESRCH;
    }

    struct mm_struct* mm = get_task_mm(task);
    put_task_struct(task);
    if (!mm) {
        wuwa_warn("failed to get mm: %d\n", cmd.pid);
        put_task_struct(task);
        return -ESRCH;
    }

    struct page* page_struct = vaddr_to_page(mm, cmd.va);
    mmput(mm);
    if (!page_struct) {
        return -EFAULT;
    }

    get_page(page_struct);

    sgt = kmalloc(sizeof(*sgt), GFP_KERNEL);
    if (!sgt) {
        return -ENOMEM;
    }

    if (sg_alloc_table_from_pages(sgt, &page_struct, 1, 0, cmd.size, GFP_KERNEL)) {
        kfree(sgt);
        return -ENOMEM;
    }

    priv = kmalloc(sizeof(*priv), GFP_KERNEL);
    if (!priv) {
        sg_free_table(sgt);
        kfree(sgt);
        return -ENOMEM;
    }
    priv->sgt = sgt;

    exp_info.ops = &wuwa_dmabuf_ops;
    exp_info.size = cmd.size;
    exp_info.flags = O_CLOEXEC | O_RDWR;
    exp_info.priv = priv;
    exp_info.owner = THIS_MODULE;

    struct dma_buf* dmabuf = dma_buf_export(&exp_info);
    if (IS_ERR(dmabuf)) {
        sg_free_table(sgt);
        kfree(sgt);
        kfree(priv);
        return PTR_ERR(dmabuf);
    }

    cmd.fd = dma_buf_fd(dmabuf, O_CLOEXEC | O_RDWR);
    if (cmd.fd < 0) {
        dma_buf_put(dmabuf);
        return cmd.fd;
    }

    if (copy_to_user(arg, &cmd, sizeof(cmd))) {
        dma_buf_put(dmabuf);
        return -EFAULT;
    }

    return 0;
}
