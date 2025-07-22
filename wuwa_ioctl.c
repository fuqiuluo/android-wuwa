#include "wuwa_ioctl.h"
#include "wuwa_utils.h"
#include "wuwa_sock.h"
#include "wuwa_page_walk.h"

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/dma-buf.h>
#include <linux/mm.h>
#include <linux/scatterlist.h>
#include <linux/slab.h>
#include <asm/pgtable.h>
#include <asm/pgtable-prot.h>
#include <asm/pgtable-types.h>

#include "wuwa_safe_signal.h"

int do_vaddr_translate(struct socket *sock, void *arg) {
    struct wuwa_addr_translate_cmd cmd;
    if (copy_from_user(&cmd, arg, sizeof(cmd))) {
        return -EFAULT;
    }

    struct pid* pid_struct = find_get_pid(cmd.pid);
    if (!pid_struct) {
        wuwa_warn("failed to find pid_struct: %d\n", cmd.pid);
        return -ESRCH;
    }

    struct task_struct *task = get_pid_task(pid_struct, PIDTYPE_PID);
    put_pid(pid_struct);
    if (!task) {
        wuwa_warn("failed to get task: %d\n", cmd.pid);
        return -ESRCH;
    }

    struct mm_struct *mm = get_task_mm(task);
    put_task_struct(task);
    if (!mm) {
        wuwa_warn("failed to get mm: %d\n", cmd.pid);
        put_task_struct(task);
        return -ESRCH;
    }

    cmd.phy_addr = vaddr_to_phy_addr(mm, cmd.va);
    mmput(mm);

    if (cmd.phy_addr == 0) {
        return -EFAULT;
    }

    if (copy_to_user(arg, &cmd, sizeof(cmd))) {
        return -EFAULT;
    }
    return 0;
}

int do_debug_info(struct socket *sock, void *arg) {
    struct wuwa_debug_info_cmd debug_info_cmd;

    debug_info_cmd.ttbr0_el1 = read_sysreg_s(SYS_TTBR0_EL1);
    debug_info_cmd.task_struct = (u64)current;
    debug_info_cmd.mm_struct = (u64)current->mm;
    debug_info_cmd.pgd_addr = (u64)current->mm->pgd;
    debug_info_cmd.pgd_phys_addr = virt_to_phys(current->mm->pgd);
    debug_info_cmd.mm_asid = ASID(current->mm);
    debug_info_cmd.mm_right = ((uint64_t)(ASID(current->mm)) << 48 | virt_to_phys(current->mm->pgd) | (uint64_t)1) == debug_info_cmd.ttbr0_el1;

    if (copy_to_user(arg, &debug_info_cmd, sizeof(debug_info_cmd))) {
        return -EFAULT;
    }

    return 0;
}

int do_at_s1e0r(struct socket *sock, void *arg) {
    struct wuwa_at_s1e0r_cmd cmd;
    if (copy_from_user(&cmd, arg, sizeof(cmd))) {
        return -EFAULT;
    }

    struct pid* pid_struct = find_get_pid(cmd.pid);
    if (!pid_struct) {
        wuwa_warn("failed to find pid_struct: %d\n", cmd.pid);
        return -ESRCH;
    }

    struct task_struct *task = get_pid_task(pid_struct, PIDTYPE_PID);
    put_pid(pid_struct);
    if (!task) {
        wuwa_warn("failed to get task: %d\n", cmd.pid);
        return -ESRCH;
    }

    struct mm_struct *mm = get_task_mm(task);
    put_task_struct(task);
    if (!mm) {
        wuwa_warn("failed to get mm: %d\n", cmd.pid);
        put_task_struct(task);
        return -ESRCH;
    }

    u64 original_ttbr0 = read_sysreg_s(SYS_TTBR0_EL1);
    u64 new_ttbr0 = (uint64_t)(ASID(mm)) << 48 | virt_to_phys(mm->pgd) | (uint64_t)1;
    dsb(ish);
    asm volatile("msr ttbr0_el1, %0" :: "r" (new_ttbr0));
    dsb(ish);
    isb();

    asm volatile("at s1e0r, %0" :: "r" (cmd.va));
    isb();
    uintptr_t pa = read_sysreg_s(SYS_PAR_EL1);
    cmd.phy_addr = pa;
    mmput(mm);

    dsb(ish);
    asm volatile("msr ttbr0_el1, %0" :: "r" (original_ttbr0));
    dsb(ish);
    isb();

    if (cmd.phy_addr == 0) {
        return -EFAULT;
    }

    if (copy_to_user(arg, &cmd, sizeof(cmd))) {
        return -EFAULT;
    }
    return 0;
}

int do_get_page_info(struct socket *sock, void *arg) {
    struct wuwa_page_info_cmd cmd;
    if (copy_from_user(&cmd, arg, sizeof(cmd))) {
        return -EFAULT;
    }

    struct pid* pid_struct = find_get_pid(cmd.pid);
    if (!pid_struct) {
        wuwa_warn("failed to find pid_struct: %d\n", cmd.pid);
        return -ESRCH;
    }

    struct task_struct *task = get_pid_task(pid_struct, PIDTYPE_PID);
    put_pid(pid_struct);
    if (!task) {
        wuwa_warn("failed to get task: %d\n", cmd.pid);
        return -ESRCH;
    }

    struct mm_struct *mm = get_task_mm(task);
    put_task_struct(task);
    if (!mm) {
        wuwa_warn("failed to get mm: %d\n", cmd.pid);
        put_task_struct(task);
        return -ESRCH;
    }

    struct page* page_struct = vaddr_to_page(mm, cmd.va);
    if (!page_struct) {
        wuwa_warn("failed to get page for va: %lx\n", cmd.va);
        mmput(mm);
        return -EFAULT;
    }

    phys_addr_t phy_addr = page_to_phys(page_struct);
    cmd.page.phy_addr = phy_addr;
    cmd.page.flags = page_struct->flags;
    cmd.page._mapcount = page_struct->_mapcount;
    cmd.page._refcount = page_struct->_refcount;

    if (copy_to_user(arg, &cmd, sizeof(cmd))) {
        return -EFAULT;
    }

    return 0;
}

static struct sg_table *wuwa_dmabuf_map_dma_buf(struct dma_buf_attachment *attachment, enum dma_data_direction dir) {
    struct wuwa_dmabuf_private *priv = attachment->dmabuf->priv;
    return priv->sgt;
}

static void wuwa_dmabuf_unmap_dma_buf(struct dma_buf_attachment *attachment, struct sg_table *sgt, enum dma_data_direction dir) {
}

static void wuwa_dmabuf_release(struct dma_buf *dmabuf) {
    struct wuwa_dmabuf_private *priv = dmabuf->priv;
    if (!priv) {
        return;
    }

    wuwa_info("releasing dmabuf private data\n");
    if (priv->sgt) {
        struct scatterlist *sg;
        int i;

        for_each_sg(priv->sgt->sgl, sg, priv->sgt->nents, i) {
            struct page *page = sg_page(sg);
            if (page) {
                put_page(page);
            }
        }

        sg_free_table(priv->sgt);
        kfree(priv->sgt);
    }

    kfree(priv);
}

static int wuwa_dmabuf_begin_cpu_access(struct dma_buf *dmabuf, enum dma_data_direction dir) {
    return 0;
}

static int wuwa_dmabuf_end_cpu_access(struct dma_buf *dmabuf, enum dma_data_direction dir) {
    return 0;
}

static int wuwa_dmabuf_mmap(struct dma_buf *dmabuf, struct vm_area_struct *vma) {
    struct wuwa_dmabuf_private *priv = dmabuf->priv;
    struct page *page;
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
    vm_flags_set(vma, vma->vm_flags | VM_DONTEXPAND | VM_DONTDUMP);
    // vma->vm_page_prot = pgprot_noncached(vma->vm_page_prot);
    // Turning this on will cause the cache and main memory to be out of sync

    wuwa_debug("remapping PFN %lx to vma start %lx\n", pfn, vma->vm_start);
    return remap_pfn_range(vma, vma->vm_start, pfn, vma->vm_end - vma->vm_start, vma->vm_page_prot);
}

static const struct dma_buf_ops wuwa_dmabuf_ops = {
    .map_dma_buf        = wuwa_dmabuf_map_dma_buf,
    .unmap_dma_buf      = wuwa_dmabuf_unmap_dma_buf,
    .release            = wuwa_dmabuf_release,
    .begin_cpu_access   = wuwa_dmabuf_begin_cpu_access,
    .end_cpu_access     = wuwa_dmabuf_end_cpu_access,
    .mmap               = wuwa_dmabuf_mmap,
};

int do_create_dma_buf(struct socket *sock, void *arg) {
    struct wuwa_dma_buf_create_cmd cmd;
    struct sg_table *sgt;
    struct wuwa_dmabuf_private *priv;
    DEFINE_DMA_BUF_EXPORT_INFO(exp_info);

    if (copy_from_user(&cmd, arg, sizeof(cmd))) {
        return -EFAULT;
    }

    struct pid* pid_struct = find_get_pid(cmd.pid);
    if (!pid_struct) {
        wuwa_warn("failed to find pid_struct: %d\n", cmd.pid);
        return -ESRCH;
    }

    struct task_struct *task = get_pid_task(pid_struct, PIDTYPE_PID);
    put_pid(pid_struct);
    if (!task) {
        wuwa_warn("failed to get task: %d\n", cmd.pid);
        return -ESRCH;
    }

    struct mm_struct *mm = get_task_mm(task);
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

    struct dma_buf *dmabuf = dma_buf_export(&exp_info);
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

int do_pte_mapping(struct socket *sock, void *arg) {
    struct wuwa_sock* wuwa_sock = (struct wuwa_sock *)sock->sk;
    struct wuwa_pte_mapping_cmd cmd;
    if (copy_from_user(&cmd, arg, sizeof(cmd))) {
        return -EFAULT;
    }

    if (cmd.start_addr < 0 || cmd.start_addr >= TASK_SIZE_64) {
        wuwa_warn("invalid start address: 0x%lx\n", cmd.start_addr);
        return -EINVAL;
    }

    if (cmd.num_pages <= 0 || cmd.num_pages > (TASK_SIZE_64 - cmd.start_addr) / PAGE_SIZE) {
        wuwa_warn("invalid number of pages: %zu\n", cmd.num_pages);
        return -EINVAL;
    }

    pgd_t *pgd;
    p4d_t *p4d;
    pud_t *pud;
    pmd_t *pmd;
    pte_t *pte;
    struct page* page = NULL;
    int ret = 0;

    struct pid* pid_struct = find_get_pid(cmd.pid);
    if (!pid_struct) {
        wuwa_warn("failed to find pid_struct: %d\n", cmd.pid);
        return -ESRCH;
    }

    struct task_struct *task = get_pid_task(pid_struct, PIDTYPE_PID);
    put_pid(pid_struct);
    if (!task) {
        wuwa_warn("failed to get task: %d\n", cmd.pid);
        return -ESRCH;
    }

    struct mm_struct *mm = get_task_mm(task);
    put_task_struct(task);
    if (!mm) {
        wuwa_warn("failed to get mm: %d\n", cmd.pid);
        return -ESRCH;
    }

    static int (*my__pmd_alloc)(struct mm_struct *mm, pud_t *pud, unsigned long address) = NULL;
    my__pmd_alloc = (int (*)(struct mm_struct *, pud_t *, unsigned long))kallsyms_lookup_name("__pmd_alloc");
    static int (*my__pte_alloc)(struct mm_struct *mm, pmd_t *pmd) = NULL;
    my__pte_alloc = (int (*)(struct mm_struct *, pmd_t *))kallsyms_lookup_name("__pte_alloc");

    if (my__pmd_alloc == NULL || my__pte_alloc == NULL) {
        wuwa_err("failed to find __pmd_alloc or __pte_alloc symbols\n");
        ret = -ENOENT;
        goto out_mm;
    }

#define my_pte_alloc(mm, pmd) (unlikely(pmd_none(*(pmd))) && my__pte_alloc(mm, pmd))
#define my_pte_alloc_map(mm, pmd, address) (my_pte_alloc(mm, pmd) ? NULL : pte_offset_map(pmd, address))

    page = alloc_pages(GFP_USER | __GFP_ZERO, get_order(cmd.num_pages * PAGE_SIZE));
    if (!page) {
        wuwa_err("failed to allocate pages\n");
        ret = -ENOMEM;
        goto out_mm;
    }

    pgd = pgd_offset(mm, cmd.start_addr);
    if (pgd_none(*pgd) || pgd_bad(*pgd)) {
        wuwa_err("invalid pgd\n");
        ret = -EINVAL;
        goto out_page;
    }

    p4d = p4d_alloc(mm, pgd, cmd.start_addr);
    if (!p4d) {
        wuwa_err("failed to allocate p4d\n");
        ret = -ENOMEM;
        goto out_page;
    }

    pud = pud_alloc(mm, p4d, cmd.start_addr);
    if (!pud) {
        wuwa_err("failed to allocate pud\n");
        ret = -ENOMEM;
        goto out_page;
    }

    if (unlikely(pud_none(*pud))) {
        if (my__pmd_alloc(mm, pud, cmd.start_addr)) {
            wuwa_err("failed to allocate pmd\n");
            ret = -ENOMEM;
            goto out_page;
        }
    }
    pmd = pmd_offset(pud, cmd.start_addr);
    if (!pmd) {
        wuwa_err("failed to get pmd\n");
        ret = -ENOMEM;
        goto out_page;
    }

    pte = my_pte_alloc_map(mm, pmd, cmd.start_addr);
    if (!pte) {
        wuwa_err("failed to allocate or map pte\n");
        ret = -ENOMEM;
        goto out_page;
    }

    if (!pte_none(*pte)) {
        wuwa_warn("pte already in use at address 0x%lx\n", cmd.start_addr);
        pte_unmap(pte);
        ret = -EEXIST;
        goto out_page;
    }

    pte_t new_pte = mk_pte(page, PAGE_SHARED_EXEC);
    new_pte = pte_mkwrite(new_pte);
    new_pte = pte_mkdirty(new_pte);
    new_pte = pte_mkyoung(new_pte);

    set_pte(pte, new_pte);

    pte_unmap(pte);

    flush_tlb_all();

    mmput(mm);

    if (cmd.hide) {
        wuwa_add_unsafe_region(wuwa_sock->session, task->cred->uid.val, cmd.start_addr, cmd.num_pages);
    }

    wuwa_info("successfully mapped page at address 0x%lx for pid %d\n", cmd.start_addr, cmd.pid);
    return 0;

out_page:
    if (page) {
        __free_pages(page, get_order(cmd.num_pages * PAGE_SIZE));
    }
out_mm:
    mmput(mm);
    return ret;
}

int do_page_table_walk(struct socket *sock, void *arg) {
    struct wuwa_page_table_walk_cmd cmd;
    if (copy_from_user(&cmd, arg, sizeof(cmd))) {
        return -EFAULT;
    }

    struct pid* pid_struct = find_get_pid(cmd.pid);
    if (!pid_struct) {
        wuwa_warn("failed to find pid_struct: %d\n", cmd.pid);
        return -ESRCH;
    }

    struct task_struct *task = get_pid_task(pid_struct, PIDTYPE_PID);
    put_pid(pid_struct);
    if (!task) {
        wuwa_warn("failed to get task: %d\n", cmd.pid);
        return -ESRCH;
    }

    struct mm_struct *mm = get_task_mm(task);
    put_task_struct(task);
    if (!mm) {
        wuwa_warn("failed to get mm: %d\n", cmd.pid);
        put_task_struct(task);
        return -ESRCH;
    }

    traverse_page_tables(mm);

    mmput(mm);

    return 0;
}

