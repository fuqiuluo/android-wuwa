#include "wuwa_utils.h"

#include <linux/hugetlb.h>
#include <linux/interrupt.h>
#include <linux/mm.h>
#include <linux/pgtable.h>
#include <linux/printk.h>
#include <linux/proc_fs.h>
#include <linux/vmalloc.h>

#include "hijack_arm64.h"

#ifdef CONFIG_CFI_CLANG
#define NO_CFI __nocfi
#else
#define NO_CFI
#endif

static int wuwa_flip_open(const char* filename, int flags, umode_t mode, struct file** f) {
#if (LINUX_VERSION_CODE < KERNEL_VERSION(5, 10, 0))
    *f = filp_open(filename, flags, mode);
    return *f == NULL ? -2 : 0;
#else
    static struct file* (*reserve_flip_open)(const char* filename, int flags, umode_t mode) = NULL;

    if (reserve_flip_open == NULL) {
        reserve_flip_open =
            (struct file * (*)(const char* filename, int flags, umode_t mode)) kallsyms_lookup_name_ex("filp_open");
        if (reserve_flip_open == NULL) {
            return -1;
        }
    }

    *f = reserve_flip_open(filename, flags, mode);
    return *f == NULL ? -2 : 0;
#endif
}

static int wuwa_flip_close(struct file** f, fl_owner_t id) {
#if (LINUX_VERSION_CODE < KERNEL_VERSION(5, 10, 0))
    filp_close(*f, id);
    return 0;
#else
    static struct file* (*reserve_flip_close)(struct file** f, fl_owner_t id) = NULL;

    if (reserve_flip_close == NULL) {
        reserve_flip_close = (struct file * (*)(struct file * *f, fl_owner_t id)) kallsyms_lookup_name_ex("filp_close");
        if (reserve_flip_close == NULL) {
            return -1;
        }
    }

    reserve_flip_close(f, id);
    return 0;
#endif
}

bool is_file_exist(const char* filename) {
    struct file* fp;

    if (wuwa_flip_open(filename, O_RDONLY, 0, &fp) == 0) {
        if (!IS_ERR(fp)) {
            wuwa_flip_close(&fp, NULL);
            return true;
        }
        return false;
    }

    //    // int kern_path(const char *name, unsigned int flags, struct path *path)
    //    struct path path;
    //    if (kern_path(filename, LOOKUP_FOLLOW, &path) == 0) {
    //        return true;
    //    }

    return false;
}


pte_t* page_from_virt_user(struct mm_struct* mm, uintptr_t va) {
    pgd_t* pgd;
    p4d_t* p4d;
    pud_t* pud;
    pmd_t* pmd;
    pte_t* ptep = NULL;

    MM_READ_LOCK(mm);

    pgd = pgd_offset(mm, va);
    if (pgd_none(*pgd) || pgd_bad(*pgd)) {
        wuwa_warn("PGD entry for address 0x%lx not found or bad\n", va);
        goto out;
    }

    p4d = p4d_offset(pgd, va);
    if (p4d_none(*p4d) || p4d_bad(*p4d)) {
        wuwa_warn("P4D entry for address 0x%lx not found or bad\n", va);
        goto out;
    }

    pud = pud_offset(p4d, va);
    if (pud_none(*pud) || pud_bad(*pud)) {
        wuwa_warn("PUD entry for address 0x%lx not found or bad\n", va);
        goto out;
    }

    if (pud_leaf(*pud)) {
        wuwa_debug("Address 0x%lx maps to a PUD-level huge page (leaf), no PTE exists\n", va);
        goto out;
    }

    pmd = pmd_offset(pud, va);
    if (pmd_none(*pmd) || pmd_bad(*pmd)) {
        wuwa_warn("PMD entry for address 0x%lx not found or bad\n", va);
        goto out;
    }

    if (pmd_leaf(*pmd)) {
        wuwa_debug("Address 0x%lx maps to a PMD-level huge page (leaf), no PTE exists\n", va);
        goto out;
    }

    ptep = pte_offset_kernel(pmd, va);
    if (!ptep) {
        wuwa_warn("Failed to map PTE for address 0x%lx\n", va);
        goto out;
    }
out:
    MM_READ_UNLOCK(mm);

    return ptep;
}

uintptr_t vaddr_to_phy_addr(struct mm_struct* mm, uintptr_t va) {
    if (!mm) {
        wuwa_warn("mm_struct is NULL, cannot perform translation\n");
        return 0;
    }

    pte_t* ptep = page_from_virt_user(mm, va);
    if (!ptep) {
        wuwa_err("failed to get PTE for virtual address 0x%lx\n", va);
        return 0;
    }

    if (!pte_present(*ptep)) {
        wuwa_err("PTE not present for virtual address 0x%lx\n", va);
        return 0;
    }

    uintptr_t page_addr = pte_pfn(*ptep) << PAGE_SHIFT;

    return page_addr + (va & (PAGE_SIZE - 1));
}

typedef unsigned long (*kallsyms_lookup_name_t)(const char *name);

static unsigned long NO_CFI call_kln(kallsyms_lookup_name_t f, const char *n) {
    return f(n);
}

unsigned long kallsyms_lookup_name_ex(const char* name) {
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 7, 0)
    static kallsyms_lookup_name_t lookup_name = NULL;
    if (lookup_name == NULL) {
        struct kprobe kp = {.symbol_name = "kallsyms_lookup_name"};

        if (register_kprobe(&kp) < 0) {
            return 0;
        }

        lookup_name = (kallsyms_lookup_name_t)kp.addr;
        unregister_kprobe(&kp);

        if (lookup_name == NULL) {
            wuwa_err("kallsyms_lookup_name not found\n");
            return 0;
        }
        wuwa_info("kallsyms_lookup_name_ex found at %p\n", lookup_name);
    }

    return call_kln(lookup_name, name);
#else
    return kallsyms_lookup_name(name);
#endif
}

struct task_struct* get_target_task(pid_t pid) {
    struct pid* pid_struct = find_get_pid(pid);
    if (!pid_struct) {
        return NULL;
    }

    struct task_struct* task = get_pid_task(pid_struct, PIDTYPE_PID);
    put_pid(pid_struct);
    if (!task) {
        return NULL;
    }

    return task;
}

int disable_kprobe_blacklist(void) {
    struct kprobe_blacklist_entry* ent;
    struct list_head* kprobe_blacklist = (struct list_head*)kallsyms_lookup_name_ex("kprobe_blacklist");
    if (!kprobe_blacklist) {
        wuwa_err("kprobe_blacklist not found\n");
        return -ENOENT;
    }

    int count = 0;
    list_for_each_entry(ent, kprobe_blacklist, list) {
        if (!ent || ent->start_addr == 0 || ent->end_addr == 0) {
            continue;
        }
        count++;
        ent->start_addr = 0;
        ent->end_addr = 0;
    }

    wuwa_info("Disabled %d kprobe blacklist entries\n", count);

    return 0;
}

void compare_pt_regs(struct pt_regs* regs1, struct pt_regs* regs2) {
#if CONFIG_COMPARE_PT_REGS == 1
    wuwa_info("==> Comparing pt_regs:\n");

    for (int i = 0; i < 31; ++i) {
        if (regs1->regs[i] != regs2->regs[i]) {
            wuwa_info("reg[%d] changed from %llx to %llx\n", i, regs1->regs[i], regs2->regs[i]);
        }
    }

    if (regs1->sp != regs2->sp) {
        wuwa_info("sp changed from %llx to %llx\n", regs1->sp, regs2->sp);
    }

    if (regs1->pc != regs2->pc) {
        wuwa_info("pc changed from %llx to %llx\n", regs1->pc, regs2->pc);
    }

    if (regs1->pstate != regs2->pstate) {
        wuwa_info("pstate changed from %llx to %llx\n", regs1->pstate, regs2->pstate);
    }

    if (regs1->sdei_ttbr1 != regs2->sdei_ttbr1) {
        wuwa_info("sdei_ttbr1 changed from %llx to %llx\n", regs1->sdei_ttbr1, regs2->sdei_ttbr1);
    }

    if (regs1->pmr_save != regs2->pmr_save) {
        wuwa_info("pmr_save changed from %llx to %llx\n", regs1->pmr_save, regs2->pmr_save);
    }

    if (regs1->stackframe[0] != regs2->stackframe[0] || regs1->stackframe[1] != regs2->stackframe[1]) {
        wuwa_info("stackframe changed from [%llx, %llx] to [%llx, %llx]\n", regs1->stackframe[0], regs1->stackframe[1],
                 regs2->stackframe[0], regs2->stackframe[1]);
    }
#endif
}

void compare_task_struct(struct task_struct* task1, struct task_struct* task2) {
#if CONFIG_COMPARE_TASK == 1
    wuwa_info("==> Comparing task_struct:\n");
#ifdef CONFIG_THREAD_INFO_IN_TASK
    if (task1->thread_info.flags != task2->thread_info.flags) {
        wuwa_info("thread_info.flags changed from %lx to %lx\n", task1->thread_info.flags, task2->thread_info.flags);
    }

    if (task1->thread_info.cpu != task2->thread_info.cpu) {
        wuwa_info("thread_info.cpu changed from %d to %d\n", task1->thread_info.cpu, task2->thread_info.cpu);
    }
#endif

    if (task1->__state != task2->__state) {
        wuwa_info("__state changed from %u to %u\n", task1->__state, task2->__state);
    }

    if (task1->stack != task2->stack) {
        wuwa_info("stack pointer changed from %p to %p\n", task1->stack, task2->stack);
    }

    if (task1->flags != task2->flags) {
        wuwa_info("flags changed from %u to %u\n", task1->flags, task2->flags);
    }

    if (task1->ptrace != task2->ptrace) {
        wuwa_info("ptrace changed from %u to %u\n", task1->ptrace, task2->ptrace);
    }

    if (task1->pid != task2->pid) {
        wuwa_info("pid changed from %d to %d\n", task1->pid, task2->pid);
    }

    if (task1->tgid != task2->tgid) {
        wuwa_info("tgid changed from %d to %d\n", task1->tgid, task2->tgid);
    }
#endif
}

#define W_PHYS_PFN(x) ((unsigned long)((x) >> PAGE_SHIFT))
#define wuwa_phys_to_pfn(paddr) W_PHYS_PFN(paddr)

struct page* vaddr_to_page(struct mm_struct* mm, uintptr_t va) {
#if !defined(pfn_to_page)
#error "vaddr_to_page failed: pfn_to_page not found"
#endif
    return pfn_to_page(wuwa_phys_to_pfn(vaddr_to_phy_addr(mm, va)));
}

int translate_process_vaddr(pid_t pid, uintptr_t vaddr, uintptr_t* paddr_out) {
    struct pid* pid_struct;
    struct task_struct* task;
    struct mm_struct* mm;
    uintptr_t paddr;

    pid_struct = find_get_pid(pid);
    if (!pid_struct) {
        wuwa_warn("failed to find pid_struct: %d\n", pid);
        return -ESRCH;
    }

    task = get_pid_task(pid_struct, PIDTYPE_PID);
    put_pid(pid_struct);
    if (!task) {
        wuwa_warn("failed to get task: %d\n", pid);
        return -ESRCH;
    }

    mm = get_task_mm(task);
    put_task_struct(task);
    if (!mm) {
        wuwa_warn("failed to get mm: %d\n", pid);
        return -ESRCH;
    }

    paddr = vaddr_to_phy_addr(mm, vaddr);
    mmput(mm);

    if (paddr == 0) {
        return -EFAULT;
    }

    *paddr_out = paddr;
    return 0;
}

uintptr_t get_module_base(pid_t pid, char* name, int vm_flag) {
    struct pid* pid_struct;
    struct task_struct* task;
    struct mm_struct* mm;
    struct vm_area_struct* vma;
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(6, 1, 0))
    struct vma_iterator vmi;
#endif
    uintptr_t result;
    struct dentry* dentry;
    size_t name_len, dname_len;

    result = 0;

    name_len = strlen(name);
    if (name_len == 0) {
        wuwa_err("module name is empty\n");
        return 0;
    }

    pid_struct = find_get_pid(pid);
    if (!pid_struct) {
        wuwa_err("failed to find pid_struct\n");
        return 0;
    }

    task = get_pid_task(pid_struct, PIDTYPE_PID);
    put_pid(pid_struct);
    if (!task) {
        wuwa_err("failed to get task from pid_struct\n");
        return 0;
    }

    mm = get_task_mm(task);
    put_task_struct(task);
    if (!mm) {
        wuwa_err("failed to get mm from task\n");
        return 0;
    }

    MM_READ_LOCK(mm)

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(6, 1, 0))
    vma_iter_init(&vmi, mm, 0);
    for_each_vma(vmi, vma)
#else
    for (vma = mm->mmap; vma; vma = vma->vm_next)
#endif
    {
        if (vma->vm_file) {
            if (vm_flag && !(vma->vm_flags & vm_flag)) {
                continue;
            }
            dentry = vma->vm_file->f_path.dentry;
            dname_len = dentry->d_name.len;
            if (!memcmp(dentry->d_name.name, name, min(name_len, dname_len))) {
                result = vma->vm_start;
                goto ret;
            }
        }
    }

ret:
    MM_READ_UNLOCK(mm)

    mmput(mm);
    return result;
}

int is_pid_alive(pid_t pid) {
    struct pid* pid_struct;
    struct task_struct* task;

    pid_struct = find_get_pid(pid);
    if (!pid_struct)
        return false;

    task = pid_task(pid_struct, PIDTYPE_PID);
    if (!task)
        return false;

    return pid_alive(task);
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 1, 0)
// 低版本内核不存在get_cmdline, 离人说的！
pid_t find_process_by_name(const char* name) {
    struct task_struct* task;
    char cmdline[256];
    char* prog_name;
    size_t name_len;
    int ret;

    name_len = strlen(name);
    if (name_len == 0) {
        pr_err("process name is empty\n");
        return -2;
    }

    static int (*my_get_cmdline)(struct task_struct* task, char* buffer, int buflen) = NULL;
    if (my_get_cmdline == NULL) {
        my_get_cmdline = (void*)kallsyms_lookup_name_ex("get_cmdline");
    }

    rcu_read_lock();
    for_each_process(task) {
        if (task->mm == NULL) {
            continue;
        }

        cmdline[0] = '\0';
        if (my_get_cmdline != NULL) {
            ret = my_get_cmdline(task, cmdline, sizeof(cmdline));
        } else {
            ret = -1;
        }

        if (ret < 0) {
            // 回退到task->comm，确保完全匹配
            if (strlen(task->comm) == name_len && strncmp(task->comm, name, name_len) == 0) {
                rcu_read_unlock();
                return task->pid;
            }
        } else {
            // 提取程序名（第一个空格之前的部分）
            prog_name = cmdline;
            char* space = strchr(cmdline, ' ');
            if (space) {
                *space = '\0';
            }

            // 提取路径中的文件名部分
            char* slash = strrchr(prog_name, '/');
            if (slash) {
                prog_name = slash + 1;
            }

            if (strlen(prog_name) == name_len && strncmp(prog_name, name, name_len) == 0) {
                rcu_read_unlock();
                return task->pid;
            }
        }
    }
    rcu_read_unlock();
    return 0;
}

#else
int get_cmdline_ex(struct task_struct* task, char* buffer, int buflen) {
    int res = 0;
    unsigned int len;
    struct mm_struct* mm = get_task_mm(task);
    unsigned long arg_start, arg_end, env_start, env_end;
    if (!mm)
        goto out;
    if (!mm->arg_end)
        goto out_mm; /* Shh! No looking before we're done */

    spin_lock(&mm->arg_lock);
    arg_start = mm->arg_start;
    arg_end = mm->arg_end;
    env_start = mm->env_start;
    env_end = mm->env_end;
    spin_unlock(&mm->arg_lock);

    len = arg_end - arg_start;

    if (len > buflen)
        len = buflen;

    res = access_process_vm(task, arg_start, buffer, len, FOLL_FORCE);

    /*
     * If the nul at the end of args has been overwritten, then
     * assume application is using setproctitle(3).
     */
    if (res > 0 && buffer[res - 1] != '\0' && len < buflen) {
        len = strnlen(buffer, res);
        if (len < res) {
            res = len;
        } else {
            len = env_end - env_start;
            if (len > buflen - res)
                len = buflen - res;
            res += access_process_vm(task, env_start, buffer + res, len, FOLL_FORCE);
            res = strnlen(buffer, res);
        }
    }
out_mm:
    mmput(mm);
out:
    return res;
}

pid_t find_process_by_name(const char* name) {
    struct task_struct* task;
    char cmdline[256];
    char* prog_name;
    size_t name_len;
    int ret;

    name_len = strlen(name);
    if (name_len == 0) {
        pr_err("process name is empty\n");
        return -2;
    }

    rcu_read_lock();
    for_each_process(task) {
        if (task->mm == NULL) {
            continue;
        }

        cmdline[0] = '\0';
        ret = get_cmdline_ex(task, cmdline, sizeof(cmdline));

        if (ret < 0) {
            // 回退到task->comm，确保完全匹配
            if (strlen(task->comm) == name_len && strncmp(task->comm, name, name_len) == 0) {
                rcu_read_unlock();
                return task->pid;
            }
        } else {
            // 提取程序名（第一个空格之前的部分）
            prog_name = cmdline;
            char* space = strchr(cmdline, ' ');
            if (space) {
                *space = '\0';
            }

            // 提取路径中的文件名部分
            char* slash = strrchr(prog_name, '/');
            if (slash) {
                prog_name = slash + 1;
            }

            if (strlen(prog_name) == name_len && strncmp(prog_name, name, name_len) == 0) {
                rcu_read_unlock();
                return task->pid;
            }
        }
    }
    rcu_read_unlock();
    return 0;
}
#endif

static struct list_head* module_previous;
static struct list_head* module_kobj_previous;
static short module_hidden = 0;

void show_module(void) {
    // list_add(&THIS_MODULE->list, module_previous);
    // kobject_add(&THIS_MODULE->mkobj.kobj, THIS_MODULE->mkobj.kobj.parent, "%s", THIS_MODULE->name);
    // list_add(&THIS_MODULE->mkobj.kobj.entry, module_kobj_previous);
    module_hidden = 0;
}

void hide_module(void) {
#if defined(HIDE_SELF_MODULE)
    if (is_file_exist("/proc/sched_debug")) {
        remove_proc_entry("sched_debug", NULL);
    }

    if (is_file_exist("/proc/uevents_records")) {
        remove_proc_entry("uevents_records", NULL);
    }

#ifdef MODULE
    // module_previous = THIS_MODULE->list.prev;
    // module_kobj_previous = THIS_MODULE->mkobj.kobj.entry.prev;
    //
    list_del(&THIS_MODULE->list); // lsmod,/proc/modules
    kobject_del(&THIS_MODULE->mkobj.kobj); // /sys/modules
    list_del(&THIS_MODULE->mkobj.kobj.entry); // kobj struct list_head entry
    module_hidden = 1;
#endif

    // protocol disguise! A lie
    memcpy(THIS_MODULE->name, "nfc\0", 4);
    // remove_proc_entry("protocols", net->proc_net);
#endif
}

int give_root(void) {
#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 29)
    current->uid = current->gid = 0;
    current->euid = current->egid = 0;
    current->suid = current->sgid = 0;
    current->fsuid = current->fsgid = 0;
#else
    struct cred* newcreds;
    static struct cred* (*my_prepare_creds)(void) = NULL;
    static int (*my_commit_creds)(struct cred*) = NULL;
    if (my_prepare_creds == NULL) {
        my_prepare_creds = (void*)kallsyms_lookup_name_ex("prepare_creds");
        my_commit_creds = (void*)kallsyms_lookup_name_ex("commit_creds");
        if (my_prepare_creds == NULL || my_commit_creds == NULL) {
            return -1;
        }
    }
    newcreds = my_prepare_creds();
    if (newcreds == NULL)
        return -2;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 5, 0) && defined(CONFIG_UIDGID_STRICT_TYPE_CHECKS) ||                      \
    LINUX_VERSION_CODE >= KERNEL_VERSION(3, 14, 0)
    newcreds->uid.val = newcreds->gid.val = 0;
    newcreds->euid.val = newcreds->egid.val = 0;
    newcreds->suid.val = newcreds->sgid.val = 0;
    newcreds->fsuid.val = newcreds->fsgid.val = 0;
#else
    newcreds->uid = newcreds->gid = 0;
    newcreds->euid = newcreds->egid = 0;
    newcreds->suid = newcreds->sgid = 0;
    newcreds->fsuid = newcreds->fsgid = 0;
#endif
    my_commit_creds(newcreds);
#endif
    return 0;
}

void __iomem* wuwa_ioremap_prot(uintptr_t phys_addr, size_t size, pgprot_t prot) {
    unsigned long offset, vaddr;
    uintptr_t last_addr;
    struct vm_struct* area;
    int err;

    offset = phys_addr & ~PAGE_MASK;
    /*
     * Page align the mapping address and size, taking account of any
     * offset.
     */
    phys_addr &= PAGE_MASK;
    size = PAGE_ALIGN(size + offset);

    /*
     * Don't allow wraparound, zero size or outside PHYS_MASK.
     */
    last_addr = phys_addr + size - 1;
    if (!size || last_addr < phys_addr || last_addr & ~PHYS_MASK)
        return NULL;

    static int (*my_ioremap_page_range)(unsigned long addr, unsigned long end,
               uintptr_t phys_addr, pgprot_t prot) = NULL;
    static void (*my_free_vm_area)(struct vm_struct *area) = NULL;
    if (my_ioremap_page_range == NULL || my_free_vm_area == NULL) {
        my_ioremap_page_range = (int (*)(unsigned long addr, unsigned long end,
                   uintptr_t phys_addr, pgprot_t prot))kallsyms_lookup_name_ex("ioremap_page_range");
        my_free_vm_area = (void (*)(struct vm_struct *area))kallsyms_lookup_name_ex("free_vm_area");
        if (my_ioremap_page_range == NULL || my_free_vm_area == NULL) {
            wuwa_err("cannot find ioremap_page_range or free_vm_area\n");
            return NULL;
        }
    }

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 6, 0)
    static struct vm_struct *(*my__get_vm_area_caller)(unsigned long size,
                    unsigned long flags,
                    unsigned long start, unsigned long end,
                    const void *caller) = NULL;
    if (my__get_vm_area_caller == NULL) {
        my__get_vm_area_caller = (struct vm_struct * (*)(unsigned long, unsigned long, unsigned long, unsigned long, const void *))kallsyms_lookup_name_ex("__get_vm_area_caller");
        if (my__get_vm_area_caller == NULL) {
            wuwa_err("cannot find __get_vm_area_caller\n");
            return NULL;
        }
    }
    area = my__get_vm_area_caller(size, VM_IOREMAP, VMALLOC_START, VMALLOC_END, __builtin_return_address(0));
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(5, 10, 0)
    static struct vm_struct* (*my_get_vm_area_caller)(unsigned long, unsigned long, const void*) = NULL;
    if (my_get_vm_area_caller == NULL) {
        my_get_vm_area_caller =
            (struct vm_struct * (*)(unsigned long, unsigned long, const void*))kallsyms_lookup_name_ex("get_vm_area_caller");
        if (my_get_vm_area_caller == NULL) {
            wuwa_err("cannot find get_vm_area_caller\n");
            return NULL;
        }
    }
    area = my_get_vm_area_caller(size, VM_IOREMAP, __builtin_return_address(0));
#endif

    if (!area)
        return NULL;
    vaddr = (unsigned long)area->addr;
    area->phys_addr = phys_addr;

    err = my_ioremap_page_range(vaddr, vaddr + size, phys_addr, prot);
    if (err) {
        my_free_vm_area(area);
        return NULL;
    }

    return (void __iomem*)(vaddr + offset);
}

int cfi_bypass(void) {
    int ret = 0;
    unsigned int RET = 0xD65F03C0; // ret指令 (aarch64)
    unsigned int MOV_X0_1 = 0xD2800020; // mov x0, #1 20 00 80 D2

    unsigned long f__cfi_slowpath = kallsyms_lookup_name_ex("__cfi_slowpath");
    if (f__cfi_slowpath) {
        unsigned int* p = (unsigned int*)f__cfi_slowpath;
        if(*p != RET) {
            hook_write_range(p, &RET, INSTRUCTION_SIZE);
            ret++;
            wuwa_err("patch __cfi_slowpath successed\n");
        } else {
            wuwa_info("__cfi_slowpath already patched\n");
        }
    }

    unsigned long f__cfi_slowpath_diag = kallsyms_lookup_name_ex("__cfi_slowpath_diag");
    if (f__cfi_slowpath_diag) {
        unsigned int* p = (unsigned int*)f__cfi_slowpath_diag;
        if(*p != RET) {
            hook_write_range(p, &RET, INSTRUCTION_SIZE);
            ret++;
            wuwa_err("patch __cfi_slowpath_diag successed\n");
        } else {
            wuwa_info("__cfi_slowpath_diag already patched\n");
        }
    }

    unsigned long f_cfi_slowpath = kallsyms_lookup_name_ex("_cfi_slowpath");
    if (f_cfi_slowpath) {
        unsigned int* p = (unsigned int*)f_cfi_slowpath;
        if(*p != RET) {
            hook_write_range(p, &RET, INSTRUCTION_SIZE);
            ret++;
            wuwa_err("patch _cfi_slowpath successed\n");
        } else {
            wuwa_info("_cfi_slowpath already patched\n");
        }
    }

    unsigned long f__cfi_check_fail = kallsyms_lookup_name_ex("__cfi_check_fail");
    if (f__cfi_check_fail) {
        unsigned int* p = (unsigned int*)f__cfi_check_fail;
        if(*p != RET) {
            hook_write_range(p, &RET, INSTRUCTION_SIZE);
            ret++;
            wuwa_err("patch __cfi_check_fail successed\n");
        } else {
            wuwa_info("__cfi_check_fail already patched\n");
        }
    }

    unsigned long f__ubsan_handle_cfi_check_fail_abort = kallsyms_lookup_name_ex("__ubsan_handle_cfi_check_fail_abort");
    if (f__ubsan_handle_cfi_check_fail_abort) {
        unsigned int* p = (unsigned int*)f__ubsan_handle_cfi_check_fail_abort;
        if(*p != RET) {
            hook_write_range(p, &RET, INSTRUCTION_SIZE);
            ret++;
            wuwa_err("patch __ubsan_handle_cfi_check_fail_abort successed\n");
        } else {
            wuwa_info("__ubsan_handle_cfi_check_fail_abort already patched\n");
        }
    }

    unsigned long f__ubsan_handle_cfi_check_fail = kallsyms_lookup_name_ex("__ubsan_handle_cfi_check_fail");
    if (f__ubsan_handle_cfi_check_fail) {
        unsigned int* p = (unsigned int*)f__ubsan_handle_cfi_check_fail;
        if(*p != RET) {
            hook_write_range(p, &RET, INSTRUCTION_SIZE);
            ret++;
            wuwa_err("patch __ubsan_handle_cfi_check_fail successed\n");
        } else {
            wuwa_info("__ubsan_handle_cfi_check_fail already patched\n");
        }
    }

    unsigned long freport_cfi_failure = kallsyms_lookup_name_ex("report_cfi_failure");
    if (freport_cfi_failure) {
        unsigned int* p = (unsigned int*)freport_cfi_failure;
        if(*p != MOV_X0_1) {
            hook_write_range(p, &MOV_X0_1, INSTRUCTION_SIZE);
            hook_write_range(p + 1, &RET, INSTRUCTION_SIZE);
            ret++;
        } else {
            wuwa_info("report_cfi_failure already patched\n");
        }
    }

    return ret;
}
