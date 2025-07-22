#include "wuwa_utils.h"

#include <linux/mm.h>
#include <linux/printk.h>
#include <linux/pgtable.h>
#include <linux/hugetlb.h>
#include <linux/interrupt.h>

pte_t *page_from_virt_user(struct mm_struct *mm, uintptr_t va) {
    pgd_t *pgd;
    p4d_t *p4d;
    pud_t *pud;
    pmd_t *pmd;
    pte_t *ptep = NULL;

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

    ptep = pte_offset_map(pmd, va);
    if (!ptep) {
        wuwa_warn("Failed to map PTE for address 0x%lx\n", va);
        goto out;
    }
out:
    MM_READ_UNLOCK(mm);

    return ptep;
}

phys_addr_t vaddr_to_phy_addr(struct mm_struct *mm, uintptr_t va) {
    if (!mm) {
        wuwa_warn("mm_struct is NULL, cannot perform translation\n");
        return 0;
    }

    pte_t *ptep = page_from_virt_user(mm, va);
    if (!ptep) {
        wuwa_err("failed to get PTE for virtual address 0x%lx\n", va);
        return 0;
    }

    if (!pte_present(*ptep)) {
        wuwa_err("PTE not present for virtual address 0x%lx\n", va);
        return 0;
    }

    phys_addr_t page_addr = pte_pfn(*ptep) << PAGE_SHIFT;

    return page_addr + (va & PAGE_SIZE - 1);
}

unsigned long kallsyms_lookup_name(const char *name) {
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 7, 0)
    typedef unsigned long (*kallsyms_lookup_name_t)(const char *name);

    static kallsyms_lookup_name_t lookup_name = NULL;
    if (lookup_name == NULL) {
        struct kprobe kp = {
            .symbol_name = "kallsyms_lookup_name"
        };

        if(register_kprobe(&kp) < 0) {
            return 0;
        }

        lookup_name = (kallsyms_lookup_name_t) kp.addr;
        unregister_kprobe(&kp);
    }
    return lookup_name(name);
#else
    return kallsyms_lookup_name(symbol_name);
#endif
}

struct task_struct * get_target_task(pid_t pid) {
    struct pid* pid_struct = find_get_pid(pid);
    if (!pid_struct) {
        return NULL;
    }

    struct task_struct *task = get_pid_task(pid_struct, PIDTYPE_PID);
    put_pid(pid_struct);
    if (!task) {
        return NULL;
    }

    return task;
}

int disable_kprobe_blacklist(void) {
    struct kprobe_blacklist_entry *ent;
    struct list_head *kprobe_blacklist = (struct list_head *) kallsyms_lookup_name("kprobe_blacklist");
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

    ovo_info("Disabled %d kprobe blacklist entries\n", count);

    return 0;
}

void compare_pt_regs(struct pt_regs *regs1, struct pt_regs *regs2) {
#if CONFIG_COMPARE_PT_REGS == 1
    ovo_info("==> Comparing pt_regs:\n");

    for (int i = 0; i < 31; ++i) {
        if (regs1->regs[i] != regs2->regs[i]) {
            ovo_info("reg[%d] changed from %llx to %llx\n", i, regs1->regs[i], regs2->regs[i]);
        }
    }

    if (regs1->sp != regs2->sp) {
        ovo_info("sp changed from %llx to %llx\n", regs1->sp, regs2->sp);
    }

    if (regs1->pc != regs2->pc) {
        ovo_info("pc changed from %llx to %llx\n", regs1->pc, regs2->pc);
    }

    if (regs1->pstate != regs2->pstate) {
        ovo_info("pstate changed from %llx to %llx\n", regs1->pstate, regs2->pstate);
    }

    if (regs1->sdei_ttbr1 != regs2->sdei_ttbr1) {
        ovo_info("sdei_ttbr1 changed from %llx to %llx\n", regs1->sdei_ttbr1, regs2->sdei_ttbr1);
    }

    if (regs1->pmr_save != regs2->pmr_save) {
        ovo_info("pmr_save changed from %llx to %llx\n", regs1->pmr_save, regs2->pmr_save);
    }

    if (regs1->stackframe[0] != regs2->stackframe[0] ||
        regs1->stackframe[1] != regs2->stackframe[1]) {
        ovo_info("stackframe changed from [%llx, %llx] to [%llx, %llx]\n",
                 regs1->stackframe[0], regs1->stackframe[1],
                 regs2->stackframe[0], regs2->stackframe[1]);
    }
#endif
}

void compare_task_struct(struct task_struct *task1, struct task_struct *task2) {
#if CONFIG_COMPARE_TASK == 1
    ovo_info("==> Comparing task_struct:\n");
#ifdef CONFIG_THREAD_INFO_IN_TASK
    if (task1->thread_info.flags != task2->thread_info.flags) {
        ovo_info("thread_info.flags changed from %lx to %lx\n", task1->thread_info.flags, task2->thread_info.flags);
    }

    if (task1->thread_info.cpu != task2->thread_info.cpu) {
        ovo_info("thread_info.cpu changed from %d to %d\n", task1->thread_info.cpu, task2->thread_info.cpu);
    }
#endif

    if (task1->__state != task2->__state) {
        ovo_info("__state changed from %u to %u\n", task1->__state, task2->__state);
    }

    if (task1->stack != task2->stack) {
        ovo_info("stack pointer changed from %p to %p\n", task1->stack, task2->stack);
    }

    if (task1->flags != task2->flags) {
        ovo_info("flags changed from %u to %u\n", task1->flags, task2->flags);
    }

    if (task1->ptrace != task2->ptrace) {
        ovo_info("ptrace changed from %u to %u\n", task1->ptrace, task2->ptrace);
    }

    if (task1->pid != task2->pid) {
        ovo_info("pid changed from %d to %d\n", task1->pid, task2->pid);
    }

    if (task1->tgid != task2->tgid) {
        ovo_info("tgid changed from %d to %d\n", task1->tgid, task2->tgid);
    }
#endif
}

#define W_PHYS_PFN(x)	((unsigned long)((x) >> PAGE_SHIFT))
#define	wuwa_phys_to_pfn(paddr)	W_PHYS_PFN(paddr)

struct page* vaddr_to_page(struct mm_struct *mm, uintptr_t va) {
#if !defined(pfn_to_page)
#error "vaddr_to_page failed: pfn_to_page not found"
#endif
    return pfn_to_page(wuwa_phys_to_pfn(vaddr_to_phy_addr(mm, va)));
}

struct karray_list * arraylist_create(size_t initial_capacity) {
    struct karray_list *list = kmalloc(sizeof(*list), GFP_KERNEL);
    if (!list) return NULL;

    if (initial_capacity < ARRAYLIST_DEFAULT_CAPACITY)
        initial_capacity = ARRAYLIST_DEFAULT_CAPACITY;

    list->data = kmalloc_array(initial_capacity, sizeof(void *), GFP_KERNEL);
    if (!list->data) {
        kfree(list);
        return NULL;
    }

    list->size = 0;
    list->capacity = initial_capacity;
    return list;
}

static int ensure_capacity(struct karray_list *list, size_t min_capacity) {
    if (min_capacity <= list->capacity) return 0;

    size_t new_capacity = list->capacity + (list->capacity >> 1);
    if (new_capacity < min_capacity) new_capacity = min_capacity;

    void **new_data = krealloc_array(list->data, new_capacity, sizeof(void *), GFP_KERNEL);
    if (!new_data) return -ENOMEM;

    list->data = new_data;
    list->capacity = new_capacity;
    return 0;
}

int arraylist_add(struct karray_list *list, void *element) {
    int ret = 0;

    if (ensure_capacity(list, list->size + 1)) {
        ret = -ENOMEM;
        goto out;
    }

    list->data[list->size++] = element;

    out:
    return ret;
}

void *arraylist_get(struct karray_list *list, size_t index) {
    void *element = NULL;

    if (index < list->size)
        element = list->data[index];
    return element;
}

void *arraylist_remove(struct karray_list *list, size_t index) {
    void *element = NULL;

    if (index >= list->size) goto out;

    element = list->data[index];
    memmove(&list->data[index], &list->data[index+1],
            (list->size - index - 1) * sizeof(void *));
    list->size--;

    out:
    return element;
}

void arraylist_destroy(struct karray_list *list) {
    if (list->data)
        kfree(list->data);
    kfree(list);
}
