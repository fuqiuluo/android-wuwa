#ifndef WUWA_UTILS_H
#define WUWA_UTILS_H

#include <linux/mm.h>
#include <linux/types.h>
#include <linux/version.h>
#include <linux/mm_types.h>
#include "wuwa_common.h"

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(5, 8, 0))
#include <linux/mmap_lock.h>
#define MM_READ_LOCK(mm) mmap_read_lock(mm);
#define MM_READ_UNLOCK(mm) mmap_read_unlock(mm);
#define MM_WRITE_LOCK(mm) mmap_write_lock(mm);
#define MM_WRITE_UNLOCK(mm) mmap_write_unlock(mm);
#else
#include <linux/rwsem.h>
#define MM_READ_LOCK(mm) down_read(&(mm)->mmap_sem);
#define MM_READ_UNLOCK(mm) up_read(&(mm)->mmap_sem);
#define MM_WRITE_LOCK(mm) down_write(&(mm)->mmap_sem);
#define MM_WRITE_UNLOCK(mm) up_write(&(mm)->mmap_sem);
#endif

pte_t *page_from_virt_user(struct mm_struct *mm, uintptr_t va);

phys_addr_t vaddr_to_phy_addr(struct mm_struct *mm, uintptr_t va);

struct page* vaddr_to_page(struct mm_struct *mm, uintptr_t va);

unsigned long kallsyms_lookup_name(const char* symbol_name);

struct task_struct *get_target_task(pid_t pid);

int disable_kprobe_blacklist(void);

void compare_pt_regs(struct pt_regs* regs1, struct pt_regs* regs2);
void compare_task_struct(struct task_struct *task1, struct task_struct *task2);

static __always_inline void set_current(struct task_struct *tsk)
{
    unsigned long tmp = (unsigned long)tsk;

    asm volatile("msr sp_el0, %0"
             :
             : "r"(tmp)
             : "memory");
}


#define ARRAYLIST_DEFAULT_CAPACITY 16

struct karray_list {
    void **data;
    size_t size;
    size_t capacity;
};

struct karray_list *arraylist_create(size_t initial_capacity);
void arraylist_destroy(struct karray_list *list);
void *arraylist_remove(struct karray_list *list, size_t index);
void *arraylist_get(struct karray_list *list, size_t index);
int arraylist_add(struct karray_list *list, void *element);

#endif //WUWA_UTILS_H
