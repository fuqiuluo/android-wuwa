#include "wuwa_page_walk.h"
#include <asm/pgtable.h>
#include <linux/hugetlb.h>
#include <linux/mm.h>
#include <linux/proc_fs.h>
#include <linux/sched/mm.h>
#include <linux/sched/signal.h>
#include <linux/seq_file.h>
#include <linux/uaccess.h>
#include "wuwa_common.h"

#include "wuwa_utils.h"

// Function to merge and print contiguous memory regions
static void print_merged_region(unsigned long* start, unsigned long* end) {
    if (*start != -1UL) {
        // [start, end) is the format used by /proc/pid/maps
        wuwa_info("Found region: 0x%lx - 0x%lx\n", *start, *end + 1);
    }
    *start = -1UL;
    *end = -1UL;
}

// Walk the Page Table Entries (PTEs)
static void walk_pte_level(pmd_t* pmd, unsigned long addr, unsigned long end, unsigned long* region_start,
                           unsigned long* region_end) {
#if defined(PTE_WALK)
    pte_t *ptep, pte;
    unsigned long current_addr;
    unsigned long pte_end;

    pte_end = (addr + PMD_SIZE) & PMD_MASK;
    if (end < pte_end)
        pte_end = end;

    ptep = pte_offset_map(pmd, addr);
    ptep = NULL;
    if (!ptep) {
        return;
    }

    for (current_addr = addr; current_addr < pte_end; current_addr += PAGE_SIZE) {
        pte = *ptep;
        if (pte_present(pte)) {
            // Found a mapped page
            if (*region_start != -1UL && current_addr != *region_end + PAGE_SIZE) {
                print_merged_region(region_start, region_end);
            }

            if (*region_start == -1UL) {
                *region_start = current_addr;
            }
            *region_end = current_addr;
        } else {
            // Gap detected, print the last region if it exists
            print_merged_region(region_start, region_end);
        }
        ptep++;
    }

    pte_unmap(ptep - ((pte_end - addr) >> PAGE_SHIFT));
#else
    wuwa_err("PTE walk not supported on this architecture.\n");
#endif
}

// Walk the Page Middle Directories (PMDs)
static void walk_pmd_level(pud_t* pud, unsigned long addr, unsigned long end, unsigned long* region_start,
                           unsigned long* region_end) {
    pmd_t* pmd;
    unsigned long next;

    pmd = pmd_offset(pud, addr);

    do {
        next = pmd_addr_end(addr, end);
        if (pmd_present(*pmd) && !pmd_none(*pmd)) {
            if (pmd_huge(*pmd)) {
                if (*region_start != -1UL && addr != *region_end + PAGE_SIZE) {
                    print_merged_region(region_start, region_end);
                }
                if (*region_start == -1UL) {
                    *region_start = addr;
                }
                *region_end = next - PAGE_SIZE;
            } else {
                walk_pte_level(pmd, addr, next, region_start, region_end);
            }
        } else {
            print_merged_region(region_start, region_end);
        }
        addr = next;
        pmd++;
    } while (addr < end);
}

// Walk the Page Upper Directories (PUDs)
static void walk_pud_level(p4d_t* p4d, unsigned long addr, unsigned long end, unsigned long* region_start,
                           unsigned long* region_end) {
    pud_t* pud;
    unsigned long next;

    pud = pud_offset(p4d, addr);

    do {
        next = pud_addr_end(addr, end);
        if (pud_present(*pud) && !pud_none(*pud)) {
            if (pud_huge(*pud)) {
                if (*region_start != -1UL && addr != *region_end + PAGE_SIZE) {
                    print_merged_region(region_start, region_end);
                }
                if (*region_start == -1UL) {
                    *region_start = addr;
                }
                *region_end = next - PAGE_SIZE;
            } else {
                walk_pmd_level(pud, addr, next, region_start, region_end);
            }
        } else {
            print_merged_region(region_start, region_end);
        }
        addr = next;
        pud++;
    } while (addr < end);
}

// Walk the Page 4th-level Directories (P4Ds)
static void walk_p4d_level(pgd_t* pgd, unsigned long addr, unsigned long end, unsigned long* region_start,
                           unsigned long* region_end) {
    p4d_t* p4d;
    unsigned long next;

    p4d = p4d_offset(pgd, addr);

    do {
        next = p4d_addr_end(addr, end);
        if (p4d_present(*p4d) && !p4d_none(*p4d)) {
            walk_pud_level(p4d, addr, next, region_start, region_end);
        } else {
            print_merged_region(region_start, region_end);
        }
        addr = next;
        p4d++;
    } while (addr < end);
}

void traverse_page_tables(struct mm_struct* mm) {
    unsigned long addr = 0;
    unsigned long region_start = -1UL, region_end = -1UL;
    pgd_t* pgd;
    unsigned long next;

    if (!mm) {
        return;
    }

    MM_READ_LOCK(mm);

    pgd = mm->pgd;

    do {
        next = pgd_addr_end(addr, TASK_SIZE);
        if (pgd_present(*pgd) && !pgd_none(*pgd)) {
            walk_p4d_level(pgd, addr, next, &region_start, &region_end);
        } else {
            print_merged_region(&region_start, &region_end);
        }
        addr = next;
        pgd++;
    } while (addr < TASK_SIZE && addr != 0);

    print_merged_region(&region_start, &region_end);

    MM_READ_UNLOCK(mm);
}
