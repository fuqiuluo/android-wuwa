#ifndef WUWA_PAGE_WALK_H
#define WUWA_PAGE_WALK_H

#include <linux/mm_types.h>

struct page_walk_stats {
    u64 total_pte_count;
    u64 present_pte_count;
    u64 pmd_huge_count;
    u64 pud_huge_count;
};

void traverse_page_tables(struct mm_struct* mm, struct page_walk_stats* stats);

#endif // WUWA_PAGE_WALK_H
