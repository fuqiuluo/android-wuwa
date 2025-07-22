#ifndef WUWA_PAGE_WALK_H
#define WUWA_PAGE_WALK_H

#include <linux/mm_types.h>

void traverse_page_tables(struct mm_struct *mm);

#endif //WUWA_PAGE_WALK_H
