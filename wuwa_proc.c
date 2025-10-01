#include "wuwa_proc.h"

int is_invisible(pid_t pid) {
    struct task_struct* task;
    if (!pid)
        return 0;
    task = find_task_by_vpid(pid);
    if (!task)
        return 0;
    if (task->flags & PF_INVISIBLE)
        return 1;
    return 0;
}
