#ifndef ANDROID_WUWA_WUWA_PROC_H
#define ANDROID_WUWA_WUWA_PROC_H

#include <linux/mm.h>
#include <linux/mm_types.h>
#include <linux/types.h>
#include <linux/version.h>
#include "wuwa_common.h"
#include <linux/sched.h>

#define PF_INVISIBLE 0x10000000

int is_invisible(pid_t pid);

#endif // ANDROID_WUWA_WUWA_PROC_H
