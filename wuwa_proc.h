#ifndef ANDROID_WUWA_WUWA_PROC_H
#define ANDROID_WUWA_WUWA_PROC_H

#include <signal.h>
#include <sched.h>

#define PF_INVISIBLE 0x10000000

int is_invisible(pid_t pid);

#endif // ANDROID_WUWA_WUWA_PROC_H
