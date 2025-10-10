#ifndef WUWA_SAFE_SIGNAL_H
#define WUWA_SAFE_SIGNAL_H

#include "wuwa_common.h"

int wuwa_safe_signal_init(void);
void wuwa_safe_signal_cleanup(void);

int wuwa_add_unsafe_region(pid_t session, uid_t uid, uintptr_t start, size_t num_page);
int wuwa_del_unsafe_region(pid_t pid);

#endif // WUWA_SAFE_SIGNAL_H
