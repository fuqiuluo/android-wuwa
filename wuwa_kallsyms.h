#ifndef WUWA_KALLSYMS_H
#define WUWA_KALLSYMS_H

#include <linux/errno.h>
#include <linux/kernel.h>
#include <linux/sched.h>
#include "wuwa_common.h"
#include "wuwa_utils.h"

#define DECLARE_KSYM_RAW(name)                                                                                         \
    static void* _wuwa_sym_##name __section(".data");                                                                  \
    static void* __maybe_unused get_##name(void) { return _wuwa_sym_##name; }                                          \
    static int __maybe_unused ksym_find_##name(void) {                                                                 \
        _wuwa_sym_##name = (void*)kallsyms_lookup_name(#name);                                                         \
        if (!_wuwa_sym_##name) {                                                                                       \
            ovo_err("Failed to find symbol: %s\n", #name);                                                             \
            return -ENOENT;                                                                                            \
        }                                                                                                              \
        return 0;                                                                                                      \
    }

#define DECLARE_KSYM_FUN(name, ret, args)                                                                              \
    static ret(*wuwa_##name) args = NULL;                                                                              \
    static int __maybe_unused ksym_find_##name(void) {                                                                 \
        if (wuwa_##name) {                                                                                             \
            return 0;                                                                                                  \
        }                                                                                                              \
        wuwa_##name = (typeof(wuwa_##name))kallsyms_lookup_name(#name);                                                \
        if (!wuwa_##name) {                                                                                            \
            ovo_err("Failed to find symbol: %s\n", #name);                                                             \
            return -ENOENT;                                                                                            \
        }                                                                                                              \
        return 0;                                                                                                      \
    }

#endif // WUWA_KALLSYMS_H
