#include "hijack_arm64.h"

#include "wuwa_common.h"
#include "wuwa_utils.h"

int (*aarch64_insn_write_ptr)(void *, u32) = NULL;
void (*flush_icache_range_ptr)(unsigned long, unsigned long) = NULL;

int init_arch(void) {
    aarch64_insn_write_ptr = (void *)kallsyms_lookup_name_ex("aarch64_insn_write");
    flush_icache_range_ptr = (void *)kallsyms_lookup_name_ex("caches_clean_inval_pou");
    if (!flush_icache_range_ptr) {
        flush_icache_range_ptr = (void *)kallsyms_lookup_name_ex("__flush_icache_range");
    }
    return !(aarch64_insn_write_ptr && flush_icache_range_ptr);
}

__nocfi int hook_write_range(void *target, void *source, int size)
{
    int ret = 0, i;

    for (i = 0; i < size; i = i + INSTRUCTION_SIZE) {
        ret = aarch64_insn_write_ptr(target + i, *(u32 *)(source + i));
        if (ret) {
            goto out;
        }
    }
    flush_icache_range_ptr((unsigned long)target, (unsigned long)target + size);

    out:
        return ret;
}