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

static bool check_instruction_can_hijack(uint32_t instruction)
{
	bool ret = true;

	//todo: we want to fix these instructions
	switch(instruction & 0x9f000000u) {
	case 0x10000000u:  //adr  
	case 0x90000000u:  //adrp
		ret = false;
		goto out;
	}
	switch(instruction & 0xfc000000u) {
	case 0x14000000u:  //b  
	case 0x94000000u:  //bl
		ret = false;
		goto out;
	}
	switch(instruction & 0xff000000u) {
	case 0x54000000u:  //b.c  
		ret = false;
		goto out;
	}    
	switch(instruction & 0x7e000000u) {
	case 0x34000000u:  //cbz cbnz
	case 0x36000000u:  //tbz tbnz
		ret = false;
		goto out;
	}
	switch(instruction & 0xbf000000u) {
	case 0x18000000u:  //ldr
		ret = false;
		goto out;
	}
	switch(instruction & 0x3f000000u) {
	case 0x1c000000u:  //ldrv
		ret = false;
		goto out;
	}
	switch(instruction & 0xff000000u) {
	case 0x98000000u:  //ldrsw
		ret = false;
		goto out;
	}

out:
	if (!ret) {
		wuwa_warn("instruction %x cannot be hijacked!\n", instruction);
	}
	return ret;
}

bool check_target_can_hijack(void *target)
{
	int offset = 0;
	for (; offset < HOOK_TARGET_OFFSET + HIJACK_SIZE; offset += INSTRUCTION_SIZE) {
		if (!check_instruction_can_hijack(*(uint32_t *)((char *)target + offset)))
			return false;
	}
	return true;
}