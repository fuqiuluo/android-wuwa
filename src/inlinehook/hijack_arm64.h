#ifndef ANDROID_WUWA_HIJACK_ARM64_H
#define ANDROID_WUWA_HIJACK_ARM64_H

#define INSTRUCTION_SIZE (4)
#define HIJACK_INST_NUM (6)
#define HIJACK_SIZE (INSTRUCTION_SIZE * HIJACK_INST_NUM)
#define HOOK_TARGET_OFFSET (0)

int init_arch(void);

__nocfi int hook_write_range(void *target, void *source, int size);

#endif // ANDROID_WUWA_HIJACK_ARM64_H
