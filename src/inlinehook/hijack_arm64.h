#ifndef ANDROID_WUWA_HIJACK_ARM64_H
#define ANDROID_WUWA_HIJACK_ARM64_H

#define INSTRUCTION_SIZE 4

int init_arch(void);

__nocfi int hook_write_range(void *target, void *source, int size);

#endif // ANDROID_WUWA_HIJACK_ARM64_H
