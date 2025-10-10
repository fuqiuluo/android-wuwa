MODULE = android-wuwa

obj-m :=$(MODULE).o
$(MODULE)-objs := \
    src/core/wuwa.o \
    src/net/wuwa_sock.o \
    src/net/wuwa_protocol.o \
    src/utils/wuwa_utils.o \
    src/ioctl/wuwa_ioctl.o \
    src/mm/wuwa_page_walk.o \
    src/hook/wuwa_safe_signal.o \
    src/hook/wuwa_d0_mm_fault.o \
    src/proc/wuwa_proc.o \
    src/inlinehook/hijack_arm64.o \
    src/utils/karray_list.o

ccflags-y += -I$(src)
ccflags-y += -I$(src)/src/core -I$(src)/src/net -I$(src)/src/ioctl -I$(src)/src/mm
ccflags-y += -I$(src)/src/inlinehook -I$(src)/src/hook -I$(src)/src/proc -I$(src)/src/utils
ccflags-y += -Wno-implicit-function-declaration -Wno-strict-prototypes -Wno-int-conversion -Wno-gcc-compat
ccflags-y += -Wno-declaration-after-statement -Wno-unused-function -Wno-unused-variable

# 编译时启用 隐藏模块功能
#EXTRA_CFLAGS += -DHIDE_SELF_MODULE
# 编译时启用 PTE_MAPPING 功能
#EXTRA_CFLAGS += -DBUILD_PTE_MAPPING
# 编译时启用 HIDE_SIGNAL 功能
#EXTRA_CFLAGS += -DBUILD_HIDE_SIGNAL
#EXTRA_CFLAGS += -DPTE_WALK

all:
	make -C $(KDIR) EXTRA_CFLAGS="$(EXTRA_CFLAGS)" M=$(PWD) modules

clean:
	make -C $(KDIR) M=$(PWD) clean

.PHONY: all clean
