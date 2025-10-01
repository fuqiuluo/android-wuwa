MODULE = android-wuwa

obj-m :=$(MODULE).o
$(MODULE)-objs := \
    wuwa.o \
    wuwa_sock.o \
    wuwa_protocol.o \
    wuwa_utils.o \
    wuwa_ioctl.o \
    wuwa_page_walk.o \
    wuwa_safe_signal.o \
    wuwa_d0_mm_fault.o \
    wuwa_proc.o

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
