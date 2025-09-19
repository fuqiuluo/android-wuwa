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
    wuwa_d0_mm_fault.o

all:
	make -C $(KDIR) M=$(PWD) modules

clean:
	make -C $(KDIR) M=$(PWD) clean

.PHONY: all clean
