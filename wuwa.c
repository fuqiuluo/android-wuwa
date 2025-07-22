#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/syscalls.h>
#include <linux/kprobes.h>
#include <asm/unistd.h>
#include <asm/tlbflush.h>
#include <linux/list.h>
#include <linux/types.h>
#include <linux/init_task.h>
#include <linux/fs.h>
#include "wuwa_sock.h"
#include "wuwa_protocol.h"
#include "wuwa_common.h"
#include "wuwa_utils.h"
#include "wuwa_safe_signal.h"
#include "wuwa_d0_mm_fault.h"

static int __init wuwa_init(void) {
    int ret;
    wuwa_info("helo!\n");

    ret = disable_kprobe_blacklist();
    if (ret) {
        wuwa_err("disable_kprobe_blacklist failed: %d\n", ret);
        return ret;
    }

    ret = wuwa_proto_init();
    if (ret) {
        wuwa_err("wuwa_socket_init failed: %d\n", ret);
        goto out;
    }

    ret = wuwa_safe_signal_init();
    if (ret) {
        wuwa_err("wuwa_safe_signal_init failed: %d\n", ret);
        goto clean_sig;
    }

    ret = init_d0_mm_fault();
    if (ret) {
        wuwa_err("init_d0_mm_fault failed: %d\n", ret);
        goto clean_d0;
    }

    return 0;

    clean_d0:
    wuwa_safe_signal_cleanup();

    clean_sig:
    wuwa_proto_cleanup();

    out:
    return ret;
}

static void __exit wuwa_exit(void) {
    wuwa_info("bye!\n");
    wuwa_proto_cleanup();
    wuwa_safe_signal_cleanup();
    cleanup_d0_mm_fault();
}

module_init(wuwa_init);
module_exit(wuwa_exit);

MODULE_AUTHOR("wuwa233");
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("https://github.com/wuwa233");
MODULE_VERSION("1.0.0");

MODULE_IMPORT_NS(DMA_BUF);