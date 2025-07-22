#ifndef WUWA_COMMON_H
#define WUWA_COMMON_H

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/net.h>
#include <net/sock.h>

#define WUWA_LOG_PREFIX "[wuwa] "
#define wuwa_info(fmt, ...) pr_info(WUWA_LOG_PREFIX fmt, ##__VA_ARGS__)
#define wuwa_warn(fmt, ...) pr_warn(WUWA_LOG_PREFIX fmt, ##__VA_ARGS__)
#define wuwa_err(fmt, ...) pr_err(WUWA_LOG_PREFIX fmt, ##__VA_ARGS__)
#define wuwa_debug(fmt, ...) pr_debug(WUWA_LOG_PREFIX fmt, ##__VA_ARGS__)

#define ovo_info(fmt, ...) \
    pr_info(WUWA_LOG_PREFIX "%s: " fmt, __func__, ##__VA_ARGS__)

#define ovo_warn(fmt, ...) \
    pr_warn(WUWA_LOG_PREFIX "%s: " fmt, __func__, ##__VA_ARGS__)

#define ovo_err(fmt, ...) \
    pr_err(WUWA_LOG_PREFIX "%s: " fmt, __func__, ##__VA_ARGS__)

#define ovo_debug(fmt, ...) \
    pr_debug(WUWA_LOG_PREFIX "%s: " fmt, __func__, ##__VA_ARGS__)

#define LUCKY_LUO 0x00000000faceb00c

#define CONFIG_COMPARE_TASK 1
#define CONFIG_COMPARE_PT_REGS 1

/*
 * !!!Poor performance!!!
 */
#define CONFIG_REDIRECT_VIA_ABORT 0

/*
 * !!!!Poor performance!!!
 * The LR address redirection is achieved by using the Linux signal processor mechanism.
 *  > is unsafe and has competition risks.
 *  > is only used for learning and verification that
 *     it can be injected into the executable memory and executed normally without any trace.
 */
#define CONFIG_REDIRECT_VIA_SIGNAL 1

struct wuwa_sock {
    struct sock sk;

    int version;

    struct {
        uintptr_t* page_address_array;
        size_t page_size;
    } __attribute__((aligned(8)));

    pid_t session;
};

struct wuwa_dmabuf_private {
    struct sg_table *sgt;


};

#endif /* WUWA_COMMON_H */