#include "wuwa_sock.h"
#include <asm/pgalloc.h>
#include <asm/pgtable-hwdef.h>
#include "wuwa_ioctl.h"
#include "wuwa_protocol.h"
#include "wuwa_utils.h"

#include "wuwa_safe_signal.h"

static int wuwa_release(struct socket* sock) {
    wuwa_info("release wuwa sock\n");

    struct sock* sk = sock->sk;
    if (!sk) {
        return 0;
    }

    struct wuwa_sock* ws = (struct wuwa_sock*)sk;
    ws->version = 0;

    if (ws->session) {
        wuwa_del_unsafe_region(ws->session);
        ws->session = 0;
    }

    if (ws->used_pages) {
        for (int i = 0; i < ws->used_pages->size; ++i) {
            struct page* page = (typeof(page))arraylist_get(ws->used_pages, i);
            if (page) {
                __free_page(page);
            }
        }
        ovo_info("free %lu used pages\n", ws->used_pages->size);
        arraylist_destroy(ws->used_pages);
    }

    sock_orphan(sk);
    sock_put(sk);
    return 0;
}

static int wuwa_ioctl(struct socket* sock, unsigned int cmd, unsigned long arg) {
    void __user* argp = (void __user*)arg;

    int i;
    for (i = 0; i < ARRAY_SIZE(ioctl_handlers); i++) {
        if (cmd == ioctl_handlers[i].cmd) {
            if (ioctl_handlers[i].handler == NULL) {
                continue;
            }
            return ioctl_handlers[i].handler(sock, argp);
        }
    }

    wuwa_warn("unsupported ioctl command: %u\n", cmd);
    return -ENOTTY;
}

static __poll_t sock_no_poll(struct file* file, struct socket* sock, struct poll_table_struct* wait) { return 0; }

static int sock_no_setsockopt(struct socket* sock, int level, int optname, sockptr_t optval, unsigned int optlen) {
#if defined(BUILD_HIDE_SIGNAL)
    if (optname == SOCK_OPT_SET_MODULE_VISIBLE) {
        if (optval.user != NULL) {
            show_module();
        } else {
            hide_module();
        }
        return 0;
    }
#endif

    return -ENOPROTOOPT;
}

static int sock_no_getsockopt(struct socket* sock, int level, int optname, char __user* optval, int __user* optlen) {
    return 0;
}

struct proto_ops wuwa_proto_ops = {
    .family = PF_DECnet,
    .owner = THIS_MODULE,
    .release = wuwa_release,
    .bind = sock_no_bind,
    .connect = sock_no_connect,
    .socketpair = sock_no_socketpair,
    .accept = sock_no_accept,
    .getname = sock_no_getname,
    .poll = sock_no_poll,
    .ioctl = wuwa_ioctl,
    .listen = sock_no_listen,
    .shutdown = sock_no_shutdown,
    .setsockopt = sock_no_setsockopt,
    .getsockopt = sock_no_getsockopt,
    .sendmsg = sock_no_sendmsg,
    .recvmsg = sock_no_recvmsg,
    .mmap = sock_no_mmap,
};
