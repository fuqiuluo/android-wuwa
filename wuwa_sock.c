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

static __poll_t wuwa_poll(struct file* file, struct socket* sock, struct poll_table_struct* wait) { return 0; }

static int wuwa_setsockopt(struct socket* sock, int level, int optname, sockptr_t optval, unsigned int optlen) {
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

static int wuwa_getsockopt(struct socket* sock, int level, int optname, char __user* optval, int __user* optlen) {
    return 0;
}

static int wuwa_bind(struct socket* sock, struct sockaddr* saddr, int len) { return -EOPNOTSUPP; }

static int wuwa_connect(struct socket* sock, struct sockaddr* saddr, int len, int flags) { return -EOPNOTSUPP; }

// int (*)(struct socket *, struct sockaddr *, int)' with an expression of type 'int (struct socket *, struct  sockaddr *, int *, int)
#if  defined(MAGIC_WUWA_GETNAME)
static int wuwa_getname(struct socket* sock, struct sockaddr* saddr, int* len, int peer) { return -EOPNOTSUPP; }
#else
static int wuwa_getname(struct socket* sock, struct sockaddr* saddr, int peer) { return -EOPNOTSUPP; }
#endif

static int wuwa_recvmsg(struct socket* sock, struct msghdr* m, size_t len, int flags) { return -EOPNOTSUPP; }

static int wuwa_sendmsg(struct socket* sock, struct msghdr* m, size_t len) { return -EOPNOTSUPP; }

static int wuwa_socketpair(struct socket *sock1, struct socket *sock2)
{
	return -EOPNOTSUPP;
}

static int wuwa_accept(struct socket *sock, struct socket *newsock, int flags,
		   bool kern)
{
	return -EOPNOTSUPP;
}

static int wuwa_listen(struct socket *sock, int backlog)
{
	return -EOPNOTSUPP;
}

static int wuwa_shutdown(struct socket *sock, int how)
{
	return -EOPNOTSUPP;
}

static int wuwa_mmap(struct file *file, struct socket *sock, struct vm_area_struct *vma)
{
	/* Mirror missing mmap method error code */
	return -ENODEV;
}

struct proto_ops wuwa_proto_ops = {
    .family = PF_DECnet,
    .owner = THIS_MODULE,
    .release = wuwa_release,
    .bind = wuwa_bind,
    .connect = wuwa_connect,
    .socketpair = wuwa_socketpair,
    .accept = wuwa_accept,
    .getname = wuwa_getname,
    .poll = wuwa_poll,
    .ioctl = wuwa_ioctl,
    .listen = wuwa_listen,
    .shutdown = wuwa_shutdown,
    .setsockopt = wuwa_setsockopt,
    .getsockopt = wuwa_getsockopt,
    .sendmsg = wuwa_sendmsg,
    .recvmsg = wuwa_recvmsg,
    .mmap = wuwa_mmap,
};
