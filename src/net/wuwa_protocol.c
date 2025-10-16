#include "wuwa_protocol.h"

#include <asm-generic/errno.h>

#include "wuwa_common.h"

#include <net/sock.h>

#include "wuwa_ioctl.h"
#include "wuwa_sock.h"

static int free_family = AF_DECnet;

struct proto wuwa_proto = {
    .name = "NFC_LLCP",
    .owner = THIS_MODULE,
    .obj_size = sizeof(struct wuwa_sock),
};

static int register_free_family(void) {
    int err = 0, i = 0;

    for (i = 0; i < ARRAY_SIZE(ioctl_handlers); i++) {
        wuwa_info("registered ioctl command: %u\n", ioctl_handlers[i].cmd);
    }

    for (int family = free_family; family < NPROTO; family++) {
        wuwa_family_ops.family = family;
        err = sock_register(&wuwa_family_ops);
        if (err)
            continue;
        free_family = family;
        wuwa_proto_ops.family = free_family;
        wuwa_info("find free proto_family: %d\n", wuwa_proto_ops.family);
        return 0;
    }

    wuwa_err("can't find any free proto_family!\n");
    return err;
}

int wuwa_proto_init(void) {
    int err = proto_register(&wuwa_proto, 1);
    if (err)
        goto out;

    err = register_free_family();
    if (err)
        goto out_proto;

    return 0;

    sock_unregister(free_family);
out_proto:
    proto_unregister(&wuwa_proto);
out:
    return err;
}

void wuwa_proto_cleanup(void) {
    sock_unregister(free_family);
    proto_unregister(&wuwa_proto);
}

static int wuwa_sock_create(struct net* net, struct socket* sock, int protocol, int kern) {
    if (!capable(CAP_NET_BIND_SERVICE)) {
        return -EACCES;
    }

    uid_t caller_uid = *(uid_t*)&current_cred()->uid;
    if (caller_uid != 0) {
        wuwa_warn("only root can create wuwa socket!\n");
        return -EAFNOSUPPORT;
    }

    if (sock->type != SOCK_RAW) {
        wuwa_warn("socket must be SOCK_RAW!\n");
        return -ENOKEY;
    }

    sock->state = SS_UNCONNECTED;
    struct sock* sk = sk_alloc(net, PF_INET, GFP_KERNEL, &wuwa_proto, kern);
    if (!sk) {
        wuwa_warn("sk_alloc failed!\n");
        return -ENOBUFS;
    }

    wuwa_family_ops.family = free_family;
    sock->ops = &wuwa_proto_ops;
    sock_init_data(sock, sk);

    struct wuwa_sock* ws = (struct wuwa_sock*)sk;
    ws->version = 1;
    ws->session = current->pid;
    ws->used_pages = arraylist_create(4);

    return 0;
}

struct net_proto_family wuwa_family_ops = {
    .family = PF_DECnet,
    .create = wuwa_sock_create,
    .owner = THIS_MODULE,
};
