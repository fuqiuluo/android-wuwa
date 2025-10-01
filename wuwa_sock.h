#ifndef WUWA_SOCK_H
#define WUWA_SOCK_H

#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/net.h>
#include <linux/skbuff.h>
#include <linux/socket.h>
#include <net/sock.h>

struct wuwa_sock;

extern struct proto_ops wuwa_proto_ops;

#define SOCK_OPT_SET_MODULE_VISIBLE 100

#endif // WUWA_SOCK_H
