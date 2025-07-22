#ifndef WUWA_SOCK_H
#define WUWA_SOCK_H

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/net.h>
#include <linux/socket.h>
#include <linux/skbuff.h>
#include <net/sock.h>
#include <linux/init.h>

struct wuwa_sock;

extern struct proto_ops wuwa_proto_ops;

#endif //WUWA_SOCK_H
