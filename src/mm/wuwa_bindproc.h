#ifndef WUWA_BINDPROC_H
#define WUWA_BINDPROC_H

#include <linux/socket.h>

int do_bind_proc(struct socket* sock, void __user* arg);

#endif // WUWA_BINDPROC_H