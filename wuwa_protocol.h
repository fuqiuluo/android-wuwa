#ifndef WUWA_PROTOCOL_H
#define WUWA_PROTOCOL_H

#include "wuwa_common.h"

int wuwa_proto_init(void);
void wuwa_proto_cleanup(void);

extern struct proto wuwa_proto;
extern struct net_proto_family wuwa_family_ops;

#endif /* WUWA_PROTOCOL_H */