/*
 * CCI over Ethernet
 * Copyright © INRIA 2011
 */

#ifndef CCIETH_COMMON_H
#define CCIETH_COMMON_H 1

#include <linux/idr.h>
#include <linux/spinlock.h>
#include <linux/list.h>

#include "ccieth_io.h"

struct ccieth_endpoint {
	struct net_device *ifp;
	int id;

	struct list_head event_list;
	spinlock_t event_list_lock;

	struct idr connection_idr;
	spinlock_t connection_idr_lock;
};

struct ccieth_endpoint_event {
	struct list_head list;
	struct ccieth_ioctl_get_event event;
};

struct ccieth_connection {
	int id;
	/* FIXME: cache skb headers? */
	__u8 dest_addr[6];
	__u32 dest_eid;
};

extern struct idr ccieth_ep_idr;

extern void ccieth_recv_init(void);
extern void ccieth_recv_exit(void);

#endif /* CCIETH_COMMON_H */
