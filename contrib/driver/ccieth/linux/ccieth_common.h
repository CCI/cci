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
};

struct ccieth_endpoint_event {
	struct list_head list;
	struct ccieth_ioctl_get_event event;
};

extern struct idr ccieth_ep_idr;

extern void ccieth_recv_init(void);
extern void ccieth_recv_exit(void);

#endif /* CCIETH_COMMON_H */
