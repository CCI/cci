/*
 * CCI over Ethernet
 * Copyright © INRIA 2011
 */

#ifndef CCIETH_COMMON_H
#define CCIETH_COMMON_H 1

#include <linux/idr.h>

struct ccieth_endpoint {
	struct net_device *ifp;
	int id;
	char * recvq;
	__u32 last_busy_slot_offset; /* offset of the last filled slot.
				      * its next_busy_offset must be -1.
				      * it will be changed when a new free slot is used.
				      */
	__u32 last_free_slot_offset; /* offset of the last freed slot.
				      * its next_free_offset must be -1.
				      * it will be changed when a new busy slot is returned.
				      */
	__u32 first_free_slot_offset; /* offset of the next freed slot to use. */
};

extern struct idr ccieth_ep_idr;

extern void ccieth_recv_init(void);
extern void ccieth_recv_exit(void);

#endif /* CCIETH_COMMON_H */
