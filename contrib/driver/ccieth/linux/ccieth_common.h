/*
 * CCI over Ethernet
 *
 * Copyright © 2011-2012 Inria.  All rights reserved.
 * $COPYRIGHT$
 */

#ifndef CCIETH_COMMON_H
#define CCIETH_COMMON_H 1

#include <linux/idr.h>
#include <linux/spinlock.h>
#include <linux/skbuff.h>
#include <linux/list.h>
#include <linux/kref.h>
#include <linux/workqueue.h>

#include "ccieth_io.h"

#define CCIETH_EVENT_SLOT_NR 64

struct ccieth_endpoint;

struct ccieth_endpoint_event {
	struct list_head list;
	struct ccieth_ioctl_get_event event;
	void (*destructor)(struct ccieth_endpoint *, struct ccieth_endpoint_event *);
};

struct ccieth_endpoint {
	struct net_device __rcu *ifp;
	__u8 addr[6];
	int max_send_size;
	int id;

	/* modified by both ioctl and network receive handler, needs _bh() */
	struct list_head event_list;
	spinlock_t event_list_lock;
	struct list_head free_event_list;
	spinlock_t free_event_list_lock;

	struct sk_buff_head deferred_connect_recv_queue;
	struct work_struct deferred_connect_recv_work;

	/* modified by ioctl and deferred network handler, does not need _bh() */
	struct idr connection_idr;
	spinlock_t connection_idr_lock;
	atomic_t connection_req_seqnum;

	struct rcu_head release_ifp_rcu_head;
	struct net_device *release_ifp;

	struct ccieth_endpoint_event embedded_event;
};

/* connection status automata:
 *
 * on connect ioctl:
 * - initiator creates connection with status REQUESTED
 * - timeout while REQUESTED to resend send_connect
 *
 * on incoming connect:
 * - target creates connection with status RECEIVED, in the receive side to detect duplicates
 * - the number of received (or total?) connections in limited to avoid ddos
 * - event only delivered to user-space if we created a connection
 *
 * on accept ioctl:
 * - target switches status to READY
 * - initiator switches status to READY when receiving accept
 *
 * on reject ioctl:
 * - target switches status to REJECTED
 * - initiator destroys connection when receiving reject
 * - initiator sends a reject ack when receiving reject, even if connection was already destroyed
 * - target destroys connection when receiving reject ack
 * - timeout while REJECTED to resend send_reject
 */
enum ccieth_connection_status {
	/* status for both sides */
	CCIETH_CONNECTION_READY,     /* accept sent or received */
	CCIETH_CONNECTION_CLOSING,   /* timeout'ing, being disconnected, or endpoint being destroyed, already unhashed */
	/* initiator side */
	CCIETH_CONNECTION_REQUESTED, /* request sent */
	/* target side */
	CCIETH_CONNECTION_RECEIVED,  /* request received, not accepted or rejected yet */
	CCIETH_CONNECTION_REJECTED,  /* reject sent and not acked yet */
};

#define CCIETH_CONNECT_RESEND_DELAY (HZ)

struct ccieth_connection {
	int id; /* always valid */ /* FIXME keep in network order too? */
	enum ccieth_connection_status status;
	struct ccieth_endpoint *ep;

	__u8 attribute;
	__u32 req_seqnum;
	__u32 max_send_size;
	__u64 user_conn_id;

	unsigned long expire; /* in jiffies */
	struct timer_list timer;
	struct sk_buff *skb;

	/* dest fields are valid when status RECEIVED, READY or REJECTED */
	/* FIXME: store in network order? */
	int dest_id;
	__u8 dest_addr[6];
	__u32 dest_eid;

	/* FIXME: cache skb headers? */

	struct rcu_head destroy_rcu_head;

	struct ccieth_endpoint_event embedded_event;
};

extern struct idr ccieth_ep_idr;

extern int ccieth_net_init(void);
extern void ccieth_net_exit(void);

extern int ccieth_destroy_connection_idrforeach_cb(int id, void *p, void *data);
extern int ccieth_connect_request(struct ccieth_endpoint *ep, struct ccieth_ioctl_connect_request *arg);
extern int ccieth_connect_accept(struct ccieth_endpoint *ep, struct ccieth_ioctl_connect_accept *arg);
extern int ccieth_connect_reject(struct ccieth_endpoint *ep, struct ccieth_ioctl_connect_reject *arg);
extern void ccieth_deferred_connect_recv_workfunc(struct work_struct *work);
extern int ccieth_defer_connect_recv(struct net_device *ifp, struct sk_buff *skb);

static inline __u32
ccieth_max_send_size(__u32 mtu)
{
	return mtu >= 9000 ? 8192 : 1024;
}

#endif /* CCIETH_COMMON_H */
