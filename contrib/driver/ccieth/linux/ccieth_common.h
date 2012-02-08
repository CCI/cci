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
#include <linux/completion.h>

#include "ccieth_io.h"
#include "ccieth_hal.h"

#define CCIETH_EVENT_SLOT_NR 64

#define CCIETH_MAX_CONNECTION_RECEIVED 64

struct ccieth_endpoint;
struct ccieth_pkt_header_msg;

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

	/* modified by ioctl and deferred network handler, does not need _bh().
	 * accessed under RCU read lock. */
	struct idr connection_idr;
	spinlock_t connection_idr_lock;
	atomic_t connection_req_seqnum;
	atomic_t connection_received; /* up to CCIETH_MAX_CONNECTION_RECEIVED */

	struct rcu_head release_ifp_rcu_head;
	struct net_device *release_ifp;

	struct ccieth_endpoint_event embedded_event;
};

/* connection status automata:
 *
 * on connect_request ioctl:
 * - initiator creates connection with status REQUESTED
 * - initiator resends until acked
 * - timeout while status REQUESTED to resend connect_request
 *
 * on incoming connect_request:
 * - target creates connection with status RECEIVED, in the receive side to detect duplicates
 * - event only delivered to user-space if we successfully created a connection
 * - TODO the number of received (or total?) connections in limited to avoid ddos
 *
 * on accept ioctl:
 * - target switches connection status from RECEIVED to READY
 * - target resends until acked
 * - initiator switches status to READY when receiving accept
 *
 * on reject ioctl:
 * - target switches connection status from RECEIVED to REJECTED
 * - target resends until acked, then destroys the connection
 * - initiator destroys connection when receiving reject
 *
 * on destroy:
 * - status is atomically test-and-set to CLOSING
 * - connection is removed from endpoint idr to avoid new users
 * - connection is destroyed after RCU grace period
 */
enum ccieth_connection_status {
	/* status for both sides */
	CCIETH_CONNECTION_READY,     /* connection is running */
	CCIETH_CONNECTION_CLOSING,   /* timeout'ing, being disconnected, or endpoint being destroyed, already unhashed */
	/* initiator side */
	CCIETH_CONNECTION_REQUESTED, /* request sent, maybe acked, but not replied or rejected yet */
	/* target side */
	CCIETH_CONNECTION_RECEIVED,  /* request received, not accepted or rejected yet */
	CCIETH_CONNECTION_REJECTED,  /* reject sent and not acked yet */
};

#define CCIETH_CONNECT_RESEND_DELAY (HZ)

struct ccieth_connection {
	int id; /* always valid */ /* FIXME keep in network order too? */
	enum ccieth_connection_status status;
	struct ccieth_endpoint *ep;
	int need_ack;

	__u32 req_seqnum;
	__u32 max_send_size;
	__u64 user_conn_id;

#define CCIETH_CONN_FLAG_RELIABLE (1<<0)
#define CCIETH_CONN_FLAG_ORDERED (1<<1)
#define CCIETH_CONN_FLAG_DEFER_EARLY_MSG (1<<2)
	unsigned long flags;

	/* only if CCIETH_CONN_FLAG_DEFERRED_EARLY_MSG */
	struct sk_buff_head deferred_msg_recv_queue;

	/* only if CCIETH_CONN_FLAG_RELIABLE */
	/* send-side reliability */
	spinlock_t send_lock;
	__u32 send_next_seqnum;
	struct sk_buff *send_queue_first, *send_queue_last;
	/* recv-side reliability */
	spinlock_t recv_lock;
	__u32 recv_last_full_seqnum;
#define CCIETH_CONN_RECV_BITMAP_BITS BITS_PER_LONG
	unsigned long recv_next_bitmap;
	struct work_struct msg_ack_work;

	/* resending of request, accept or reject */
	unsigned long expire; /* in jiffies, only for request because it has a timeout */
	struct timer_list timer;
	struct sk_buff *skb; /* cached skb, to be cloned for resending */

	/* dest fields are valid when status RECEIVED, READY or REJECTED */
	/* FIXME: store in network order? */
	int dest_id;
	__u8 dest_addr[6];
	__u32 dest_eid;

	/* FIXME: cache skb headers? */

	struct rcu_head destroy_rcu_head;

	/* event to be used when destroying the connection:
	 * the user should set the status to CLOSING first,
	 * and let the event destructor destroy the connection for real.
	 */
	struct ccieth_endpoint_event embedded_event;
};

/* stored in skbuff cb private field while queued for deferred processing */
struct ccieth_connect_skb_cb {
	__u8 type;
};
#define CCIETH_CONNECT_SKB_CB(__skb) ((struct ccieth_connect_skb_cb *)&((__skb)->cb[0]))

/* stored in skbuff cb private field while queued for possible retransmit (RO or RU),
 * or while queued before delivery to userspace (RO connection only) */
struct ccieth_msg_skb_cb {
	__u32 seqnum;
};
#define CCIETH_MSG_SKB_CB(__skb) ((struct ccieth_msg_skb_cb *)&((__skb)->cb[0]))

extern struct idr ccieth_ep_idr; /* accessed under RCU read lock */

extern int ccieth_destroy_connection_idrforeach_cb(int id, void *p, void *data);
extern int ccieth_connect_request(struct ccieth_endpoint *ep, struct ccieth_ioctl_connect_request *arg);
extern int ccieth_connect_accept(struct ccieth_endpoint *ep, struct ccieth_ioctl_connect_accept *arg);
extern int ccieth_connect_reject(struct ccieth_endpoint *ep, struct ccieth_ioctl_connect_reject *arg);
extern void ccieth_deferred_connect_recv_workfunc(struct work_struct *work);
extern int ccieth_defer_connect_recv(struct net_device *ifp, __u8 type, struct sk_buff *skb);

extern int ccieth_msg(struct ccieth_endpoint *ep, struct ccieth_ioctl_msg *arg);
extern int ccieth_msg_ack(struct ccieth_connection *conn);

extern void ccieth_conn_uu_defer_recv_msg(struct ccieth_connection *conn, struct sk_buff *skb);
extern int ccieth__recv_msg(struct ccieth_endpoint *ep, struct ccieth_connection *conn, struct ccieth_pkt_header_msg *hdr, struct sk_buff *skb);

extern int ccieth_recv(struct sk_buff *skb, struct net_device *ifp, struct packet_type *pt, struct net_device *orig_dev);

#ifdef CCIETH_DEBUG
#define dprintk printk
#else
#define dprintk(args...) do { /* nothing */ } while (0)
#endif

#endif /* CCIETH_COMMON_H */
