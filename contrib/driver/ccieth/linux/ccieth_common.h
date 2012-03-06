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
#include <linux/sched.h>
#ifdef CONFIG_CCIETH_DEBUGFS
#include <linux/debugfs.h>
#endif

#include "ccieth_io.h"
#include "ccieth_wire.h"
#include "ccieth_hal.h"

#define CCIETH_EVENT_SLOT_NR 64

#define CCIETH_MAX_CONNECTION_RECEIVED 64

struct ccieth_endpoint;
struct ccieth_pkt_header_msg;

struct ccieth_driver_event {
	struct list_head list;

	__u32 seqnum; /* for RO recv */

	/* skb data is copied into the final event during get_event()
	 * before releasing the skb.
	 * only matters if event.data_length > 0 */
	struct sk_buff *data_skb;
	unsigned data_skb_offset;

	/* the actual event */
	struct ccieth_ioctl_get_event event;
	void (*destructor) (struct ccieth_endpoint *, struct ccieth_driver_event *);
};
struct ccieth_rcu_completion {
	struct rcu_head rcu; /* for kfree_rcu() */
	struct completion completion;
	int status;
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
	__u32 free_event_list_length; /* used as debugfs u32 */
	spinlock_t free_event_list_lock;
	wait_queue_head_t event_wq;

	struct sk_buff_head deferred_connect_recv_queue;
	struct work_struct deferred_connect_recv_work;

	/* modified by ioctl and deferred network handler, does not need _bh().
	 * accessed under RCU read lock. */
	struct idr connection_idr;
	spinlock_t connection_idr_lock;
	atomic_t connection_req_seqnum;
	atomic_t connection_received;	/* up to CCIETH_MAX_CONNECTION_RECEIVED */

	struct rcu_head release_ifp_rcu_head;
	struct net_device *release_ifp;

	struct ccieth_driver_event embedded_event;

#ifdef CONFIG_CCIETH_DEBUGFS
	struct dentry *debugfs_dir;
#endif
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
	CCIETH_CONNECTION_READY,	/* connection is running */
	CCIETH_CONNECTION_CLOSING,	/* timeout'ing, being disconnected, or endpoint being destroyed, already unhashed */
	/* initiator side */
	CCIETH_CONNECTION_REQUESTED,	/* request sent, maybe acked, but not replied or rejected yet */
	/* target side */
	CCIETH_CONNECTION_RECEIVED,	/* request received, not accepted or rejected yet */
	CCIETH_CONNECTION_ACCEPTING,	/* accept sent and not acked yet */
	CCIETH_CONNECTION_REJECTING,	/* reject sent and not acked yet */
};

#define CCIETH_CONNECT_RESEND_DELAY (HZ)	/* resend connect request/accept/reject every second until acked */
#define CCIETH_MSG_RESEND_DELAY (HZ/2)	/* resend MSG every half-second until acked */
#define CCIETH_DEFERRED_MSG_ACK_DELAY (HZ/10)	/* ack after 100ms if some msgs were not acked yet */
#define CCIETH_IMMEDIATE_MSG_ACK_NR 8	/* ack after 8 msgs not acked yet */

/* seqnums are __u32 with wraparound. b is considered after a once when a<b<=a+65536.
 * everything after 65536 is likely a very obsolete duplicate.
 * b-a is unsigned, so we just check whether b-a<=65536
 */
#define CCIETH_SEQNUM_WRAPAROUND_GUARD 65536
#define ccieth_seqnum_positive(a) ((a) <= CCIETH_SEQNUM_WRAPAROUND_GUARD)
#define ccieth_seqnum_after(a, b) ccieth_seqnum_positive((b)-(a))
#define ccieth_seqnum_positive_strict(a) ((a) > 0 && (a) <= CCIETH_SEQNUM_WRAPAROUND_GUARD)
#define ccieth_seqnum_after_strict(a, b) ccieth_seqnum_positive_strict((b)-(a))

struct ccieth_connection {
	int id;			/* FIXME keep in network order too? */
	enum ccieth_connection_status status;
	struct ccieth_endpoint *ep;

	__u32 req_seqnum;
	__u32 max_send_size;
	__u64 user_conn_id;

#define CCIETH_CONN_FLAG_RELIABLE (1<<0)
#define CCIETH_CONN_FLAG_ORDERED (1<<1)
	unsigned long flags;

	/* only if CCIETH_CONN_FLAG_RELIABLE */
	/* send-side reliability */
	spinlock_t send_lock;
	__u32 send_next_seqnum;
	/* double-linked list of packets not acked yet, ordered by seqnum ... */
	struct sk_buff *send_queue_first_seqnum, *send_queue_last_seqnum;
	/* ... with a pointer to the next one to resend */
	struct sk_buff *send_queue_next_resend;
	/* resending */
	struct timer_list send_resend_timer;
	struct work_struct send_resend_work;
	/* recv-side reliability */
	spinlock_t recv_lock;
	__u32 recv_last_full_seqnum;
#define CCIETH_CONN_RECV_BITMAP_BITS 32
	__u32 recv_next_bitmap;
	/* recv-side deferred acking */
	int recv_needack_nr;
	int recv_needack_force;
	struct timer_list recv_needack_timer;
	struct work_struct recv_needack_work;
	/* only if CCIETH_CONN_FLAG_ORDERED */
	/* recv-side deferred misordered event */
	struct list_head recv_misordered_event_list;

	/* resending of connect request, accept or reject */
	int connect_needack;
	unsigned long connect_expire;	/* in jiffies, only for request because it has a timeout */
	struct timer_list connect_timer;
	struct sk_buff *connect_skb;	/* cached skb, to be cloned for resending */

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
	struct ccieth_driver_event embedded_event;

#ifdef CONFIG_CCIETH_DEBUGFS
	struct dentry *debugfs_dir;
	struct {
		__u32 send;
		__u32 send_resend;
		__u32 send_reordered_event;
		__u32 recv;
		__u32 recv_duplicate;
		__u32 recv_misorder;
		__u32 recv_tooearly;
		__u32 ack_explicit;
	} stats;
#endif
};

#ifdef CONFIG_CCIETH_DEBUGFS
#define CCIETH_STAT_INC(obj, name) (obj)->stats.name++
#define CCIETH_STAT_DEC(obj, name) (obj)->stats.name--
#else
#define CCIETH_STAT_INC(obj, name) do { /* nothing */ } while (0)
#define CCIETH_STAT_DEC(obj, name) do { /* nothing */ } while (0)
#endif

/* stored in skbuff cb private field when queued:
 * - for deferred processing (incoming connect request/accept/reject packets)
 * - for possible retransmit (RO or RU MSG sends)
 * - before delivery to userspace (RO MSG recvs)
 */
struct ccieth_skb_cb {
	union {
		struct {
			__u8 type;
		} connect;
		struct {
			unsigned long resend_jiffies;
			__u32 seqnum;
			enum ccieth_msg_completion_type {
				CCIETH_MSG_COMPLETION_EVENT,
				CCIETH_MSG_COMPLETION_BLOCKING,
				CCIETH_MSG_COMPLETION_SILENT,
			} completion_type;
			union {
				struct ccieth_driver_event *event; /* CCIETH_MSG_COMPLETION_EVENT */
				struct ccieth_rcu_completion __rcu *completion; /* CCIETH_MSG_COMPLETION_BLOCKING */
			};

			/* RO sends that complete out of order are removed from the resend list
			 * and queued after the last-previous-seqnum non-completed send.
			 * When a RO send completes in order, it is notified before all sends
			 * queued after it are notified as well.
			 * For non-completed sends, this field is the head of queue.
			 * For misordered completed RO sends, this field is the list element.
			 */
			struct list_head reordered_completed_send_list;
		} reliable_send;
	};
};
#define CCIETH_SKB_CB(__skb) ((struct ccieth_skb_cb *)&((__skb)->cb[0]))

extern struct idr ccieth_ep_idr;	/* accessed under RCU read lock */
#ifdef CONFIG_CCIETH_DEBUGFS
extern struct dentry *ccieth_debugfs_root;
#endif

extern int ccieth_destroy_connection_idrforeach_cb(int id, void *p, void *data);
extern int ccieth_connect_request(struct ccieth_endpoint *ep, struct ccieth_ioctl_connect_request *arg);
extern int ccieth_connect_accept(struct ccieth_endpoint *ep, struct ccieth_ioctl_connect_accept *arg);
extern int ccieth_connect_reject(struct ccieth_endpoint *ep, struct ccieth_ioctl_connect_reject *arg);
extern void ccieth_deferred_connect_recv_workfunc(struct work_struct *work);
extern int ccieth_defer_connect_recv(struct net_device *ifp, __u8 type, struct sk_buff *skb);

extern int ccieth_msg_resend(struct ccieth_connection *conn);

extern int ccieth_msg(struct ccieth_endpoint *ep, struct ccieth_ioctl_msg *arg);
extern int ccieth_msg_ack(struct ccieth_connection *conn);

extern void ccieth_abort_reliable_send_scb(struct ccieth_connection *conn, struct ccieth_skb_cb *scb, int error);

extern int ccieth_recv(struct sk_buff *skb, struct net_device *ifp, struct packet_type *pt, struct net_device *orig_dev);

static inline struct ccieth_driver_event *
ccieth_get_free_event(struct ccieth_endpoint *ep)
{
	struct ccieth_driver_event *event;
	spin_lock_bh(&ep->free_event_list_lock);
	if (unlikely(!ep->free_event_list_length)) {
		spin_unlock_bh(&ep->free_event_list_lock);
		return NULL;
	}
	event = list_first_entry(&ep->free_event_list, struct ccieth_driver_event, list);
	list_del(&event->list);
	ep->free_event_list_length--;
	spin_unlock_bh(&ep->free_event_list_lock);
	return event;
}

static inline struct ccieth_driver_event *
ccieth_get_free_event_maydefer(struct ccieth_endpoint *ep, int willdefer)
{
	struct ccieth_driver_event *event;
	spin_lock_bh(&ep->free_event_list_lock);
	if (unlikely(!ep->free_event_list_length)
	    /* if the event will be deferred instead of delivered now,
	     * don't consume the last quarter of the list */
	    || (willdefer && unlikely(ep->free_event_list_length <= CCIETH_EVENT_SLOT_NR/4))) {
		spin_unlock_bh(&ep->free_event_list_lock);
		return NULL;
	}
	event = list_first_entry(&ep->free_event_list, struct ccieth_driver_event, list);
	list_del(&event->list);
	ep->free_event_list_length--;
	spin_unlock_bh(&ep->free_event_list_lock);
	return event;
}

static inline void
ccieth_putback_free_event(struct ccieth_endpoint *ep,
			  struct ccieth_driver_event *event)
{
	spin_lock_bh(&ep->free_event_list_lock);
	ep->free_event_list_length++;
	list_add_tail(&event->list, &ep->free_event_list);
	spin_unlock_bh(&ep->free_event_list_lock);
}

static inline void
ccieth_queue_busy_event(struct ccieth_endpoint *ep,
			struct ccieth_driver_event *event)
{
	spin_lock_bh(&ep->event_list_lock);
	list_add_tail(&event->list, &ep->event_list);
	wake_up_interruptible(&ep->event_wq);
	spin_unlock_bh(&ep->event_list_lock);
}

static inline unsigned
ccieth_pkt_ack_status_to_errno(__u8 status)
{
	switch (status) {
	case CCIETH_PKT_ACK_SUCCESS: return 0;
	case CCIETH_PKT_ACK_INVALID: return EINVAL; /* only occurs if connect data is too large for remote peer, user-space should return EINVAL earlier */
	case CCIETH_PKT_ACK_NO_ENDPOINT: return EINVAL; /* FIXME: ECONNREFUSED actually looks better but already used for reject() */
	case CCIETH_PKT_ACK_NO_CONNECTION: return EINVAL; /* FIXME: ECONNRESET? */
	default: return EIO;
	}
}


#ifdef CONFIG_CCIETH_DEBUG
#define dprintk printk
#else
#define dprintk(args...) do { /* nothing */ } while (0)
#endif

#if (defined CONFIG_CCIETH_FAULT) && (CONFIG_CCIETH_FAULT > 0)
#include <linux/random.h>
#define dev_queue_xmit(skb) do {				\
  __u16 val;							\
  get_random_bytes(&val, sizeof(val));				\
  if (100 * (unsigned long) val < CONFIG_CCIETH_FAULT * 65536)	\
    kfree_skb(skb);						\
  else								\
    dev_queue_xmit(skb);					\
} while (0)
#if 0
#endif
#endif

#endif /* CCIETH_COMMON_H */
