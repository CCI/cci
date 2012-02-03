/*
 * CCI over Ethernet
 *
 * Copyright © 2011-2012 Inria.  All rights reserved.
 * $COPYRIGHT$
 */

#include <linux/netdevice.h>
#include <linux/rcupdate.h>

#include <ccieth_io.h>
#include <ccieth_common.h>
#include <ccieth_wire.h>

static int
ccieth_connect_ack_from_endpoint(struct ccieth_endpoint *ep, __u32 src_conn_id,
				 __u8 dst_addr[6],  __u32 dst_ep_id, __u32 dst_conn_id,
				 __u32 req_seqnum,
				 __u8 ack_status);

/*
 * RO specific callbacks
 */

static void
ccieth_conn_ro_set_next_send_seqnum(struct ccieth_connection *conn, struct ccieth_pkt_header_msg *hdr)
{
	hdr->msg_seqnum = htonl(atomic_inc_return(&conn->ro.next_send_seqnum));
}

static void
ccieth_conn_ro_free(struct ccieth_connection *conn)
{
}

static void
ccieth_conn_ro_init(struct ccieth_connection *conn)
{
	conn->set_next_send_seqnum = ccieth_conn_ro_set_next_send_seqnum;
	conn->free = ccieth_conn_ro_free;
	atomic_set(&conn->ro.next_send_seqnum, jiffies);
}

/*
 * RU specific callbacks
 */

static void
ccieth_conn_ru_set_next_send_seqnum(struct ccieth_connection *conn, struct ccieth_pkt_header_msg *hdr)
{
	hdr->msg_seqnum = htonl(atomic_inc_return(&conn->ru.next_send_seqnum));
}

static void
ccieth_conn_ru_free(struct ccieth_connection *conn)
{
}

static void
ccieth_conn_ru_init(struct ccieth_connection *conn)
{
	conn->set_next_send_seqnum = ccieth_conn_ru_set_next_send_seqnum;
	conn->free = ccieth_conn_ru_free;
	atomic_set(&conn->ru.next_send_seqnum, jiffies);
}

/*
 * UU specific callbacks
 */

static void
ccieth_conn_uu_recv_deferred_msgs(struct ccieth_connection *conn)
{
	struct sk_buff *skb;
	BUG_ON(conn->attribute != CCIETH_CONNECT_ATTR_UU);
	while ((skb = skb_dequeue(&conn->uu.deferred_msg_recv_queue)) != NULL) {
		struct ccieth_pkt_header_msg _hdr, *hdr;
		dprintk("processing deferred msg\n");
		hdr = skb_header_pointer(skb, 0, sizeof(_hdr), &_hdr);
		BUG_ON(!hdr); /* would have failed in ccieth_recv_msg() */
		ccieth__recv_msg(conn->ep, conn, hdr, skb);
	}
}

void
ccieth_conn_uu_defer_recv_msg(struct ccieth_connection *conn,
			      struct sk_buff *skb)
{
	BUG_ON(conn->attribute != CCIETH_CONNECT_ATTR_UU);
	dprintk("deferring UU msg until accept\n");
	skb_queue_tail(&conn->uu.deferred_msg_recv_queue, skb);
	if (conn->status == CCIETH_CONNECTION_READY)
		/* accepted in the meantime, make sure it didn't miss our packet */
		ccieth_conn_uu_recv_deferred_msgs(conn);
}

static void
ccieth_conn_uu_set_next_send_seqnum(struct ccieth_connection *conn, struct ccieth_pkt_header_msg *hdr)
{
	hdr->msg_seqnum = htonl(-1); /* debug */
}

static void
ccieth_conn_uu_free(struct ccieth_connection *conn)
{
	skb_queue_purge(&conn->uu.deferred_msg_recv_queue);
}

static void
ccieth_conn_uu_init(struct ccieth_connection *conn)
{
	conn->set_next_send_seqnum = ccieth_conn_uu_set_next_send_seqnum;
	conn->free = ccieth_conn_uu_free;
	skb_queue_head_init(&conn->uu.deferred_msg_recv_queue);
}

static void
ccieth_conn_init(struct ccieth_connection *conn, int attribute)
{
	conn->attribute = attribute;

	switch (attribute) {
	case CCIETH_CONNECT_ATTR_RO:
		ccieth_conn_ro_init(conn);
		break;
	case CCIETH_CONNECT_ATTR_RU:
		ccieth_conn_ru_init(conn);
		break;
	case CCIETH_CONNECT_ATTR_UU:
		ccieth_conn_uu_init(conn);
		break;
	default:
		BUG();
	}
}

/*
 * Connection destruction management
 */

static void
ccieth_destroy_connection_rcu(struct rcu_head *rcu_head)
{
	struct ccieth_connection *conn = container_of(rcu_head, struct ccieth_connection, destroy_rcu_head);
	dprintk("destroying connection %p in rcu call\n", conn);
	conn->free(conn);
	kfree_skb(conn->skb);
	kfree(conn);
}

static void
ccieth_connection_event_destructor(struct ccieth_endpoint *ep,
				   struct ccieth_endpoint_event *event)
{
	struct ccieth_connection *conn = container_of(event, struct ccieth_connection, embedded_event);
	/* the event was enqueued from ccieth_connect_timer_hdlr, while rcu readers may exist */
	/* timer isn't running anymore, no need to del_timer_sync() */
	call_rcu(&conn->destroy_rcu_head, ccieth_destroy_connection_rcu);
}

int
ccieth_destroy_connection_idrforeach_cb(int id, void *p, void *data)
{
	struct ccieth_connection *conn = p;
	enum ccieth_connection_status status = conn->status;
	int *destroyed_conn = data;

	if (cmpxchg(&conn->status, status, CCIETH_CONNECTION_CLOSING) != status)
		/* somebody else is closing it */
		return 0;

	/* we set to CLOSING, we own the connection now, nobody else may destroy it */
	del_timer_sync(&conn->timer);
	/* the caller will destroy the entire idr, no need to remove us from there */
	call_rcu(&conn->destroy_rcu_head, ccieth_destroy_connection_rcu);

	(*destroyed_conn)++;
	return 0;
}

/*
 * Connect packet timers
 */

static
void ccieth_connect_request_timer_hdlr(unsigned long data)
{
	struct ccieth_connection *conn = (void*) data;
	struct ccieth_endpoint *ep = conn->ep;
	enum ccieth_connection_status status = conn->status;
	struct sk_buff *skb;
	unsigned long now = jiffies;

	if (status != CCIETH_CONNECTION_REQUESTED)
		return;

	if (now < conn->expire && conn->need_ack) {
		/* resend request */
		unsigned long next;
		next = now + CCIETH_CONNECT_RESEND_DELAY;
		if (next > conn->expire)
			next = conn->expire;
		mod_timer(&conn->timer, next);

		skb = skb_clone(conn->skb, GFP_ATOMIC);
		if (skb) {
			struct net_device *ifp;
			rcu_read_lock();
			/* is the interface still available? */
			ifp = rcu_dereference(ep->ifp);
			if (ifp) {
				skb->dev = ifp;
				dev_queue_xmit(skb);
			} else {
				kfree_skb(skb);
			}
			rcu_read_unlock();
		}
		return;

	} else if (now < conn->expire) {
		/* only keep the expire timer, no need to resend anymore */
		mod_timer(&conn->timer, conn->expire);
		return;
	}

	/* connect timeout */

	if (cmpxchg(&conn->status, status, CCIETH_CONNECTION_CLOSING) != status)
		/* somebody else is closing it */
		return;

	/* we set to CLOSING, we own the connection now, nobody else may destroy it */
	spin_lock(&ep->connection_idr_lock);
	idr_remove(&ep->connection_idr, conn->id);
	spin_unlock(&ep->connection_idr_lock);

	dprintk("delivering connection %p timeout\n", conn);
	conn->embedded_event.event.type = CCIETH_IOCTL_EVENT_CONNECT_TIMEDOUT;
	conn->embedded_event.event.connect_timedout.user_conn_id = conn->user_conn_id;
	/* destroy the connection after the event */
	spin_lock_bh(&ep->event_list_lock);
	list_add_tail(&conn->embedded_event.list, &ep->event_list);
	spin_unlock_bh(&ep->event_list_lock);
}

static
void ccieth_connect_reply_timer_hdlr(unsigned long data)
{
	struct ccieth_connection *conn = (void*) data;
	struct ccieth_endpoint *ep = conn->ep;
	struct sk_buff *skb;

	if (conn->status != CCIETH_CONNECTION_READY && conn->status != CCIETH_CONNECTION_REJECTED)
		return;

	if (!conn->need_ack)
		return;

	/* resend request */
	mod_timer(&conn->timer, jiffies + CCIETH_CONNECT_RESEND_DELAY);

	skb = skb_clone(conn->skb, GFP_ATOMIC);
	if (skb) {
		struct net_device *ifp;
		rcu_read_lock();
		/* is the interface still available? */
		ifp = rcu_dereference(ep->ifp);
		if (ifp) {
			skb->dev = ifp;
			dev_queue_xmit(skb);
		} else {
			kfree_skb(skb);
		}
		rcu_read_unlock();
	}
}

/*
 * Connect request, accept, reject and ack
 */

int
ccieth_connect_request(struct ccieth_endpoint *ep, struct ccieth_ioctl_connect_request *arg)
{
	struct sk_buff *skb, *skb2;
	struct net_device *ifp;
	struct ccieth_pkt_header_connect_request *hdr;
	struct ccieth_connection *conn;
	unsigned long now, next;
	__u32 req_seqnum = atomic_inc_return(&ep->connection_req_seqnum);
	size_t skblen;
	int id;
	int err;

	err = -EINVAL;
	if (arg->data_len > ep->max_send_size)
		goto out;

	if (arg->attribute != CCIETH_CONNECT_ATTR_RO
	    && arg->attribute != CCIETH_CONNECT_ATTR_RU
	    && arg->attribute != CCIETH_CONNECT_ATTR_UU)
		goto out;

	/* get a connection */
	err = -ENOMEM;
	conn = kmalloc(sizeof(*conn), GFP_KERNEL);
	if (!conn)
		goto out;
	conn->embedded_event.event.data_length = 0;
	conn->embedded_event.destructor = ccieth_connection_event_destructor;
	conn->skb = NULL;
	ccieth_conn_init(conn, arg->attribute);

	/* initialize the timer to make destroy easier */
	setup_timer(&conn->timer, ccieth_connect_request_timer_hdlr, (unsigned long) conn);

	/* get a connection id (only reserve it) */
retry:
	spin_lock(&ep->connection_idr_lock);
	err = idr_get_new(&ep->connection_idr, NULL, &id);
	spin_unlock(&ep->connection_idr_lock);
	if (err < 0) {
		if (err == -EAGAIN) {
			if (idr_pre_get(&ep->connection_idr, GFP_KERNEL) > 0)
				goto retry;
			err = -ENOMEM;
		}
		goto out_with_conn;
	}

	/* allocate and initialize the skb */
	skblen = sizeof(*hdr) + arg->data_len;
	if (skblen < ETH_ZLEN)
		skblen = ETH_ZLEN;
	skb = alloc_skb(skblen, GFP_KERNEL);
	if (!skb)
		goto out_with_conn_id;
	skb_reset_mac_header(skb);
	skb_reset_network_header(skb);
	skb->protocol = __constant_htons(ETH_P_CCI);
	skb_put(skb, skblen);
	skb2 = skb_clone(skb, GFP_KERNEL);
	if (!skb2)
		goto out_with_skb;
	/* setup as much as possible of the skb
	 * so that things don't fail later once the connection is hashed
	 */
	hdr = (struct ccieth_pkt_header_connect_request *) skb_mac_header(skb);
	memcpy(&hdr->eth.h_dest, &arg->dest_addr, 6);
	memcpy(&hdr->eth.h_source, ep->addr, 6);
	hdr->eth.h_proto = __constant_cpu_to_be16(ETH_P_CCI);
	hdr->type = CCIETH_PKT_CONNECT_REQUEST;
	hdr->dst_ep_id = htonl(arg->dest_eid);
	hdr->attribute = arg->attribute;
	hdr->src_ep_id = htonl(ep->id);
	hdr->max_send_size = htonl(ep->max_send_size);
	hdr->req_seqnum = htonl(req_seqnum);
	hdr->data_len = htonl(arg->data_len);
	err = copy_from_user(&hdr->data, (const void __user *)(uintptr_t) arg->data_ptr, arg->data_len);
	if (err) {
		err = -EFAULT;
		goto out_with_skb2;
	}

	/* initialize the connection */
	conn->ep = ep;
	conn->req_seqnum = req_seqnum;
	conn->status = CCIETH_CONNECTION_REQUESTED;
	memcpy(&conn->dest_addr, &arg->dest_addr, 6);
	conn->dest_eid = arg->dest_eid;
	conn->user_conn_id = arg->user_conn_id;
	conn->id = id;
	idr_replace(&ep->connection_idr, conn, id);
	hdr->src_conn_id = htonl(id);

	conn->need_ack = 1;
	/* keep the current skb cached in the connection,
	 * and try to send the clone. if we can't, we'll resend later.
	 */
	conn->skb = skb;
	rcu_read_lock();
	/* is the interface still available? */
	ifp = rcu_dereference(ep->ifp);
	if (!ifp) {
		err = -ENODEV;
		goto out_with_rculock;
	}
	skb2->dev = ifp;
	dev_queue_xmit(skb2);
	rcu_read_unlock();

	/* setup resend or timeout timer */
	now = jiffies;
	if (arg->timeout_sec != -1ULL || arg->timeout_usec != -1) {
		__u64 msecs = arg->timeout_sec * 1000 + arg->timeout_usec / 1000;
		conn->expire = now + msecs_to_jiffies(msecs);
	} else {
		conn->expire = -1; /* that's MAX_LONG now */
	}
	next = now + CCIETH_CONNECT_RESEND_DELAY;
	if (next > conn->expire)
		next = conn->expire;
	mod_timer(&conn->timer, next);

	arg->conn_id = conn->id;
	return 0;

out_with_rculock:
	rcu_read_unlock();
out_with_skb2:
	kfree_skb(skb2);
out_with_skb:
	kfree_skb(skb);
out_with_conn_id:
	spin_lock(&ep->connection_idr_lock);
	idr_remove(&ep->connection_idr, id);
	spin_unlock(&ep->connection_idr_lock);
out_with_conn:
	kfree(conn);
out:
	return err;
}

static int ccieth_recv_connect_idrforeach_cb(int id, void *p, void *data)
{
	struct ccieth_connection *conn = p, *new = data;
	/* return -EBUSY in case of duplicate incoming connect.
	 * it may even already be accepted or rejcted.
	 */
	if (conn->status != CCIETH_CONNECTION_REQUESTED /* so that dest_id is valid */
	    && !memcmp(&conn->dest_addr, &new->dest_addr, 6)
	    && conn->dest_eid == new->dest_eid
	    && conn->dest_id == new->dest_id
	    && conn->req_seqnum == new->req_seqnum)
		return -EBUSY;
	return 0;
}

static int
ccieth__recv_connect_request(struct ccieth_endpoint *ep,
			     struct sk_buff *skb,
			     struct ccieth_pkt_header_connect_request *hdr)
{
	struct ccieth_endpoint_event *event;
	struct ccieth_connection *conn;
	__u32 src_ep_id;
	__u32 src_conn_id;
	__u32 data_len;
	__u32 src_max_send_size;
	__u32 req_seqnum;
	struct sk_buff *replyskb;
	size_t replyskblen;
	int need_ack = 0;
	enum ccieth_pkt_ack_status ack_status = CCIETH_PKT_ACK_SUCCESS;
	int id;
	int err;

	dprintk("processing queued connect request skb %p\n", skb);

	err = -EINVAL;
	if (hdr->attribute != CCIETH_CONNECT_ATTR_RO
	    && hdr->attribute != CCIETH_CONNECT_ATTR_RU
	    && hdr->attribute != CCIETH_CONNECT_ATTR_UU)
		/* remote doesn't look OK, ignore */
		goto out;

	if (atomic_read(&ep->connection_received) >= CCIETH_MAX_CONNECTION_RECEIVED)
		/* don't let the network DoS us if the application
		 * doesn't handle connection request quickly enough.
		 * ignore, it'll be resent later. */
		goto out;

	src_ep_id = ntohl(hdr->src_ep_id);
	src_conn_id = ntohl(hdr->src_conn_id);
	data_len = ntohl(hdr->data_len);
	src_max_send_size = ntohl(hdr->max_send_size);
	req_seqnum = ntohl(hdr->req_seqnum);

	dprintk("got conn request from eid %d conn id %d seqnum %d\n",
		src_ep_id, src_conn_id, req_seqnum);

	/* check msg length */
	if (data_len > ep->max_send_size
	    || skb->len < sizeof(*hdr) + data_len) {
		need_ack = 1;
		ack_status = CCIETH_PKT_ACK_INVALID;
		goto out;
	}

	/* the request looks ok.
	 * if we fail to honor it below, just ignore it and let it be resent later.
	 */

	/* get an event */
	err = -ENOMEM;
	spin_lock_bh(&ep->free_event_list_lock);
	if (list_empty(&ep->free_event_list)) {
		spin_unlock_bh(&ep->free_event_list_lock);
		dprintk("ccieth: no event slot for connect request\n");
		goto out;
	}
	event = list_first_entry(&ep->free_event_list, struct ccieth_endpoint_event, list);
	list_del(&event->list);
	spin_unlock_bh(&ep->free_event_list_lock);

	/* get a connection */
	conn = kmalloc(sizeof(*conn), GFP_KERNEL);
	if (!conn)
		goto out_with_event;
	conn->embedded_event.event.data_length = 0;
	conn->embedded_event.destructor = ccieth_connection_event_destructor;
	conn->need_ack = 0;
	ccieth_conn_init(conn, hdr->attribute);

	/* initialize the timer to make destroy easier */
	setup_timer(&conn->timer, ccieth_connect_reply_timer_hdlr, (unsigned long) conn);

	/* allocate and initialize the connect reply skb now so that we don't fail with ENOMEM later */
	replyskblen = max(sizeof(struct ccieth_pkt_header_connect_accept),
			  sizeof(struct ccieth_pkt_header_connect_reject));
	if (replyskblen < ETH_ZLEN)
		replyskblen = ETH_ZLEN;
	replyskb = alloc_skb(replyskblen, GFP_KERNEL);
	if (!replyskb)
		goto out_with_conn;
	skb_reset_mac_header(replyskb);
	skb_reset_network_header(replyskb);
	replyskb->protocol = __constant_htons(ETH_P_CCI);
	skb_put(replyskb, replyskblen);
	conn->skb = replyskb;

	/* setup the connection so that we can check for duplicates before inserting */
	conn->ep = ep;
	conn->status = CCIETH_CONNECTION_RECEIVED;
	memcpy(&conn->dest_addr, &hdr->eth.h_source, 6);
	conn->dest_eid = src_ep_id;
	conn->dest_id = src_conn_id;
	conn->req_seqnum = req_seqnum;

	/* get a connection id (only reserve it for now) */
retry:
	spin_lock(&ep->connection_idr_lock);
	/* check for duplicates */
	err = idr_for_each(&ep->connection_idr, ccieth_recv_connect_idrforeach_cb, conn);
	if (err != -EBUSY)
		/* if no duplicates, try to add new connection */
		err = idr_get_new(&ep->connection_idr, NULL, &id);
	spin_unlock(&ep->connection_idr_lock);
	if (err < 0) {
		if (err == -EAGAIN) {
			if (idr_pre_get(&ep->connection_idr, GFP_KERNEL) > 0)
				goto retry;
			err = -ENOMEM;
		} else if (err == -EBUSY) {
			/* already received, a previous ack might have been lost, ack again */
			need_ack = 1;
		}
		goto out_with_replyskb;
	}

	/* setup the event */
	event->event.type = CCIETH_IOCTL_EVENT_CONNECT_REQUEST;
	event->event.data_length = data_len;
	event->event.connect_request.attribute = hdr->attribute;
	event->event.connect_request.max_send_size = src_max_send_size < ep->max_send_size ? src_max_send_size : ep->max_send_size;
	err = skb_copy_bits(skb, sizeof(*hdr), event+1, data_len);
	BUG_ON(err < 0);

	/* things cannot fail anymore now, insert the connection for real */
	conn->id = id;
	idr_replace(&ep->connection_idr, conn, id);
	atomic_inc(&ep->connection_received);

	/* finalize and notify the event */
	event->event.connect_request.conn_id = id;
	spin_lock_bh(&ep->event_list_lock);
	list_add_tail(&event->list, &ep->event_list);
	spin_unlock_bh(&ep->event_list_lock);

	ccieth_connect_ack_from_endpoint(ep, -1,
					 (__u8*)&hdr->eth.h_source, src_ep_id, src_conn_id, req_seqnum,
					 ack_status);
	dev_kfree_skb(skb);
	return 0;

out_with_replyskb:
	kfree_skb(replyskb);
out_with_conn:
	kfree(conn);
out_with_event:
	spin_lock_bh(&ep->free_event_list_lock);
	list_add_tail(&event->list, &ep->free_event_list);
	spin_unlock_bh(&ep->free_event_list_lock);
out:
	if (need_ack)
		ccieth_connect_ack_from_endpoint(ep, -1,
						 (__u8*)&hdr->eth.h_source, src_ep_id, src_conn_id, req_seqnum,
						 ack_status);
	dev_kfree_skb(skb);
	return err;
}

int
ccieth_connect_accept(struct ccieth_endpoint *ep, struct ccieth_ioctl_connect_accept *arg)
{
	struct sk_buff *skb;
	struct net_device *ifp;
	struct ccieth_pkt_header_connect_accept *hdr;
	struct ccieth_connection *conn;
	int err;

	rcu_read_lock();

	/* update the connection */
	err = -EINVAL;
	conn = idr_find(&ep->connection_idr, arg->conn_id);
	if (!conn)
		goto out_with_rculock;

	if (cmpxchg(&conn->status, CCIETH_CONNECTION_RECEIVED, CCIETH_CONNECTION_READY)
	    != CCIETH_CONNECTION_RECEIVED)
		goto out_with_rculock;
	atomic_dec(&ep->connection_received);
	conn->max_send_size = arg->max_send_size;
	conn->user_conn_id = arg->user_conn_id;

	/* fill headers */
	skb = conn->skb;
	hdr = (struct ccieth_pkt_header_connect_accept *) skb_mac_header(skb);
	memcpy(&hdr->eth.h_dest, &conn->dest_addr, 6);
	memcpy(&hdr->eth.h_source, ep->addr, 6);
	hdr->eth.h_proto = __constant_cpu_to_be16(ETH_P_CCI);
	hdr->type = CCIETH_PKT_CONNECT_ACCEPT;
	hdr->dst_ep_id = htonl(conn->dest_eid);
	hdr->dst_conn_id = htonl(conn->dest_id);
	hdr->src_ep_id = htonl(ep->id);
	hdr->src_conn_id = htonl(conn->id);
	hdr->max_send_size = htonl(conn->max_send_size);
	hdr->req_seqnum = htonl(conn->req_seqnum);

	/* setup resend or timeout timer */
	conn->need_ack = 1;
	mod_timer(&conn->timer, jiffies + CCIETH_CONNECT_RESEND_DELAY);

	rcu_read_unlock(); /* end of rcu read access to ep conn idr only */

	/* try to send a clone. if we can't, we'll resend later. */
	skb = skb_clone(skb, GFP_KERNEL);
	if (skb) {
		rcu_read_lock(); /* start of another rcu read access for ep->ifp only */
		/* is the interface still available? */
		ifp = rcu_dereference(ep->ifp);
		if (!ifp) {
			err = -ENODEV;
			goto out_with_skb;
		}
		skb->dev = ifp;
		dev_queue_xmit(skb);
		rcu_read_unlock();
	}

	return 0;

out_with_skb:
	kfree_skb(skb);
out_with_rculock:
	rcu_read_unlock();
	return err;
}

static int
ccieth__recv_connect_accept(struct ccieth_endpoint *ep,
			    struct sk_buff *skb,
			    struct ccieth_pkt_header_connect_accept *hdr)
{
	struct ccieth_endpoint_event *event;
	struct ccieth_connection *conn;
	__u32 src_conn_id;
	__u32 src_ep_id;
	__u32 dst_conn_id;
	__u32 dst_ep_id;
	__u32 max_send_size;
	__u32 req_seqnum;
	int need_ack = 0;
	enum ccieth_pkt_ack_status ack_status = CCIETH_PKT_ACK_SUCCESS;
	int err;

	dprintk("processing queued connect accept skb %p\n", skb);

	src_conn_id = ntohl(hdr->src_conn_id);
	src_ep_id = ntohl(hdr->src_ep_id);
	dst_conn_id = ntohl(hdr->dst_conn_id);
	dst_ep_id = ntohl(hdr->dst_ep_id);
	max_send_size = ntohl(hdr->max_send_size);
	req_seqnum = ntohl(hdr->req_seqnum);

	dprintk("got conn accept from eid %d conn id %d seqnum %d to %d %d\n",
		src_ep_id, src_conn_id, req_seqnum, dst_ep_id, dst_conn_id);

	rcu_read_lock();

	/* get an event */
	err = -ENOMEM;
	spin_lock_bh(&ep->free_event_list_lock);
	if (list_empty(&ep->free_event_list)) {
		spin_unlock_bh(&ep->free_event_list_lock);
		dprintk("ccieth: no event slot for connect accepted\n");
		goto out_with_rculock;
	}
	event = list_first_entry(&ep->free_event_list, struct ccieth_endpoint_event, list);
	list_del(&event->list);
	spin_unlock_bh(&ep->free_event_list_lock);

	/* setup the event */
	event->event.type = CCIETH_IOCTL_EVENT_CONNECT_ACCEPTED;
	event->event.data_length = 0;
	event->event.connect_accepted.conn_id = dst_conn_id;

	/* find the connection and update it */
	err = -EINVAL;
	conn = idr_find(&ep->connection_idr, dst_conn_id);
	if (!conn || conn->req_seqnum != req_seqnum) {
		need_ack = 1;
		ack_status = CCIETH_PKT_ACK_NO_CONNECTION;
		goto out_with_event;
	}

	err = 0;
	if (cmpxchg(&conn->status, CCIETH_CONNECTION_REQUESTED, CCIETH_CONNECTION_READY)
	    != CCIETH_CONNECTION_REQUESTED) {
		/* already received, a previous ack might have been lost, ack again */
		need_ack = 1;
		goto out_with_conn;
	}
	conn->need_ack = 0;

	/* setup connection */
	conn->dest_id = src_conn_id;
	conn->max_send_size = max_send_size;

	/* finalize and notify the event */
	event->event.connect_accepted.attribute = conn->attribute;
	event->event.connect_accepted.max_send_size = max_send_size;
	event->event.connect_accepted.user_conn_id = conn->user_conn_id;

	spin_lock_bh(&ep->event_list_lock);
	list_add_tail(&event->list, &ep->event_list);
	spin_unlock_bh(&ep->event_list_lock);

	/* handle deferred msgs */
	if (conn->attribute == CCIETH_CONNECT_ATTR_UU)
		ccieth_conn_uu_recv_deferred_msgs(conn);

	rcu_read_unlock();

	ccieth_connect_ack_from_endpoint(ep, dst_conn_id,
					 (__u8*)&hdr->eth.h_source, src_ep_id, src_conn_id, req_seqnum,
					 ack_status);
	dev_kfree_skb(skb);
	return 0;

out_with_conn:
	/* nothing */
out_with_event:
	spin_lock_bh(&ep->free_event_list_lock);
	list_add_tail(&event->list, &ep->free_event_list);
	spin_unlock_bh(&ep->free_event_list_lock);
out_with_rculock:
	rcu_read_unlock();
	if (need_ack)
		ccieth_connect_ack_from_endpoint(ep, dst_conn_id,
						 (__u8*)&hdr->eth.h_source, src_ep_id, src_conn_id, req_seqnum,
						 ack_status);
	dev_kfree_skb(skb);
	return err;
}

int
ccieth_connect_reject(struct ccieth_endpoint *ep, struct ccieth_ioctl_connect_reject *arg)
{
	struct sk_buff *skb;
	struct net_device *ifp;
	struct ccieth_pkt_header_connect_reject *hdr;
	struct ccieth_connection *conn;
	int err;

	rcu_read_lock();

	/* update the connection */
	err = -EINVAL;
	conn = idr_find(&ep->connection_idr, arg->conn_id);
	if (!conn)
		goto out_with_rculock;

	if (cmpxchg(&conn->status, CCIETH_CONNECTION_RECEIVED, CCIETH_CONNECTION_REJECTED)
	    != CCIETH_CONNECTION_RECEIVED)
		goto out_with_rculock;
	atomic_dec(&ep->connection_received);

	/* fill headers */
	skb = conn->skb;
	hdr = (struct ccieth_pkt_header_connect_reject *) skb_mac_header(skb);
	memcpy(&hdr->eth.h_dest, &conn->dest_addr, 6);
	memcpy(&hdr->eth.h_source, ep->addr, 6);
	hdr->eth.h_proto = __constant_cpu_to_be16(ETH_P_CCI);
	hdr->type = CCIETH_PKT_CONNECT_REJECT;
	hdr->dst_ep_id = htonl(conn->dest_eid);
	hdr->dst_conn_id = htonl(conn->dest_id);
	hdr->src_ep_id = htonl(ep->id);
	hdr->src_conn_id = htonl(conn->id);
	hdr->req_seqnum = htonl(conn->req_seqnum);

	/* setup resend or timeout timer */
	conn->need_ack = 1;
	mod_timer(&conn->timer, jiffies + CCIETH_CONNECT_RESEND_DELAY);

	rcu_read_unlock(); /* end of rcu read access to ep conn idr only */

	/* try to send a clone. if we can't, we'll resend later. */
	skb = skb_clone(skb, GFP_KERNEL);
	if (skb) {
		rcu_read_lock(); /* start of another rcu read access for ep->ifp only */
		/* is the interface still available? */
		ifp = rcu_dereference(ep->ifp);
		if (!ifp) {
			err = -ENODEV;
			goto out_with_skb;
		}
		skb->dev = ifp;
		dev_queue_xmit(skb);
		rcu_read_unlock();
	}

	return 0;

out_with_skb:
	kfree_skb(skb);
out_with_rculock:
	rcu_read_unlock();
	return err;
}

static int
ccieth__recv_connect_reject(struct ccieth_endpoint *ep,
			    struct sk_buff *skb,
			    struct ccieth_pkt_header_connect_reject *hdr)
{
	struct ccieth_connection *conn;
	__u32 src_conn_id;
	__u32 src_ep_id;
	__u32 dst_conn_id;
	__u32 dst_ep_id;
	__u32 req_seqnum;
	int need_ack = 0;
	enum ccieth_pkt_ack_status ack_status = CCIETH_PKT_ACK_SUCCESS;
	int err;

	dprintk("processing queued connect reject skb %p\n", skb);

	src_conn_id = ntohl(hdr->src_conn_id);
	src_ep_id = ntohl(hdr->src_ep_id);
	dst_conn_id = ntohl(hdr->dst_conn_id);
	dst_ep_id = ntohl(hdr->dst_ep_id);
	req_seqnum = ntohl(hdr->req_seqnum);

	dprintk("got conn reject from eid %d conn id %d seqnum %d to %d %d\n",
		src_ep_id, src_conn_id, req_seqnum, dst_ep_id, dst_conn_id);

	rcu_read_lock();

	/* find the connection and remove it */
	err = -EINVAL;
	conn = idr_find(&ep->connection_idr, dst_conn_id);
	if (!conn || conn->req_seqnum != req_seqnum) {
		need_ack = 1;
		ack_status = CCIETH_PKT_ACK_NO_CONNECTION;
		goto out_with_rculock;
	}
	err = 0;
	if (cmpxchg(&conn->status, CCIETH_CONNECTION_REQUESTED, CCIETH_CONNECTION_CLOSING)
	    != CCIETH_CONNECTION_REQUESTED) {
		/* already received, a previous ack might have been lost, ack again */
		need_ack = 1;
		goto out_with_rculock;
	}
	conn->need_ack = 0;

	rcu_read_unlock();

	/* we set to CLOSING, we own the connection now, nobody else may destroy it */
	del_timer_sync(&conn->timer);
	spin_lock(&ep->connection_idr_lock);
	idr_remove(&ep->connection_idr, dst_conn_id);
	spin_unlock(&ep->connection_idr_lock);

	/* setup the event */
	conn->embedded_event.event.type = CCIETH_IOCTL_EVENT_CONNECT_REJECTED;
	conn->embedded_event.event.connect_rejected.user_conn_id = conn->user_conn_id;
	/* destroy the connection after the event */
	spin_lock_bh(&ep->event_list_lock);
	list_add_tail(&conn->embedded_event.list, &ep->event_list);
	spin_unlock_bh(&ep->event_list_lock);

	ccieth_connect_ack_from_endpoint(ep, dst_conn_id,
					 (__u8*)&hdr->eth.h_source, src_ep_id, src_conn_id, req_seqnum,
					 ack_status);
	dev_kfree_skb(skb);
	return 0;

out_with_rculock:
	rcu_read_unlock();
	if (need_ack)
		ccieth_connect_ack_from_endpoint(ep, dst_conn_id,
						 (__u8*)&hdr->eth.h_source, src_ep_id, src_conn_id, req_seqnum,
						 ack_status);
	dev_kfree_skb(skb);
	return err;
}

static int
ccieth_connect_ack_from_endpoint(struct ccieth_endpoint *ep, __u32 src_conn_id,
				 __u8 dst_addr[6],  __u32 dst_ep_id, __u32 dst_conn_id,
				 __u32 req_seqnum,
				 __u8 ack_status)
{
	struct sk_buff *skb;
	struct net_device *ifp;
	struct ccieth_pkt_header_connect_ack *hdr;
	size_t skblen;
	int err;

	/* allocate and initialize the skb */
	skblen = sizeof(*hdr);
	if (skblen < ETH_ZLEN)
		skblen = ETH_ZLEN;
	err = -ENOMEM;
	skb = alloc_skb(skblen, GFP_KERNEL);
	if (!skb)
		goto out;
	skb_reset_mac_header(skb);
	skb_reset_network_header(skb);
	skb->protocol = __constant_htons(ETH_P_CCI);
	skb_put(skb, skblen);

	rcu_read_lock();

	/* is the interface still available? */
	ifp = rcu_dereference(ep->ifp);
	if (!ifp) {
		err = -ENODEV;
		goto out_with_rculock;
	}
	skb->dev = ifp;

	/* fill headers */
	hdr = (struct ccieth_pkt_header_connect_ack *) skb_mac_header(skb);
	memcpy(&hdr->eth.h_dest, dst_addr, 6);
	memcpy(&hdr->eth.h_source, ep->addr, 6);
	hdr->eth.h_proto = __constant_cpu_to_be16(ETH_P_CCI);
	hdr->type = CCIETH_PKT_CONNECT_ACK;
	hdr->status = ack_status;
	hdr->dst_ep_id = htonl(dst_ep_id);
	hdr->dst_conn_id = htonl(dst_conn_id);
	hdr->src_ep_id = htonl(ep->id);
	hdr->src_conn_id = htonl(src_conn_id);
	hdr->req_seqnum = htonl(req_seqnum);

	dev_queue_xmit(skb);

	rcu_read_unlock();
	return 0;

out_with_rculock:
	kfree_skb(skb);
	rcu_read_unlock();
out:
	return err;
}

/* called with RCU lock held, cannot sleep */
static int
ccieth_connect_ack_without_endpoint(struct net_device *ifp,
				    __u8 intype, struct sk_buff *inskb,
				    __u8 ack_status)
{
	struct sk_buff *skb;
	struct ccieth_pkt_header_connect_ack *hdr;
	size_t skblen;
	int err;

	/* allocate and initialize the skb */
	skblen = sizeof(*hdr);
	if (skblen < ETH_ZLEN)
		skblen = ETH_ZLEN;
	err = -ENOMEM;
	skb = alloc_skb(skblen, GFP_ATOMIC);
	if (!skb)
		goto out;
	skb_reset_mac_header(skb);
	skb_reset_network_header(skb);
	skb->protocol = __constant_htons(ETH_P_CCI);
	skb_put(skb, skblen);
	skb->dev = ifp;

	/* fill headers */
	hdr = (struct ccieth_pkt_header_connect_ack *) skb_mac_header(skb);
	hdr->eth.h_proto = __constant_cpu_to_be16(ETH_P_CCI);
	hdr->type = CCIETH_PKT_CONNECT_ACK;
	hdr->status = ack_status;

	switch (intype) {
	case CCIETH_PKT_CONNECT_REQUEST: {
		struct ccieth_pkt_header_connect_request _inhdr, *inhdr;
		inhdr = skb_header_pointer(inskb, 0, sizeof(_inhdr), &_inhdr);
		if (!inhdr)
			goto out_with_skb;
		memcpy(&hdr->eth.h_dest, &inhdr->eth.h_source, 6);
		memcpy(&hdr->eth.h_source, &inhdr->eth.h_dest, 6);
		hdr->dst_ep_id = inhdr->src_ep_id;
		hdr->dst_conn_id = inhdr->src_conn_id;
		hdr->src_ep_id = inhdr->dst_ep_id;
		hdr->src_conn_id = htonl(-1);
		hdr->req_seqnum = inhdr->req_seqnum;
		break;
	}
	case CCIETH_PKT_CONNECT_ACCEPT: {
		struct ccieth_pkt_header_connect_accept _inhdr, *inhdr;
		inhdr = skb_header_pointer(inskb, 0, sizeof(_inhdr), &_inhdr);
		if (!inhdr)
			goto out_with_skb;
		memcpy(&hdr->eth.h_dest, &inhdr->eth.h_source, 6);
		memcpy(&hdr->eth.h_source, &inhdr->eth.h_dest, 6);
		hdr->dst_ep_id = inhdr->src_ep_id;
		hdr->dst_conn_id = inhdr->src_conn_id;
		hdr->src_ep_id = inhdr->dst_ep_id;
		hdr->src_conn_id = inhdr->dst_conn_id;
		hdr->req_seqnum = inhdr->req_seqnum;
		break;
	}
	case CCIETH_PKT_CONNECT_REJECT: {
		struct ccieth_pkt_header_connect_reject _inhdr, *inhdr;
		inhdr = skb_header_pointer(inskb, 0, sizeof(_inhdr), &_inhdr);
		if (!inhdr)
			goto out_with_skb;
		memcpy(&hdr->eth.h_dest, &inhdr->eth.h_source, 6);
		memcpy(&hdr->eth.h_source, &inhdr->eth.h_dest, 6);
		hdr->dst_ep_id = inhdr->src_ep_id;
		hdr->dst_conn_id = inhdr->src_conn_id;
		hdr->src_ep_id = inhdr->dst_ep_id;
		hdr->src_conn_id = inhdr->dst_conn_id;
		hdr->req_seqnum = inhdr->req_seqnum;
		break;
	}
	break;
	default:
		BUG();
	}

	dev_queue_xmit(skb);
	return 0;

out_with_skb:
	kfree_skb(skb);
out:
	return err;
}

static int
ccieth__recv_connect_ack(struct ccieth_endpoint *ep, 
			 struct sk_buff *skb,
			 struct ccieth_pkt_header_connect_ack *hdr)
{
	struct ccieth_connection *conn;
	__u32 src_conn_id;
	__u32 src_ep_id;
	__u32 dst_conn_id;
	__u32 dst_ep_id;
	__u32 req_seqnum;
	__u8 ack_status;
	int destroy = 0, notify_close = 0;
	int err;

	dprintk("processing queued connect ack skb %p\n", skb);

	src_conn_id = ntohl(hdr->src_conn_id);
	src_ep_id = ntohl(hdr->src_ep_id);
	dst_conn_id = ntohl(hdr->dst_conn_id);
	dst_ep_id = ntohl(hdr->dst_ep_id);
	req_seqnum = ntohl(hdr->req_seqnum);
	ack_status = hdr->status;

	dprintk("got conn ack from eid %d conn id %d seqnum %d to %d %d\n",
		src_ep_id, src_conn_id, req_seqnum, dst_ep_id, dst_conn_id);

	rcu_read_lock();

	/* find the connection and update it */
	err = -EINVAL;
	conn = idr_find(&ep->connection_idr, dst_conn_id);
	if (!conn || conn->req_seqnum != req_seqnum)
		goto out_with_rculock;

	dprintk("conn %p status %d acked with status %d\n", conn, conn->status, ack_status);

	/* packet was received, stop resending */
	conn->need_ack = 0;

	/* reject ack status doesn't matter, just destroy the connection */
	if (cmpxchg(&conn->status, CCIETH_CONNECTION_REJECTED, CCIETH_CONNECTION_CLOSING)
	    == CCIETH_CONNECTION_REJECTED)
		destroy = 1;

	else if (ack_status != CCIETH_PKT_ACK_SUCCESS) {
		if (cmpxchg(&conn->status, CCIETH_CONNECTION_READY, CCIETH_CONNECTION_CLOSING)
		    == CCIETH_CONNECTION_READY) {
			/* ready nack likely means that the remote side closed in the meantime, maybe because of the timeout.
			 * tell user-space that the connection isn't ready anymore */
			notify_close = 1;
			conn->embedded_event.event.type = CCIETH_IOCTL_EVENT_CONNECTION_CLOSED;
			conn->embedded_event.event.connection_closed.user_conn_id = conn->user_conn_id;
		}
		/* request nack does nothing, the application will get a timeout */
	}

	rcu_read_unlock();

	if (notify_close) {
		/* we set to CLOSING, we own the connection now, nobody else may destroy it */
		del_timer_sync(&conn->timer);
		spin_lock(&ep->connection_idr_lock);
		idr_remove(&ep->connection_idr, dst_conn_id);
		spin_unlock(&ep->connection_idr_lock);
		/* destroy the connection after the event */
		spin_lock_bh(&ep->event_list_lock);
		list_add_tail(&conn->embedded_event.list, &ep->event_list);
		spin_unlock_bh(&ep->event_list_lock);

	} else if (destroy) {
		dprintk("destroying acked rejected connection %p\n", conn);
		/* we set to CLOSING, we own the connection now, nobody else may destroy it */
		del_timer_sync(&conn->timer);
		spin_lock(&ep->connection_idr_lock);
		idr_remove(&ep->connection_idr, conn->id);
		spin_unlock(&ep->connection_idr_lock);
		/* destroy the connection immediately (after RCU grace period) */
		call_rcu(&conn->destroy_rcu_head, ccieth_destroy_connection_rcu);
	}

	dev_kfree_skb(skb);
	return 0;

out_with_rculock:
	rcu_read_unlock();
	dev_kfree_skb(skb);
	return err;
}

/*
 * Generic receiving of connect packets
 */

void
ccieth_deferred_connect_recv_workfunc(struct work_struct *work)
{
	struct ccieth_endpoint *ep = container_of(work, struct ccieth_endpoint, deferred_connect_recv_work);
	struct sk_buff *skb;

	dprintk("dequeueing queued skbs\n");

	while ((skb = skb_dequeue(&ep->deferred_connect_recv_queue)) != NULL) {
		struct ccieth_connect_skb_cb *scb = CCIETH_CONNECT_SKB_CB(skb);
		__u8 type = scb->type;
		int err;

		switch (type) {
		case CCIETH_PKT_CONNECT_REQUEST: {
			struct ccieth_pkt_header_connect_request _hdr, *hdr;
			/* copy the entire header */
			hdr = skb_header_pointer(skb, 0, sizeof(_hdr), &_hdr);
			if (!hdr) {
				dev_kfree_skb(skb);
				continue;
			}
			err = ccieth__recv_connect_request(ep, skb, hdr);
			break;
		}
		case CCIETH_PKT_CONNECT_ACCEPT: {
			struct ccieth_pkt_header_connect_accept _hdr, *hdr;
			/* copy the entire header */
			hdr = skb_header_pointer(skb, 0, sizeof(_hdr), &_hdr);
			if (!hdr) {
				dev_kfree_skb(skb);
				continue;
			}
			err = ccieth__recv_connect_accept(ep, skb, hdr);
			break;
		}
		case CCIETH_PKT_CONNECT_REJECT: {
			struct ccieth_pkt_header_connect_reject _hdr, *hdr;
			/* copy the entire header */
			hdr = skb_header_pointer(skb, 0, sizeof(_hdr), &_hdr);
			if (!hdr) {
				dev_kfree_skb(skb);
				continue;
			}
			err = ccieth__recv_connect_reject(ep, skb, hdr);
			break;
		}
		case CCIETH_PKT_CONNECT_ACK: {
			struct ccieth_pkt_header_connect_ack _hdr, *hdr;
			/* copy the entire header */
			hdr = skb_header_pointer(skb, 0, sizeof(_hdr), &_hdr);
			if (!hdr) {
				dev_kfree_skb(skb);
				continue;
			}
			err = ccieth__recv_connect_ack(ep, skb, hdr);
			break;
		}
		default:
			BUG();
		}
	}
}

int
ccieth_defer_connect_recv(struct net_device *ifp, __u8 type, struct sk_buff *skb)
{
	struct ccieth_endpoint *ep;
	struct ccieth_connect_skb_cb *scb;
	__be32 dst_ep_id_n, *dst_ep_id_n_p;
	int err;

	/* copy the entire header */
	err = -EINVAL;
	dst_ep_id_n_p = skb_header_pointer(skb, offsetof(struct ccieth_pkt_header_generic, dst_ep_id), sizeof(dst_ep_id_n), &dst_ep_id_n);
	if (!dst_ep_id_n_p)
		goto out;

	rcu_read_lock();

	/* find endpoint and check that it's attached to this ifp */
	ep = idr_find(&ccieth_ep_idr, ntohl(*dst_ep_id_n_p));
	if (!ep) {
		if (type != CCIETH_PKT_CONNECT_ACK)
			ccieth_connect_ack_without_endpoint(ifp, type, skb, CCIETH_PKT_ACK_NO_ENDPOINT);
		goto out_with_rculock;
	}
	if (rcu_access_pointer(ep->ifp) != ifp)
		goto out_with_rculock;

	/* save type for later reuse */
	BUILD_BUG_ON(sizeof(*scb) > sizeof(skb->cb));
	scb = CCIETH_CONNECT_SKB_CB(skb);
	scb->type = type;

	dprintk("queueing skb %p\n", skb);
	skb_queue_tail(&ep->deferred_connect_recv_queue, skb);
	schedule_work(&ep->deferred_connect_recv_work);

	rcu_read_unlock();
	return 0;

out_with_rculock:
	rcu_read_unlock();
out:
	dev_kfree_skb(skb);
	return err;
}
