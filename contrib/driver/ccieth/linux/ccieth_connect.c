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

static void
ccieth_connection_event_destructor(struct ccieth_endpoint *ep,
				   struct ccieth_driver_event *event);
static int
ccieth_connect_ack_from_endpoint(struct ccieth_endpoint *ep, __u32 src_conn_id,
				 __u8 dst_addr[6],  __u32 dst_ep_id, __u32 dst_conn_id,
				 __u32 req_seqnum,
				 __u8 ack_status);

/*
 * Connection attribute-specific function
 */

static void
ccieth_send_resend_workfunc(struct work_struct *work)
{
	struct ccieth_connection *conn = container_of(work, struct ccieth_connection, send_resend_work);
	ccieth_msg_resend(conn);
}

static void
ccieth_send_resend_timer_hdlr(unsigned long _data)
{
	struct ccieth_connection *conn = (void *)_data;
	schedule_work(&conn->send_resend_work);
}

static void
ccieth_recv_needack_workfunc(struct work_struct *work)
{
	struct ccieth_connection *conn = container_of(work, struct ccieth_connection, recv_needack_work);
	ccieth_msg_ack(conn);
}

static void
ccieth_recv_needack_timer_hdlr(unsigned long _data)
{
	struct ccieth_connection *conn = (void *)_data;
	if (conn->recv_needack_nr || conn->recv_needack_force)
		schedule_work(&conn->recv_needack_work);
}

static void
ccieth_conn_init(struct ccieth_connection *conn, struct ccieth_endpoint *ep, int attribute)
{
	unsigned long flags;

	conn->ep = ep;
	conn->embedded_event.event.data_length = 0;
	conn->embedded_event.destructor = ccieth_connection_event_destructor;

	switch (attribute) {
	case CCIETH_CONNECT_ATTR_RO:
		flags = CCIETH_CONN_FLAG_RELIABLE | CCIETH_CONN_FLAG_ORDERED;
		break;
	case CCIETH_CONNECT_ATTR_RU:
		flags = CCIETH_CONN_FLAG_RELIABLE;
		break;
	case CCIETH_CONNECT_ATTR_UU:
		flags = 0;
		break;
	default:
		BUG();
	}

	conn->flags = flags;
	if (conn->flags & CCIETH_CONN_FLAG_RELIABLE) {
		/* send side */
		spin_lock_init(&conn->send_lock);
		conn->send_next_seqnum = jiffies;
		conn->send_queue_first_seqnum
		 = conn->send_queue_last_seqnum
		 = conn->send_queue_next_resend = NULL;
		setup_timer(&conn->send_resend_timer, ccieth_send_resend_timer_hdlr, (unsigned long)conn);
		INIT_WORK(&conn->send_resend_work, ccieth_send_resend_workfunc);
		/* recv side */
		spin_lock_init(&conn->recv_lock);
		conn->recv_next_bitmap = 0;
		conn->recv_needack_nr = 0;
		conn->recv_needack_force = 0;
		setup_timer(&conn->recv_needack_timer, ccieth_recv_needack_timer_hdlr, (unsigned long)conn);
		INIT_WORK(&conn->recv_needack_work, ccieth_recv_needack_workfunc);

		if (conn->flags & CCIETH_CONN_FLAG_ORDERED) {
		    /* ordered recv side */
		    INIT_LIST_HEAD(&conn->recv_misordered_event_list);
		}
	}
}

static void
ccieth_conn_free(struct ccieth_connection *conn)
{
	if (conn->flags & CCIETH_CONN_FLAG_RELIABLE) {
		/* drop pending sends */
		struct sk_buff *nskb, *skb = conn->send_queue_first_seqnum;
		while (skb) {
			struct ccieth_skb_cb *scb = CCIETH_SKB_CB(skb), *cscb, *nscb;
			nskb = skb->next;

			ccieth_abort_reliable_send_scb(conn, scb, EIO /* FIXME? */);
			/* dequeue queued events */
			list_for_each_entry_safe(cscb, nscb, &scb->reliable_send.reordered_completed_send_list, reliable_send.reordered_completed_send_list) {
			struct sk_buff *cskb = container_of((void*)cscb, struct sk_buff, cb);
				ccieth_abort_reliable_send_scb(conn, cscb, EIO /* FIXME */);
				/* don't bother dequeueing, we're freeing everything */
				kfree_skb(cskb);
			}
			kfree_skb(skb);

			skb = nskb;
		}

		if (conn->flags & CCIETH_CONN_FLAG_ORDERED) {
			/* drop queued misordered events */
			while (!list_empty(&conn->recv_misordered_event_list)) {
				struct ccieth_driver_event *event = list_first_entry(&conn->recv_misordered_event_list,
										     struct ccieth_driver_event, list);
				list_del(&event->list);
				if (event->event.data_length)
					dev_kfree_skb(event->data_skb);
				ccieth_putback_free_event(conn->ep, event);
			}
		}
	}
}

static void
ccieth_conn_stop_sync(struct ccieth_connection *conn)
{
	/* connection status should be CLOSING so that we can actually stop deferred works */
	BUG_ON(conn->status != CCIETH_CONNECTION_CLOSING);
	if (conn->flags & CCIETH_CONN_FLAG_RELIABLE) {
		/* stop deferred recv_needack */
		del_timer_sync(&conn->recv_needack_timer);
		/* timer isn't running anymore, and can't be rescheduled because conn->status is CLOSING */
		cancel_work_sync(&conn->recv_needack_work);
		/* deferred work not running anymore either */

		/* stop deferred send_resend (same mode) */
		del_timer_sync(&conn->send_resend_timer);
		cancel_work_sync(&conn->send_resend_work);
	}
}

/*
 * Per connection statistics
 */

static void
ccieth_conn_stats_init(struct ccieth_connection *conn, const char *prefix)
{
#ifdef CONFIG_CCIETH_DEBUGFS
	memset(&conn->stats, 0, sizeof(conn->stats));
	conn->debugfs_dir = NULL;
	if (conn->ep->debugfs_dir) {
		char *name = kasprintf(GFP_KERNEL, "%s%08x", prefix, conn->id);
		if (name) {
			struct dentry *d = debugfs_create_dir(name, conn->ep->debugfs_dir);
			if (!IS_ERR(d)) {
				conn->debugfs_dir = d;
				debugfs_create_u32("send", 0444, d, &conn->stats.send);
				debugfs_create_u32("send_resend", 0444, d, &conn->stats.send_resend);
				debugfs_create_u32("send_reordered_event", 0444, d, &conn->stats.send_reordered_event);
				debugfs_create_u32("recv", 0444, d, &conn->stats.recv);
				debugfs_create_u32("recv_duplicate", 0444, d, &conn->stats.recv_duplicate);
				debugfs_create_u32("recv_misorder", 0444, d, &conn->stats.recv_misorder);
				debugfs_create_u32("recv_tooearly", 0444, d, &conn->stats.recv_tooearly);
				debugfs_create_u32("ack_explicit", 0444, d, &conn->stats.ack_explicit);
			}
			kfree(name);
		}
	}
#endif
}

static void
ccieth_conn_stats_stop(struct ccieth_connection *conn)
{
#ifdef CONFIG_CCIETH_DEBUGFS
	if (conn->debugfs_dir)
		debugfs_remove_recursive(conn->debugfs_dir);
#endif
}

/*
 * Connection destruction management
 */

static void
ccieth_destroy_connection_rcu(struct rcu_head *rcu_head)
{
	struct ccieth_connection *conn = container_of(rcu_head, struct ccieth_connection, destroy_rcu_head);
	dprintk("destroying connection %p in rcu call\n", conn);
	ccieth_conn_free(conn);
	kfree_skb(conn->connect_skb);
	kfree(conn);
}

static void
ccieth_connection_event_destructor(struct ccieth_endpoint *ep,
				   struct ccieth_driver_event *event)
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
	del_timer_sync(&conn->connect_timer);
	ccieth_conn_stop_sync(conn);
	/* remove our debugfs entries now, so that the caller can remove its endpoint debugfs dir */
	ccieth_conn_stats_stop(conn);
	/* the caller will destroy the entire idr, no need to remove us from there */
	call_rcu(&conn->destroy_rcu_head, ccieth_destroy_connection_rcu);

	(*destroyed_conn)++;
	return 0;
}

/*
 * Connect packet timers
 */

static
void ccieth_connect_request_timer_hdlr(unsigned long _data)
{
	struct ccieth_connection *conn = (void *)_data;
	struct ccieth_endpoint *ep = conn->ep;
	enum ccieth_connection_status status = conn->status;
	struct sk_buff *skb;
	unsigned long now = jiffies;

	if (status != CCIETH_CONNECTION_REQUESTED)
		return;

	if (now < conn->connect_expire && conn->connect_needack) {
		/* resend request */
		unsigned long next;
		next = now + CCIETH_CONNECT_RESEND_DELAY;
		if (next > conn->connect_expire)
			next = conn->connect_expire;
		mod_timer(&conn->connect_timer, next);

		skb = skb_clone(conn->connect_skb, GFP_ATOMIC);
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

	} else if (now < conn->connect_expire) {
		/* only keep the expire timer, no need to resend anymore */
		mod_timer(&conn->connect_timer, conn->connect_expire);
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
	/* ccieth_conn_stop_sync() not needed, the connection has never been ready */

	dprintk("delivering connection %p timeout\n", conn);
	conn->embedded_event.event.type = CCIETH_IOCTL_EVENT_CONNECT;
	conn->embedded_event.event.connect.user_conn_id = conn->user_conn_id;
	conn->embedded_event.event.connect.status = ETIMEDOUT;
	/* destroy the connection after the event */
	ccieth_queue_busy_event(ep, &conn->embedded_event);
}

static
void ccieth_connect_reply_timer_hdlr(unsigned long _data)
{
	struct ccieth_connection *conn = (void *)_data;
	struct ccieth_endpoint *ep = conn->ep;
	struct sk_buff *skb;

	if (conn->status != CCIETH_CONNECTION_ACCEPTING && conn->status != CCIETH_CONNECTION_REJECTING)
		return;

	if (!conn->connect_needack)
		return;

	/* resend request */
	mod_timer(&conn->connect_timer, jiffies + CCIETH_CONNECT_RESEND_DELAY);

	skb = skb_clone(conn->connect_skb, GFP_ATOMIC);
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
	ccieth_conn_init(conn, ep, arg->attribute);

	/* initialize the timer to make destroy easier */
	setup_timer(&conn->connect_timer, ccieth_connect_request_timer_hdlr, (unsigned long)conn);

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
	skb = alloc_skb_fclone(skblen, GFP_KERNEL);
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
	hdr = (struct ccieth_pkt_header_connect_request *)skb_mac_header(skb);
	memcpy(&hdr->eth.h_dest, &arg->dest_addr, 6);
	memcpy(&hdr->eth.h_source, ep->addr, 6);
	hdr->eth.h_proto = __constant_cpu_to_be16(ETH_P_CCI);
	hdr->type = CCIETH_PKT_CONNECT_REQUEST;
	hdr->dst_ep_id = htonl(arg->dest_eid);
	hdr->attribute = arg->attribute;
	hdr->src_ep_id = htonl(ep->id);
	hdr->max_send_size = htonl(ep->max_send_size);
	hdr->req_seqnum = htonl(req_seqnum);
	hdr->first_seqnum = htonl(conn->send_next_seqnum);
	hdr->data_len = htonl(arg->data_len);
	err = copy_from_user(&hdr->data, (const void __user *)(uintptr_t) arg->data_ptr, arg->data_len);
	if (err) {
		err = -EFAULT;
		goto out_with_skb2;
	}

	/* initialize the connection */
	conn->req_seqnum = req_seqnum;
	conn->status = CCIETH_CONNECTION_REQUESTED;
	memcpy(&conn->dest_addr, &arg->dest_addr, 6);
	conn->dest_eid = arg->dest_eid;
	conn->user_conn_id = arg->user_conn_id;
	conn->id = id; /* cannot be CCIETH_CONNECTION_INVALID_ID */
	idr_replace(&ep->connection_idr, conn, id);
	hdr->src_conn_id = htonl(id);

	/* now that the connection has an id, we can put stats in debugfs */
	ccieth_conn_stats_init(conn, "connreq");

	/* this connection now needs this request to be acked */
	conn->connect_needack = 1;
	/* keep the current skb cached in the connection,
	 * and try to send the clone. if we can't, we'll resend later.
	 */
	conn->connect_skb = skb;
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
		conn->connect_expire = now + msecs_to_jiffies(msecs);
	} else {
		conn->connect_expire = -1;	/* that's MAX_LONG now */
	}
	next = now + CCIETH_CONNECT_RESEND_DELAY;
	if (next > conn->connect_expire)
		next = conn->connect_expire;
	mod_timer(&conn->connect_timer, next);

	arg->conn_id = conn->id;
	return 0;

out_with_rculock:
	rcu_read_unlock();
	ccieth_conn_stats_stop(conn);
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
	if (conn->status != CCIETH_CONNECTION_REQUESTED	/* so that dest_id is valid */
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
	struct ccieth_driver_event *event;
	struct ccieth_connection *conn;
	__u32 src_ep_id;
	__u32 src_conn_id;
	__u32 data_len;
	__u32 src_max_send_size;
	__u32 req_seqnum;
	__u32 first_seqnum;
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
	first_seqnum = ntohl(hdr->first_seqnum);

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
	event = ccieth_get_free_event(ep);
	if (!event) {
		/* don't ack, we need a resend */
		err = -ENOBUFS;
		dprintk("ccieth: no event slot for connect request\n");
		goto out;
	}

	/* get a connection */
	err = -ENOMEM;
	conn = kmalloc(sizeof(*conn), GFP_KERNEL);
	if (!conn)
		goto out_with_event;
	ccieth_conn_init(conn, ep, hdr->attribute);
	/* no need for a ack before accept()/reject() is actually called */
	conn->connect_needack = 0;

	/* initialize the timer to make destroy easier */
	setup_timer(&conn->connect_timer, ccieth_connect_reply_timer_hdlr, (unsigned long)conn);

	/* allocate and initialize the connect reply skb now so that we don't fail with ENOMEM later */
	replyskblen = max(sizeof(struct ccieth_pkt_header_connect_accept),
			  sizeof(struct ccieth_pkt_header_connect_reject));
	if (replyskblen < ETH_ZLEN)
		replyskblen = ETH_ZLEN;
	replyskb = alloc_skb_fclone(replyskblen, GFP_KERNEL);
	if (!replyskb)
		goto out_with_conn;
	skb_reset_mac_header(replyskb);
	skb_reset_network_header(replyskb);
	replyskb->protocol = __constant_htons(ETH_P_CCI);
	skb_put(replyskb, replyskblen);
	conn->connect_skb = replyskb;

	/* setup the connection so that we can check for duplicates before inserting */
	conn->status = CCIETH_CONNECTION_RECEIVED;
	memcpy(&conn->dest_addr, &hdr->eth.h_source, 6);
	conn->dest_eid = src_ep_id;
	conn->dest_id = src_conn_id;
	conn->req_seqnum = req_seqnum;
	conn->recv_last_full_seqnum = first_seqnum - 1;
	conn->max_send_size = src_max_send_size < ep->max_send_size ? src_max_send_size : ep->max_send_size;

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
	event->event.connect_request.max_send_size = conn->max_send_size;
	if (data_len) {
		event->data_skb = skb;
		event->data_skb_offset = sizeof(*hdr);
		skb = NULL;
	}

	/* things cannot fail anymore now, insert the connection for real */
	conn->id = id; /* cannot be CCIETH_CONNECTION_INVALID_ID */
	idr_replace(&ep->connection_idr, conn, id);
	atomic_inc(&ep->connection_received);

	/* now that the connection has an id, we can put stats in debugfs */
	ccieth_conn_stats_init(conn, "connacc");

	/* finalize and notify the event */
	event->event.connect_request.conn_id = id;
	ccieth_queue_busy_event(ep, event);

	ccieth_connect_ack_from_endpoint(ep, -1,
					 (__u8 *)&hdr->eth.h_source, src_ep_id, src_conn_id, req_seqnum,
					 ack_status);
	dev_kfree_skb(skb);
	return 0;

out_with_replyskb:
	kfree_skb(replyskb);
out_with_conn:
	kfree(conn);
out_with_event:
	ccieth_putback_free_event(ep, event);
out:
	if (need_ack)
		ccieth_connect_ack_from_endpoint(ep, -1,
						 (__u8 *)&hdr->eth.h_source, src_ep_id, src_conn_id, req_seqnum,
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

	if (cmpxchg(&conn->status, CCIETH_CONNECTION_RECEIVED, CCIETH_CONNECTION_ACCEPTING)
	    != CCIETH_CONNECTION_RECEIVED)
		goto out_with_rculock;
	atomic_dec(&ep->connection_received);
	conn->user_conn_id = arg->user_conn_id;

	/* fill headers */
	skb = conn->connect_skb;
	hdr = (struct ccieth_pkt_header_connect_accept *)skb_mac_header(skb);
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
	hdr->first_seqnum = htonl(conn->send_next_seqnum);

	/* this connection now needs this accept to be acked */
	conn->connect_needack = 1;
	/* setup resend or timeout timer */
	mod_timer(&conn->connect_timer, jiffies + CCIETH_CONNECT_RESEND_DELAY);

	rcu_read_unlock();	/* end of rcu read access to ep conn idr only */

	/* try to send a clone. if we can't, we'll resend later. */
	skb = skb_clone(skb, GFP_KERNEL);
	if (skb) {
		rcu_read_lock();	/* start of another rcu read access for ep->ifp only */
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
	struct ccieth_driver_event *event;
	struct ccieth_connection *conn;
	__u32 src_conn_id;
	__u32 src_ep_id;
	__u32 dst_conn_id;
	__u32 max_send_size;
	__u32 req_seqnum;
	__u32 first_seqnum;
	int need_ack = 0;
	enum ccieth_pkt_ack_status ack_status = CCIETH_PKT_ACK_SUCCESS;
	int err;

	dprintk("processing queued connect accept skb %p\n", skb);

	src_conn_id = ntohl(hdr->src_conn_id);
	src_ep_id = ntohl(hdr->src_ep_id);
	dst_conn_id = ntohl(hdr->dst_conn_id);
	max_send_size = ntohl(hdr->max_send_size);
	req_seqnum = ntohl(hdr->req_seqnum);
	first_seqnum = ntohl(hdr->first_seqnum);

	dprintk("got conn accept from eid %d conn id %d seqnum %d to %d %d\n",
		src_ep_id, src_conn_id, req_seqnum, ntohl(hdr->dst_ep_id), dst_conn_id);

	rcu_read_lock();

	/* get an event */
	event = ccieth_get_free_event(ep);
	if (!event) {
		/* don't ack, we need a resend */
		err = -ENOBUFS;
		dprintk("ccieth: no event slot for connect accepted\n");
		goto out_with_rculock;
	}

	/* setup the event */
	event->event.type = CCIETH_IOCTL_EVENT_CONNECT;
	event->event.data_length = 0;
	event->event.connect.status = 0;
	event->event.connect.conn_id = dst_conn_id;

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
	/* accept means ack, no need to resend anymore */
	conn->connect_needack = 0;

	/* setup connection */
	conn->dest_id = src_conn_id;
	conn->max_send_size = max_send_size;
	conn->recv_last_full_seqnum = first_seqnum - 1;

	/* finalize and notify the event */
	event->event.connect.max_send_size = max_send_size;
	event->event.connect.user_conn_id = conn->user_conn_id;
	ccieth_queue_busy_event(ep, event);

	rcu_read_unlock();

	ccieth_connect_ack_from_endpoint(ep, dst_conn_id,
					 (__u8 *)&hdr->eth.h_source, src_ep_id, src_conn_id, req_seqnum,
					 ack_status);
	dev_kfree_skb(skb);
	return 0;

out_with_conn:
	/* nothing */
out_with_event:
	ccieth_putback_free_event(ep, event);
out_with_rculock:
	rcu_read_unlock();
	if (need_ack)
		ccieth_connect_ack_from_endpoint(ep, dst_conn_id,
						 (__u8 *)&hdr->eth.h_source, src_ep_id, src_conn_id, req_seqnum,
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

	if (cmpxchg(&conn->status, CCIETH_CONNECTION_RECEIVED, CCIETH_CONNECTION_REJECTING)
	    != CCIETH_CONNECTION_RECEIVED)
		goto out_with_rculock;
	atomic_dec(&ep->connection_received);

	/* fill headers */
	skb = conn->connect_skb;
	hdr = (struct ccieth_pkt_header_connect_reject *)skb_mac_header(skb);
	memcpy(&hdr->eth.h_dest, &conn->dest_addr, 6);
	memcpy(&hdr->eth.h_source, ep->addr, 6);
	hdr->eth.h_proto = __constant_cpu_to_be16(ETH_P_CCI);
	hdr->type = CCIETH_PKT_CONNECT_REJECT;
	hdr->dst_ep_id = htonl(conn->dest_eid);
	hdr->dst_conn_id = htonl(conn->dest_id);
	hdr->src_ep_id = htonl(ep->id);
	hdr->src_conn_id = htonl(conn->id);
	hdr->req_seqnum = htonl(conn->req_seqnum);

	/* this connection now needs this accept to be acked */
	conn->connect_needack = 1;
	/* setup resend or timeout timer */
	mod_timer(&conn->connect_timer, jiffies + CCIETH_CONNECT_RESEND_DELAY);

	rcu_read_unlock();	/* end of rcu read access to ep conn idr only */

	/* try to send a clone. if we can't, we'll resend later. */
	skb = skb_clone(skb, GFP_KERNEL);
	if (skb) {
		rcu_read_lock();	/* start of another rcu read access for ep->ifp only */
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
	__u32 req_seqnum;
	int need_ack = 0;
	enum ccieth_pkt_ack_status ack_status = CCIETH_PKT_ACK_SUCCESS;
	int err;

	dprintk("processing queued connect reject skb %p\n", skb);

	src_conn_id = ntohl(hdr->src_conn_id);
	src_ep_id = ntohl(hdr->src_ep_id);
	dst_conn_id = ntohl(hdr->dst_conn_id);
	req_seqnum = ntohl(hdr->req_seqnum);

	dprintk("got conn reject from eid %d conn id %d seqnum %d to %d %d\n",
		src_ep_id, src_conn_id, req_seqnum, ntohl(hdr->dst_ep_id), dst_conn_id);

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
	/* reject means ack, no need to resend anymore */
	conn->connect_needack = 0;

	rcu_read_unlock();

	/* we set to CLOSING, we own the connection now, nobody else may destroy it */
	del_timer_sync(&conn->connect_timer);
	spin_lock(&ep->connection_idr_lock);
	idr_remove(&ep->connection_idr, dst_conn_id);
	spin_unlock(&ep->connection_idr_lock);

	/* setup the event */
	conn->embedded_event.event.type = CCIETH_IOCTL_EVENT_CONNECT;
	conn->embedded_event.event.connect.user_conn_id = conn->user_conn_id;
	conn->embedded_event.event.connect.status = ECONNREFUSED;
	/* destroy the connection after the event */
	ccieth_queue_busy_event(ep, &conn->embedded_event);

	ccieth_connect_ack_from_endpoint(ep, dst_conn_id,
					 (__u8 *)&hdr->eth.h_source, src_ep_id, src_conn_id, req_seqnum,
					 ack_status);
	dev_kfree_skb(skb);
	return 0;

out_with_rculock:
	rcu_read_unlock();
	if (need_ack)
		ccieth_connect_ack_from_endpoint(ep, dst_conn_id,
						 (__u8 *)&hdr->eth.h_source, src_ep_id, src_conn_id, req_seqnum,
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
	hdr = (struct ccieth_pkt_header_connect_ack *)skb_mac_header(skb);
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
	struct _ccieth_pkt_header_connect_generic _inhdr, *inhdr;
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
	hdr = (struct ccieth_pkt_header_connect_ack *)skb_mac_header(skb);
	hdr->eth.h_proto = __constant_cpu_to_be16(ETH_P_CCI);
	hdr->type = CCIETH_PKT_CONNECT_ACK;
	hdr->status = ack_status;

	/* make sure we can read request/accept/reject headers as a generic packet */
	BUILD_BUG_ON(sizeof(struct _ccieth_pkt_header_connect_generic) > sizeof(struct ccieth_pkt_header_connect_request));
	BUILD_BUG_ON(offsetof(struct _ccieth_pkt_header_connect_generic, eth) != offsetof(struct ccieth_pkt_header_connect_request, eth));
	BUILD_BUG_ON(offsetof(struct _ccieth_pkt_header_connect_generic, type) != offsetof(struct ccieth_pkt_header_connect_request, type));
	BUILD_BUG_ON(offsetof(struct _ccieth_pkt_header_connect_generic, src_ep_id) != offsetof(struct ccieth_pkt_header_connect_request, src_ep_id));
	BUILD_BUG_ON(offsetof(struct _ccieth_pkt_header_connect_generic, src_conn_id) != offsetof(struct ccieth_pkt_header_connect_request, src_conn_id));
	BUILD_BUG_ON(offsetof(struct _ccieth_pkt_header_connect_generic, dst_ep_id) != offsetof(struct ccieth_pkt_header_connect_request, dst_ep_id));
	BUILD_BUG_ON(offsetof(struct _ccieth_pkt_header_connect_generic, req_seqnum) != offsetof(struct ccieth_pkt_header_connect_request, req_seqnum));
	BUILD_BUG_ON(sizeof(struct _ccieth_pkt_header_connect_generic) > sizeof(struct ccieth_pkt_header_connect_accept));
	BUILD_BUG_ON(offsetof(struct _ccieth_pkt_header_connect_generic, eth) != offsetof(struct ccieth_pkt_header_connect_accept, eth));
	BUILD_BUG_ON(offsetof(struct _ccieth_pkt_header_connect_generic, type) != offsetof(struct ccieth_pkt_header_connect_accept, type));
	BUILD_BUG_ON(offsetof(struct _ccieth_pkt_header_connect_generic, src_ep_id) != offsetof(struct ccieth_pkt_header_connect_accept, src_ep_id));
	BUILD_BUG_ON(offsetof(struct _ccieth_pkt_header_connect_generic, src_conn_id) != offsetof(struct ccieth_pkt_header_connect_accept, src_conn_id));
	BUILD_BUG_ON(offsetof(struct _ccieth_pkt_header_connect_generic, dst_ep_id) != offsetof(struct ccieth_pkt_header_connect_accept, dst_ep_id));
	BUILD_BUG_ON(offsetof(struct _ccieth_pkt_header_connect_generic, dst_conn_id) != offsetof(struct ccieth_pkt_header_connect_accept, dst_conn_id));
	BUILD_BUG_ON(offsetof(struct _ccieth_pkt_header_connect_generic, req_seqnum) != offsetof(struct ccieth_pkt_header_connect_accept, req_seqnum));
	BUILD_BUG_ON(sizeof(struct _ccieth_pkt_header_connect_generic) > sizeof(struct ccieth_pkt_header_connect_reject));
	BUILD_BUG_ON(offsetof(struct _ccieth_pkt_header_connect_generic, eth) != offsetof(struct ccieth_pkt_header_connect_reject, eth));
	BUILD_BUG_ON(offsetof(struct _ccieth_pkt_header_connect_generic, type) != offsetof(struct ccieth_pkt_header_connect_reject, type));
	BUILD_BUG_ON(offsetof(struct _ccieth_pkt_header_connect_generic, src_ep_id) != offsetof(struct ccieth_pkt_header_connect_reject, src_ep_id));
	BUILD_BUG_ON(offsetof(struct _ccieth_pkt_header_connect_generic, src_conn_id) != offsetof(struct ccieth_pkt_header_connect_reject, src_conn_id));
	BUILD_BUG_ON(offsetof(struct _ccieth_pkt_header_connect_generic, dst_ep_id) != offsetof(struct ccieth_pkt_header_connect_reject, dst_ep_id));
	BUILD_BUG_ON(offsetof(struct _ccieth_pkt_header_connect_generic, dst_conn_id) != offsetof(struct ccieth_pkt_header_connect_reject, dst_conn_id));
	BUILD_BUG_ON(offsetof(struct _ccieth_pkt_header_connect_generic, req_seqnum) != offsetof(struct ccieth_pkt_header_connect_reject, req_seqnum));

	/* copy packet info from generic connect header */
	inhdr = skb_header_pointer(inskb, 0, sizeof(_inhdr), &_inhdr);
	if (!inhdr)
		goto out_with_skb;
	memcpy(&hdr->eth.h_dest, &inhdr->eth.h_source, 6);
	memcpy(&hdr->eth.h_source, &inhdr->eth.h_dest, 6);
	hdr->dst_ep_id = inhdr->src_ep_id;
	hdr->dst_conn_id = inhdr->src_conn_id;
	hdr->src_ep_id = inhdr->dst_ep_id;
	hdr->src_conn_id = intype == CCIETH_PKT_CONNECT_REQUEST ? htonl(-1) : inhdr->dst_conn_id;
	hdr->req_seqnum = inhdr->req_seqnum;

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
	struct ccieth_driver_event *event = NULL;
	__u32 dst_conn_id;
	__u32 req_seqnum;
	__u8 ack_status;
	int destroy = 0, notify_close = 0;
	int err;

	dprintk("processing queued connect ack skb %p\n", skb);

	dst_conn_id = ntohl(hdr->dst_conn_id);
	req_seqnum = ntohl(hdr->req_seqnum);
	ack_status = hdr->status;

	dprintk("got conn ack from eid %d conn id %d seqnum %d to %d %d\n",
		ntohl(hdr->src_ep_id), ntohl(hdr->src_conn_id), req_seqnum, ntohl(hdr->dst_ep_id), dst_conn_id);

	/* get an event */
	event = ccieth_get_free_event(ep);
	if (!event) {
		/* don't ack, we need a resend */
		err = -ENOBUFS;
		dprintk("ccieth: no event slot for connect accepted\n");
		goto out;
	}

	rcu_read_lock();

	/* find the connection and update it */
	err = -EINVAL;
	conn = idr_find(&ep->connection_idr, dst_conn_id);
	if (!conn || conn->req_seqnum != req_seqnum)
		goto out_with_rculock;

	dprintk("conn %p status %d acked with status %d\n", conn, conn->status, ack_status);

	/* packet was received, stop resending */
	conn->connect_needack = 0;

	if (ack_status == CCIETH_PKT_ACK_SUCCESS) {
		/* ACK */
		if (cmpxchg(&conn->status, CCIETH_CONNECTION_ACCEPTING, CCIETH_CONNECTION_READY)
		      == CCIETH_CONNECTION_ACCEPTING) {
			/* setup and notify the ACCEPT success event */
			event->event.type = CCIETH_IOCTL_EVENT_ACCEPT;
			event->event.data_length = 0;
			event->event.accept.status = 0;
			event->event.accept.user_conn_id = conn->user_conn_id;
			ccieth_queue_busy_event(ep, event);
			/* don't let the remaining code putback this event */
			event = NULL;

		} else if (cmpxchg(&conn->status, CCIETH_CONNECTION_REJECTING, CCIETH_CONNECTION_CLOSING)
		    == CCIETH_CONNECTION_REJECTING) {
			/* reject ack status doesn't matter, just destroy the connection */
			destroy = 1;

		} else {
			/* request ack does nothing, recv accept does the job */
			/* ready ack does nothing */
			/* ack on CLOSING is ignored */
		}

	} else {
		/* NACK */
		if (cmpxchg(&conn->status, CCIETH_CONNECTION_ACCEPTING, CCIETH_CONNECTION_CLOSING)
		    == CCIETH_CONNECTION_ACCEPTING) {
			/* setup and notify the ACCEPT failed event */
			event->event.type = CCIETH_IOCTL_EVENT_ACCEPT;
			event->event.data_length = 0;
			event->event.accept.status = ccieth_pkt_ack_status_to_errno(ack_status);
			event->event.accept.user_conn_id = conn->user_conn_id;
			ccieth_queue_busy_event(ep, event);
			/* don't let the remaining code putback this event */
			event = NULL;

		} else if (cmpxchg(&conn->status, CCIETH_CONNECTION_REJECTING, CCIETH_CONNECTION_CLOSING)
		    == CCIETH_CONNECTION_REJECTING) {
			/* reject ack status doesn't matter, just destroy the connection */
			destroy = 1;

		} else if (cmpxchg(&conn->status, CCIETH_CONNECTION_REQUESTED, CCIETH_CONNECTION_CLOSING)
		    == CCIETH_CONNECTION_REQUESTED) {
			/* setup and notify the CONNECT failed event */
			event->event.type = CCIETH_IOCTL_EVENT_CONNECT;
			event->event.data_length = 0;
			event->event.connect.status = ccieth_pkt_ack_status_to_errno(ack_status);
			event->event.connect.user_conn_id = conn->user_conn_id;
			ccieth_queue_busy_event(ep, event);
			/* don't let the remaining code putback this event */
			event = NULL;

		} else if (cmpxchg(&conn->status, CCIETH_CONNECTION_READY, CCIETH_CONNECTION_CLOSING)
		    == CCIETH_CONNECTION_READY) {
			/* ready nack likely means that the remote side closed in the meantime, maybe because of the timeout.
			 * tell user-space that the connection isn't ready anymore */
			notify_close = 1;
			conn->embedded_event.event.type = CCIETH_IOCTL_EVENT_CONNECTION_CLOSED;
			conn->embedded_event.event.connection_closed.user_conn_id = conn->user_conn_id;

		} else {
			/* nack on CLOSING is ignored */
		}
	}

	rcu_read_unlock();

	if (notify_close) {
		/* we set to CLOSING, we own the connection now, nobody else may destroy it */
		del_timer_sync(&conn->connect_timer);
		ccieth_conn_stop_sync(conn);
		spin_lock(&ep->connection_idr_lock);
		idr_remove(&ep->connection_idr, dst_conn_id);
		spin_unlock(&ep->connection_idr_lock);
		/* destroy the connection after the event */
		ccieth_queue_busy_event(ep, &conn->embedded_event);

	} else if (destroy) {
		dprintk("destroying acked rejected connection %p\n", conn);
		/* we set to CLOSING, we own the connection now, nobody else may destroy it */
		del_timer_sync(&conn->connect_timer);
		ccieth_conn_stop_sync(conn);
		spin_lock(&ep->connection_idr_lock);
		idr_remove(&ep->connection_idr, conn->id);
		spin_unlock(&ep->connection_idr_lock);
		/* destroy the connection immediately (after RCU grace period) */
		call_rcu(&conn->destroy_rcu_head, ccieth_destroy_connection_rcu);
	}

	if (event)
		ccieth_putback_free_event(ep, event);
	dev_kfree_skb(skb);
	return 0;

out_with_rculock:
	rcu_read_unlock();
	if (event)
		ccieth_putback_free_event(ep, event);
out:
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
		struct ccieth_skb_cb *scb = CCIETH_SKB_CB(skb);
		__u8 type = scb->connect.type;

		switch (type) {
		case CCIETH_PKT_CONNECT_REQUEST: {
			struct ccieth_pkt_header_connect_request _hdr, *hdr;
			/* copy the entire header */
			hdr = skb_header_pointer(skb, 0, sizeof(_hdr), &_hdr);
			if (!hdr) {
				dev_kfree_skb(skb);
				continue;
			}
			ccieth__recv_connect_request(ep, skb, hdr);
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
			ccieth__recv_connect_accept(ep, skb, hdr);
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
			ccieth__recv_connect_reject(ep, skb, hdr);
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
			ccieth__recv_connect_ack(ep, skb, hdr);
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
	CCIETH_SKB_CB(skb)->connect.type = type;

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
