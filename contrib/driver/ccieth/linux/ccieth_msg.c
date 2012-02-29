/*
 * CCI over Ethernet
 *
 * Copyright © 2011-2012 Inria.  All rights reserved.
 * $COPYRIGHT$
 */

#include <linux/netdevice.h>
#include <linux/rcupdate.h>

#include <ccieth_common.h>
#include <ccieth_wire.h>

static inline int
ccieth_conn_send_ack(struct ccieth_connection *conn, __be32 *seqnum, __be32 *bitmap)
{
	int ret;
	spin_lock_bh(&conn->recv_lock);
	ret = conn->recv_needack_nr || conn->recv_needack_force;
	*seqnum = htonl(conn->recv_last_full_seqnum);
	if (bitmap)
		*bitmap = htonl(conn->recv_next_bitmap);
	conn->recv_needack_nr = 0;
	conn->recv_needack_force = 0;
	spin_unlock_bh(&conn->recv_lock);
	return ret ? 0 : -EAGAIN;
}

static void
ccieth_conn_handle_ack(struct ccieth_connection *conn, __u32 acked_seqnum, __u32 acked_bitmap)
{
	struct sk_buff *skb, *nskb, *old_next_resend;
	__u32 last_acked = acked_seqnum;

	if (acked_bitmap) {
		last_acked += fls(acked_bitmap);
		dprintk("marking acked %u-%u %04x\n", acked_seqnum, last_acked, acked_bitmap);
	}

	spin_lock_bh(&conn->send_lock);

	old_next_resend = conn->send_queue_next_resend;
	skb = conn->send_queue_first_seqnum;
	/* remove acked MSGs */
	while (skb != NULL) {
		struct ccieth_endpoint_event *event;
		struct ccieth_skb_cb *scb = CCIETH_SKB_CB(skb);

		if (ccieth_seqnum_after_strict(last_acked, scb->reliable_send.seqnum))
			/* queue is ordered by seqnum, no need to try further */
			break;

		if (ccieth_seqnum_after_strict(acked_seqnum, scb->reliable_send.seqnum)) {
			/* handle acked bitmap */
			__u32 offset = scb->reliable_send.seqnum - acked_seqnum -1;
			if (!(acked_bitmap & (1 << offset))) {
				skb = skb->next;
				continue;
			}
		}

		nskb = skb->next;

		/* dequeue this MSG */
		if (skb == conn->send_queue_first_seqnum)
			conn->send_queue_first_seqnum = nskb;
		else
			skb->prev->next = nskb;
		if (skb == conn->send_queue_last_seqnum)
			conn->send_queue_last_seqnum = skb->prev;
		else
			skb->next->prev = skb->prev;

		/* if this MSG was the next to resend, update the pointer */
		if (skb == conn->send_queue_next_resend)
			conn->send_queue_next_resend = nskb ? nskb : conn->send_queue_first_seqnum;

		event = scb->reliable_send.event;
		event->event.send.status = 0;
		ccieth_queue_busy_event(conn->ep, event);

		dprintk("no need to resend MSG %u anymore\n", scb->reliable_send.seqnum);
		kfree_skb(skb);

		skb = nskb;
	}

	/* update connection resend timer if:
	 * - some MSGs still have not been acked
	 * - the first one has changed
	 */
	if (conn->send_queue_next_resend
	    && conn->send_queue_next_resend != old_next_resend
	    && conn->status == CCIETH_CONNECTION_READY)
		mod_timer(&conn->send_resend_timer,
			  CCIETH_SKB_CB(conn->send_queue_next_resend)->reliable_send.resend_jiffies);

	spin_unlock_bh(&conn->send_lock);
}

int
ccieth_msg_resend(struct ccieth_connection *conn)
{
	spin_lock_bh(&conn->send_lock);

	if (!conn->send_queue_next_resend)
		goto out_with_lock;

	/* walk the resend_jiffies-ordered queue and resend everything needed */
	while (1) {
		struct sk_buff *skb = conn->send_queue_next_resend;
		struct ccieth_skb_cb *scb = CCIETH_SKB_CB(skb);
		struct net_device *ifp;

		if (scb->reliable_send.resend_jiffies > jiffies)
			break;

		CCIETH_STAT_INC(conn, send_resend);

		/* try to send a clone */
		rcu_read_lock();
		/* is the interface still available? */
		ifp = rcu_dereference(conn->ep->ifp);
		if (ifp) {
			struct sk_buff *newskb = skb_clone(skb, GFP_ATOMIC);
			if (newskb) {
				struct ccieth_pkt_header_msg *hdr = (struct ccieth_pkt_header_msg *)skb_mac_header(skb);
				ccieth_conn_send_ack(conn, &hdr->acked_seqnum, NULL);
				newskb->dev = ifp;
				dev_queue_xmit(newskb);
			}
		}
		rcu_read_unlock();

		/* plan next resend for this MSG */
		scb->reliable_send.resend_jiffies = jiffies + CCIETH_MSG_RESEND_DELAY;

		/* switch to next packet, wrap-around if needed */
		conn->send_queue_next_resend = skb->next ? skb->next : conn->send_queue_first_seqnum;
	}

	/* update connection resend timer */
	if (conn->status == CCIETH_CONNECTION_READY)
		mod_timer(&conn->send_resend_timer,
			  CCIETH_SKB_CB(conn->send_queue_next_resend)->reliable_send.resend_jiffies);

out_with_lock:
	spin_unlock_bh(&conn->send_lock);
	return 0;
}

int
ccieth_msg(struct ccieth_endpoint *ep, struct ccieth_ioctl_msg *arg)
{
	struct sk_buff *skb, *skb2 = NULL;
	struct net_device *ifp;
	struct ccieth_pkt_header_msg *hdr;
	struct ccieth_connection *conn;
	struct ccieth_endpoint_event *event;
	size_t skblen;
	int err;

	err = -EINVAL;
	if (unlikely(arg->msg_len > ep->max_send_size))
		goto out;

	/* allocate and initialize the skb */
	skblen = sizeof(*hdr) + arg->msg_len;
	if (skblen < ETH_ZLEN)
		skblen = ETH_ZLEN;
	if (arg->internal_flags & CCIETH_MSG_FLAG_RELIABLE)
		skb = alloc_skb_fclone(skblen, GFP_KERNEL);
	else
		skb = alloc_skb(skblen, GFP_KERNEL);
	if (unlikely(!skb))
		goto out;
	skb_reset_mac_header(skb);
	skb_reset_network_header(skb);
	skb->protocol = __constant_htons(ETH_P_CCI);
	skb_put(skb, skblen);
	/* reliable sends need a clone */
	if (arg->internal_flags & CCIETH_MSG_FLAG_RELIABLE) {
		skb2 = skb_clone(skb, GFP_KERNEL);
		if (unlikely(!skb2))
			goto out_with_skb;
	}

	/* copy data while not holding RCU read lock yet */
	hdr = (struct ccieth_pkt_header_msg *)skb_mac_header(skb);
	err = copy_from_user(&hdr->msg, (const void __user *)(uintptr_t) arg->msg_ptr, arg->msg_len);
	if (unlikely(err)) {
		err = -EFAULT;
		goto out_with_skb2;
	}

	rcu_read_lock();

	/* is the interface still available? */
	ifp = rcu_dereference(ep->ifp);
	if (unlikely(!ifp)) {
		err = -ENODEV;
		goto out_with_rculock;
	}

	/* find connection */
	conn = idr_find(&ep->connection_idr, arg->conn_id);
	if (unlikely(!conn || conn->status != CCIETH_CONNECTION_READY))
		goto out_with_rculock;
	/* check that the user-space reliable hint was valid */
	if (unlikely(!!(arg->internal_flags & CCIETH_MSG_FLAG_RELIABLE)
		     != !!(conn->flags & CCIETH_CONN_FLAG_RELIABLE)))
		goto out_with_rculock;

	/* get an event */
	event = ccieth_get_free_event(ep);
	if (unlikely(!event)) {
		err = -ENOBUFS;
		dprintk("ccieth: no event slot for send\n");
		goto out_with_rculock;
	}

	/* setup the event */
	event->event.type = CCIETH_IOCTL_EVENT_SEND;
	event->event.data_length = 0;
	event->event.send.user_conn_id = conn->user_conn_id;
	event->event.send.context = arg->context;

	/* fill headers */
	memcpy(&hdr->eth.h_dest, &conn->dest_addr, 6);
	memcpy(&hdr->eth.h_source, ep->addr, 6);
	hdr->eth.h_proto = __constant_cpu_to_be16(ETH_P_CCI);
	hdr->type = CCIETH_PKT_MSG;
	hdr->dst_ep_id = htonl(conn->dest_eid);
	hdr->dst_conn_id = htonl(conn->dest_id);
	hdr->conn_seqnum = htonl(conn->req_seqnum);
	hdr->msg_len = htonl(arg->msg_len);

	/* FIXME: implement flags */

	CCIETH_STAT_INC(conn, send);

	if (conn->flags & CCIETH_CONN_FLAG_RELIABLE) {
		struct ccieth_skb_cb *scb = CCIETH_SKB_CB(skb);
		__u32 seqnum;

		spin_lock_bh(&conn->send_lock);
		seqnum = conn->send_next_seqnum++;
		hdr->msg_seqnum = htonl(seqnum);
		scb->reliable_send.seqnum = seqnum;
		scb->reliable_send.resend_jiffies = jiffies + CCIETH_MSG_RESEND_DELAY;
		scb->reliable_send.event = event;
		if (conn->send_queue_last_seqnum) {
			conn->send_queue_last_seqnum->next = skb;
			skb->prev = conn->send_queue_last_seqnum;
			/* timer already scheduled */
		} else {
			conn->send_queue_first_seqnum
			 = conn->send_queue_next_resend = skb;
			skb->prev = NULL;
			mod_timer(&conn->send_resend_timer, scb->reliable_send.resend_jiffies);
		}
		conn->send_queue_last_seqnum = skb;
		skb->next = NULL;
		dprintk("need to resend MSG %u\n", seqnum);
		spin_unlock_bh(&conn->send_lock);

		ccieth_conn_send_ack(conn, &hdr->acked_seqnum, NULL);

		skb2->dev = ifp;
		dev_queue_xmit(skb2);
	} else {
#ifdef CONFIG_CCIETH_DEBUG
		hdr->msg_seqnum = htonl(-1);
#endif
		skb->dev = ifp;
		dev_queue_xmit(skb);

		/* finalize and notify the event */
		event->event.send.status = 0;
		ccieth_queue_busy_event(ep, event);
	}

	rcu_read_unlock();
	return 0;

out_with_rculock:
	rcu_read_unlock();
out_with_skb2:
	kfree_skb(skb2);
out_with_skb:
	kfree_skb(skb);
out:
	return err;
}

/* called under rcu_read_lock() */
static int
ccieth__recv_msg_unreliable(struct ccieth_endpoint *ep, struct ccieth_connection *conn,
			    struct ccieth_pkt_header_msg *hdr, struct sk_buff *skb)
{
	struct ccieth_endpoint_event *event;
	__u32 msg_len = ntohl(hdr->msg_len);
	int err;

	/* get an event */
	event = ccieth_get_free_event(ep);
	if (unlikely(!event)) {
		/* don't ack, we need a resend */
		err = -ENOBUFS;
		dprintk("ccieth: no event slot for msg\n");
		goto out;
	}

	/* setup the event */
	event->event.type = CCIETH_IOCTL_EVENT_RECV;
	event->event.data_length = msg_len;
	event->event.recv.user_conn_id = conn->user_conn_id;

	err = skb_copy_bits(skb, sizeof(*hdr), event+1, msg_len);
	BUG_ON(err < 0);

	CCIETH_STAT_INC(conn, recv);

	/* notify the event */
	ccieth_queue_busy_event(ep, event);

	dev_kfree_skb(skb);
	return 0;

out:
	dev_kfree_skb(skb);
	return err;
}

/* called under rcu_read_lock() */
static int
ccieth__recv_msg_reliable(struct ccieth_endpoint *ep, struct ccieth_connection *conn,
			  struct ccieth_pkt_header_msg *hdr, struct sk_buff *skb)
{
	struct ccieth_endpoint_event *event;
	__u32 msg_len = ntohl(hdr->msg_len);
	__u32 msg_seqnum = ntohl(hdr->msg_seqnum);
	__u32 relseqnum;
	unsigned relfull = 0;
	int force_delayed_ack = 0;
	int force_immediate_ack = 0;
	int err;

	/* get an event */
	event = ccieth_get_free_event(ep);
	if (unlikely(!event)) {
		/* don't ack, we need a resend */
		err = -ENOBUFS;
		dprintk("ccieth: no event slot for msg\n");
		goto out;
	}

	/* setup the event */
	event->event.type = CCIETH_IOCTL_EVENT_RECV;
	event->event.data_length = msg_len;
	event->event.recv.user_conn_id = conn->user_conn_id;

	err = skb_copy_bits(skb, sizeof(*hdr), event+1, msg_len);
	BUG_ON(err < 0);

	spin_lock_bh(&conn->recv_lock);

	CCIETH_STAT_INC(conn, recv);

	/* reliable, look for obsolete, duplicates, ... */

	dprintk("got MSG seqnum %u while we have %u+%x\n",
		msg_seqnum, conn->recv_last_full_seqnum, conn->recv_next_bitmap);

	relseqnum = msg_seqnum - conn->recv_last_full_seqnum - 1; /* 0 if the next expected seqnum */
	if (unlikely(relseqnum >= CCIETH_CONN_RECV_BITMAP_BITS)) {
		/* not in the window of next expected seqnums */
		if (ccieth_seqnum_positive(relseqnum))
			/* way in advance, drop */
			CCIETH_STAT_INC(conn, recv_tooearly);
		else
			/* old duplicate, ignore */
			CCIETH_STAT_INC(conn, recv_duplicate);
		ccieth_putback_free_event(ep, event);
		force_delayed_ack = 1;
		goto done;
	}

	if (unlikely(conn->recv_next_bitmap & (1U << relseqnum))) {
		/* recent misordered duplicate, ignore */
		CCIETH_STAT_INC(conn, recv_duplicate);
		ccieth_putback_free_event(ep, event);
		force_delayed_ack = 1;
		goto done;
	}

	if (unlikely(relseqnum > 0)) {
		CCIETH_STAT_INC(conn, recv_misorder);
		/* force an immediate ack every once in a while when packets are out-of-order */
		if (!(relseqnum % 8))
			force_immediate_ack = 1;
	}

	/* deliver the event now that we verified everything ... */
	ccieth_queue_busy_event(ep, event);
	/* ... and update connection then */
	conn->recv_next_bitmap |= 1U << relseqnum;
	/* how many new fully received packets? */
	if (conn->recv_next_bitmap == ~0U) {
		relfull = 32;
		conn->recv_next_bitmap = 0;
	} else {
		unsigned long bitmap = conn->recv_next_bitmap;  /* ffz wants a ulong */
		relfull = ffz(bitmap); /* we know we have at least one zero, find the first one */
		conn->recv_next_bitmap >>= relfull;
	}
	conn->recv_last_full_seqnum += relfull;
	dprintk("found %u new fully received, now have %u+%x\n",
		relfull, conn->recv_last_full_seqnum, conn->recv_next_bitmap);
	conn->recv_needack_nr += relfull;

done:
	if (force_immediate_ack || force_delayed_ack)
		conn->recv_needack_force = 1;
	if (unlikely(conn->recv_needack_nr >= CCIETH_IMMEDIATE_MSG_ACK_NR
		     || force_immediate_ack)) {
		/* many non acked packets, we need to ack now */
		schedule_work(&conn->recv_needack_work);
	} else if (relfull || force_delayed_ack) {
		/* some new non acked packets, we need to ack at some point in the future */
		mod_timer(&conn->recv_needack_timer,
			  jiffies + CCIETH_DEFERRED_MSG_ACK_DELAY);
	}

	spin_unlock_bh(&conn->recv_lock);

	/* piggyback acks */
	ccieth_conn_handle_ack(conn, ntohl(hdr->acked_seqnum), 0);

	dev_kfree_skb(skb);
	return 0;

out:
	dev_kfree_skb(skb);
	return err;
}

static int
ccieth_recv_msg(struct net_device *ifp, struct sk_buff *skb)
{
	struct ccieth_pkt_header_msg _hdr, *hdr;
	struct ccieth_endpoint *ep;
	struct ccieth_connection *conn;
	__u32 dst_ep_id;
	__u32 dst_conn_id;
	__u32 msg_len;
	int err;

	/* copy the entire header */
	err = -EINVAL;
	hdr = skb_header_pointer(skb, 0, sizeof(_hdr), &_hdr);
	if (unlikely(!hdr))
		goto out;

	dst_ep_id = ntohl(hdr->dst_ep_id);
	dst_conn_id = ntohl(hdr->dst_conn_id);
	msg_len = ntohl(hdr->msg_len);

	dprintk("got msg len %d to eid %d conn id %d seqnum %u\n",
		msg_len, dst_ep_id, dst_conn_id, ntohl(hdr->msg_seqnum));

	rcu_read_lock();

	/* find endpoint and check that it's attached to this ifp */
	ep = idr_find(&ccieth_ep_idr, dst_ep_id);
	if (unlikely(!ep || rcu_access_pointer(ep->ifp) != ifp))
		goto out_with_rculock;

	/* check msg length */
	if (unlikely(msg_len > ep->max_send_size
		     || skb->len < sizeof(*hdr) + msg_len))
		goto out_with_rculock;

	/* find the connection */
	err = -EINVAL;
	conn = idr_find(&ep->connection_idr, dst_conn_id);
	if (unlikely(!conn))
		goto out_with_rculock;

	if (unlikely(conn->status != CCIETH_CONNECTION_READY))
		goto out_with_rculock;

	if (conn->flags & CCIETH_CONN_FLAG_RELIABLE)
		err = ccieth__recv_msg_reliable(ep, conn, hdr, skb);
	else
		err = ccieth__recv_msg_unreliable(ep, conn, hdr, skb);

	rcu_read_unlock();
	return err;

out_with_rculock:
	rcu_read_unlock();
out:
	dev_kfree_skb(skb);
	return err;
}

int
ccieth_msg_ack(struct ccieth_connection *conn)
{
	struct ccieth_endpoint *ep = conn->ep;
	struct net_device *ifp;
	struct sk_buff *skb;
	struct ccieth_pkt_header_msg_ack *hdr;
	size_t skblen;
	int err;

	/* allocate and initialize the skb */
	skblen = sizeof(*hdr);
	if (skblen < ETH_ZLEN)
		skblen = ETH_ZLEN;
	err = -ENOMEM;
	skb = alloc_skb(skblen, GFP_KERNEL);
	if (unlikely(!skb))
		goto out;
	skb_reset_mac_header(skb);
	skb_reset_network_header(skb);
	skb->protocol = __constant_htons(ETH_P_CCI);
	skb_put(skb, skblen);

	/* fill headers */
	hdr = (struct ccieth_pkt_header_msg_ack *)skb_mac_header(skb);
	memcpy(&hdr->eth.h_dest, &conn->dest_addr, 6);
	memcpy(&hdr->eth.h_source, ep->addr, 6);
	hdr->eth.h_proto = __constant_cpu_to_be16(ETH_P_CCI);
	hdr->type = CCIETH_PKT_MSG_ACK;
	hdr->dst_ep_id = htonl(conn->dest_eid);
	hdr->dst_conn_id = htonl(conn->dest_id);
	hdr->conn_seqnum = htonl(conn->req_seqnum);

	err = ccieth_conn_send_ack(conn, &hdr->acked_seqnum, &hdr->acked_bitmap);
	if (unlikely(err < 0))
		goto out_with_skb;

	CCIETH_STAT_INC(conn, ack_explicit);

	rcu_read_lock();
	/* is the interface still available? */
	ifp = rcu_dereference(ep->ifp);
	if (unlikely(!ifp)) {
		err = -ENODEV;
		goto out_with_rculock;
	}
	skb->dev = ifp;
	dev_queue_xmit(skb);
	rcu_read_unlock();
	return 0;

out_with_rculock:
	rcu_read_unlock();
out_with_skb:
	kfree_skb(skb);
out:
	return err;
}

static int
ccieth_recv_msg_ack(struct net_device *ifp, struct sk_buff *skb)
{
	struct ccieth_pkt_header_msg_ack _hdr, *hdr;
	struct ccieth_endpoint *ep;
	struct ccieth_connection *conn;
	__u32 dst_ep_id;
	__u32 dst_conn_id;
	__u32 acked_seqnum;
	__u32 acked_bitmap;
	int err;

	/* copy the entire header */
	err = -EINVAL;
	hdr = skb_header_pointer(skb, 0, sizeof(_hdr), &_hdr);
	if (unlikely(!hdr))
		goto out;

	dst_ep_id = ntohl(hdr->dst_ep_id);
	dst_conn_id = ntohl(hdr->dst_conn_id);
	acked_seqnum = ntohl(hdr->acked_seqnum);
	acked_bitmap = ntohl(hdr->acked_bitmap);

	dprintk("got msg ack for seqnum %u bitmap %04x to eid %d conn id %d\n",
		acked_seqnum, acked_bitmap, dst_ep_id, dst_conn_id);

	rcu_read_lock();

	/* find endpoint and check that it's attached to this ifp */
	ep = idr_find(&ccieth_ep_idr, dst_ep_id);
	if (unlikely(!ep || rcu_access_pointer(ep->ifp) != ifp))
		goto out_with_rculock;

	/* find the connection */
	err = -EINVAL;
	conn = idr_find(&ep->connection_idr, dst_conn_id);
	if (unlikely(!conn || !(conn->flags & CCIETH_CONN_FLAG_RELIABLE)))
		goto out_with_rculock;

	ccieth_conn_handle_ack(conn, acked_seqnum, acked_bitmap);

	rcu_read_unlock();

	dev_kfree_skb(skb);
	return 0;

out_with_rculock:
	rcu_read_unlock();
out:
	dev_kfree_skb(skb);
	return err;
}

int
ccieth_recv(struct sk_buff *skb, struct net_device *ifp, struct packet_type *pt,
	    struct net_device *orig_dev)
{
	__u8 type, *typep;
	int err = -EINVAL;

	skb = skb_share_check(skb, GFP_ATOMIC);
	if (unlikely(skb == NULL))
		return 0;

	/* len doesn't include header */
	skb_push(skb, ETH_HLEN);

	/* get type */
	typep = skb_header_pointer(skb, offsetof(struct ccieth_pkt_header_generic, type), sizeof(type), &type);
	if (unlikely(!typep))
		goto out;

	dprintk("got a packet with type %d\n", *typep);

	switch (*typep) {
	case CCIETH_PKT_CONNECT_REQUEST:
	case CCIETH_PKT_CONNECT_ACCEPT:
	case CCIETH_PKT_CONNECT_REJECT:
	case CCIETH_PKT_CONNECT_ACK:
		return ccieth_defer_connect_recv(ifp, *typep, skb);
	case CCIETH_PKT_MSG:
		return ccieth_recv_msg(ifp, skb);
	case CCIETH_PKT_MSG_ACK:
		return ccieth_recv_msg_ack(ifp, skb);
	default:
		err = -EINVAL;
		break;
	}

out:
	dev_kfree_skb(skb);
	return err;
}
