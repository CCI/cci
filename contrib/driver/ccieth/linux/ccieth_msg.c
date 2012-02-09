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
ccieth_conn_send_ack(struct ccieth_connection *conn, __be32 *seqnum)
{
	int ret;
	spin_lock_bh(&conn->recv_lock);
	ret = conn->recv_needack_nr;
	*seqnum = htonl(conn->recv_last_full_seqnum);
	conn->recv_needack_nr = 0;
	spin_unlock_bh(&conn->recv_lock);
	return ret ? 0 : -EAGAIN;
}

static void
ccieth_conn_handle_ack(struct ccieth_connection *conn, __u32 acked_seqnum)
{
	struct sk_buff *skb, *nskb;
	spin_lock_bh(&conn->send_lock);
	skb = conn->send_queue_first;
	while (skb != NULL) {
		struct ccieth_msg_skb_cb *scb = CCIETH_MSG_SKB_CB(skb);
		nskb = skb->next;
		if (scb->seqnum <= acked_seqnum) {
			if (skb == conn->send_queue_first)
				conn->send_queue_first = nskb;
			else
				skb->prev->next = nskb;
			if (skb == conn->send_queue_last)
				conn->send_queue_last = skb->prev;
			else
				skb->next->prev = skb->prev;
			kfree_skb(skb);
			dprintk("no need to resend MSG skb %p anymore\n", skb);
		}
		skb = nskb;
	}
	spin_unlock_bh(&conn->send_lock);
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
	if (arg->msg_len > ep->max_send_size)
		goto out;

	/* allocate and initialize the skb */
	skblen = sizeof(*hdr) + arg->msg_len;
	if (skblen < ETH_ZLEN)
		skblen = ETH_ZLEN;
	if (arg->internal_flags & CCIETH_MSG_FLAG_RELIABLE)
		skb = alloc_skb_fclone(skblen, GFP_KERNEL);
	else
		skb = alloc_skb(skblen, GFP_KERNEL);
	if (!skb)
		goto out;
	skb_reset_mac_header(skb);
	skb_reset_network_header(skb);
	skb->protocol = __constant_htons(ETH_P_CCI);
	skb_put(skb, skblen);
	/* reliable sends need a clone */
	if (arg->internal_flags & CCIETH_MSG_FLAG_RELIABLE) {
		skb2 = skb_clone(skb, GFP_KERNEL);
		if (!skb2)
			goto out_with_skb;
	}

	/* copy data while not holding RCU read lock yet */
	hdr = (struct ccieth_pkt_header_msg *) skb_mac_header(skb);
	err = copy_from_user(&hdr->msg, (const void __user *)(uintptr_t) arg->msg_ptr, arg->msg_len);
	if (err) {
		err = -EFAULT;
		goto out_with_skb2;
	}

	rcu_read_lock();

	/* is the interface still available? */
	ifp = rcu_dereference(ep->ifp);
	if (!ifp) {
		err = -ENODEV;
		goto out_with_rculock;
	}

	/* find connection */
	conn = idr_find(&ep->connection_idr, arg->conn_id);
	if (!conn || conn->status != CCIETH_CONNECTION_READY)
		goto out_with_rculock;
	/* check that the user-space reliable hint was valid */
	if (!!(arg->internal_flags & CCIETH_MSG_FLAG_RELIABLE)
	    != !!(conn->flags & CCIETH_CONN_FLAG_RELIABLE))
		goto out_with_rculock;

	/* get an event */
	spin_lock_bh(&ep->free_event_list_lock);
	if (list_empty(&ep->free_event_list)) {
		err = -ENOMEM;
		spin_unlock_bh(&ep->free_event_list_lock);
		dprintk("ccieth: no event slot for send\n");
		goto out_with_rculock;
	}
	event = list_first_entry(&ep->free_event_list, struct ccieth_endpoint_event, list);
	list_del(&event->list);
	spin_unlock_bh(&ep->free_event_list_lock);

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


	if (conn->flags & CCIETH_CONN_FLAG_RELIABLE) {
		struct ccieth_msg_skb_cb *scb = CCIETH_MSG_SKB_CB(skb);
		__u32 seqnum;
		BUILD_BUG_ON(sizeof(*scb) > sizeof(skb->cb));

		spin_lock_bh(&conn->send_lock);
		seqnum = conn->send_next_seqnum++;
		hdr->msg_seqnum = htonl(seqnum);
		scb->seqnum = seqnum;
		if (conn->send_queue_last) {
			conn->send_queue_last->next = skb;
			skb->prev = conn->send_queue_last;
		} else {
			conn->send_queue_first = skb;
			skb->prev = NULL;
		}
		conn->send_queue_last = skb;
		skb->next = NULL;
		dprintk("need to resend MSG skb %p\n", skb);
		spin_unlock_bh(&conn->send_lock);

		ccieth_conn_send_ack(conn, &hdr->acked_seqnum);

		skb2->dev = ifp;
		dev_queue_xmit(skb2);
	} else {
#ifdef CCIETH_DEBUG
		hdr->msg_seqnum = htonl(-1);
#endif
		skb->dev = ifp;
		dev_queue_xmit(skb);
	}

	/* finalize and notify the event */
	event->event.send.status = 0;
	spin_lock_bh(&ep->event_list_lock);
	list_add_tail(&event->list, &ep->event_list);
	spin_unlock_bh(&ep->event_list_lock);

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
int
ccieth__recv_msg(struct ccieth_endpoint *ep, struct ccieth_connection *conn,
		 struct ccieth_pkt_header_msg *hdr, struct sk_buff *skb)
{
	struct ccieth_endpoint_event *event;
	__u32 msg_len = ntohl(hdr->msg_len);
	__u32 msg_seqnum = ntohl(hdr->msg_seqnum);
	int err;

	/* get an event */
	err = -ENOMEM;
	spin_lock_bh(&ep->free_event_list_lock);
	if (list_empty(&ep->free_event_list)) {
		spin_unlock_bh(&ep->free_event_list_lock);
		dprintk("ccieth: no event slot for msg\n");
		goto out;
	}
	event = list_first_entry(&ep->free_event_list, struct ccieth_endpoint_event, list);
	list_del(&event->list);
	spin_unlock_bh(&ep->free_event_list_lock);

	/* setup the event */
	event->event.type = CCIETH_IOCTL_EVENT_RECV;
	event->event.data_length = msg_len;

	err = skb_copy_bits(skb, sizeof(*hdr), event+1, msg_len);
	BUG_ON(err < 0);

	/* finalize and notify the event */
	event->event.recv.user_conn_id = conn->user_conn_id;

	if (conn->flags & CCIETH_CONN_FLAG_RELIABLE) {
		/* reliable, look for obsolete, duplicates, ... */
		__u32 relseqnum;
		int relfull;

		spin_lock_bh(&conn->recv_lock);
		dprintk("got %d while we have %d+%lx\n",
			msg_seqnum, conn->recv_last_full_seqnum, conn->recv_next_bitmap);
		relseqnum = msg_seqnum - conn->recv_last_full_seqnum - 1;
		if (relseqnum > CCIETH_CONN_RECV_BITMAP_BITS)
			/* way in advance (or very old), drop */
			goto out_with_recv_lock;
		if (conn->recv_next_bitmap & (1ULL << relseqnum))
			/* duplicate, ignore */
			goto out_with_recv_lock;
		conn->recv_next_bitmap |= 1ULL << relseqnum;
		/* how many new fully received packets? */
		relfull = find_first_zero_bit(&conn->recv_next_bitmap, CCIETH_CONN_RECV_BITMAP_BITS);
		conn->recv_next_bitmap >>= relfull;
		conn->recv_last_full_seqnum += relfull;
		dprintk("found %d new fully received, now have %d+%lx\n",
			relfull, conn->recv_last_full_seqnum, conn->recv_next_bitmap);
		conn->recv_needack_nr += relfull;
		if (conn->recv_needack_nr >= CCIETH_IMMEDIATE_MSG_ACK_NR) {
			/* many non acked packets, we need to ack now */
			schedule_work(&conn->recv_needack_work);
		} else if (relfull) {
			/* some new non acked packets, we need to ack at some point in the future */
			mod_timer(&conn->recv_needack_timer,
				  jiffies + CCIETH_DEFERRED_MSG_ACK_DELAY);
		}
		spin_unlock_bh(&conn->recv_lock);

		/* piggyback acks */
		ccieth_conn_handle_ack(conn, ntohl(hdr->acked_seqnum));
	}

	/* FIXME: deliver the event before doing all the reliability thing ? */
	spin_lock_bh(&ep->event_list_lock);
	list_add_tail(&event->list, &ep->event_list);
	spin_unlock_bh(&ep->event_list_lock);

	dev_kfree_skb(skb);
	return 0;

out_with_recv_lock:
	ccieth_conn_handle_ack(conn, ntohl(hdr->acked_seqnum));
	spin_unlock_bh(&conn->recv_lock);
	spin_lock_bh(&ep->free_event_list_lock);
	list_add_tail(&event->list, &ep->free_event_list);
	spin_unlock_bh(&ep->free_event_list_lock);
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
	if (!hdr)
		goto out;

	dst_ep_id = ntohl(hdr->dst_ep_id);
	dst_conn_id = ntohl(hdr->dst_conn_id);
	msg_len = ntohl(hdr->msg_len);

	dprintk("got msg len %d to eid %d conn id %d seqnum %d\n",
		msg_len, dst_ep_id, dst_conn_id, ntohl(hdr->msg_seqnum));

	rcu_read_lock();

	/* find endpoint and check that it's attached to this ifp */
	ep = idr_find(&ccieth_ep_idr, dst_ep_id);
	if (!ep || rcu_access_pointer(ep->ifp) != ifp)
		goto out_with_rculock;

	/* check msg length */
	if (msg_len > ep->max_send_size
	    || skb->len < sizeof(*hdr) + msg_len)
		goto out_with_rculock;

	/* find the connection */
	err = -EINVAL;
	conn = idr_find(&ep->connection_idr, dst_conn_id);
	if (!conn)
		goto out_with_rculock;

	if (conn->status == CCIETH_CONNECTION_READY) {
		err = ccieth__recv_msg(ep, conn, hdr, skb);
	} else if (conn->status == CCIETH_CONNECTION_REQUESTED
		   && (conn->flags & CCIETH_CONN_FLAG_DEFER_EARLY_MSG)) {
		ccieth_conn_uu_defer_recv_msg(conn, skb);
		err = 0;
		/* UU doesn't need ack */
	} else
		goto out_with_rculock;

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
	if (!skb)
		goto out;
	skb_reset_mac_header(skb);
	skb_reset_network_header(skb);
	skb->protocol = __constant_htons(ETH_P_CCI);
	skb_put(skb, skblen);

	/* fill headers */
	hdr = (struct ccieth_pkt_header_msg_ack *) skb_mac_header(skb);
	memcpy(&hdr->eth.h_dest, &conn->dest_addr, 6);
	memcpy(&hdr->eth.h_source, ep->addr, 6);
	hdr->eth.h_proto = __constant_cpu_to_be16(ETH_P_CCI);
	hdr->type = CCIETH_PKT_MSG_ACK;
	hdr->dst_ep_id = htonl(conn->dest_eid);
	hdr->dst_conn_id = htonl(conn->dest_id);
	hdr->conn_seqnum = htonl(conn->req_seqnum);

	err = ccieth_conn_send_ack(conn, &hdr->acked_seqnum);
	if (err < 0)
		goto out_with_skb;

	rcu_read_lock();
	/* is the interface still available? */
	ifp = rcu_dereference(ep->ifp);
	if (!ifp) {
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
	int err;

	/* copy the entire header */
	err = -EINVAL;
	hdr = skb_header_pointer(skb, 0, sizeof(_hdr), &_hdr);
	if (!hdr)
		goto out;

	dst_ep_id = ntohl(hdr->dst_ep_id);
	dst_conn_id = ntohl(hdr->dst_conn_id);
	acked_seqnum = ntohl(hdr->acked_seqnum);

	dprintk("got msg ack for seqnum %d to eid %d conn id %d\n",
		acked_seqnum, dst_ep_id, dst_conn_id);

	rcu_read_lock();

	/* find endpoint and check that it's attached to this ifp */
	ep = idr_find(&ccieth_ep_idr, dst_ep_id);
	if (!ep || rcu_access_pointer(ep->ifp) != ifp)
		goto out_with_rculock;

	/* find the connection */
	err = -EINVAL;
	conn = idr_find(&ep->connection_idr, dst_conn_id);
	if (!conn || !(conn->flags & CCIETH_CONN_FLAG_RELIABLE))
		goto out_with_rculock;

	ccieth_conn_handle_ack(conn, acked_seqnum);

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
	if (!typep)
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
