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

static int ccieth_recv_connect_idrforeach_cb(int id, void *p, void *data)
{
	struct ccieth_connection *conn = p, *new = data;
	/* return -EBUSY in case of duplicate incoming connect.
	 * it may even already be accepted or rejcted.
	 */
	if (conn->status != CCIETH_CONNECTION_REQUESTED /* so that dest_id is valid */
	    && !memcmp(&conn->dest_addr, &new->dest_addr, 6)
	    && conn->dest_eid == new->dest_eid
	    && conn->dest_id == new->dest_id)
		return -EBUSY;
	return 0;
}

static int
ccieth_recv_connect_request(struct net_device *ifp, struct ccieth_endpoint *ep,
			    struct ccieth_pkt_header_connect_request *hdr, struct sk_buff *skb)
{
	struct ccieth_endpoint_event *event;
	struct ccieth_connection *conn;
	__u32 src_ep_id = ntohl(hdr->src_ep_id);
	__u32 src_conn_id = ntohl(hdr->src_conn_id);
	__u32 data_len = ntohl(hdr->data_len);
	__u32 src_max_send_size = ntohl(hdr->max_send_size);
	int err;

	printk("got conn request from eid %d conn id %d\n",
	       src_ep_id, src_conn_id);

	err = -EINVAL;
	if (data_len >= ep->max_send_size)
		goto out;

	/* setup the event */
	err = -ENOMEM;
	event = kmalloc(sizeof(*event) + data_len, GFP_KERNEL);
	if (!event)
		goto out;
	event->event.type = CCIETH_IOCTL_EVENT_CONNECT_REQUEST;
	event->event.data_length = data_len;
	event->event.connect_request.attribute = hdr->attribute;
	event->event.connect_request.max_send_size = src_max_send_size < ep->max_send_size ? src_max_send_size : ep->max_send_size;

	err = -EINVAL;
	err = skb_copy_bits(skb, sizeof(*hdr), event+1, data_len);
	if (err < 0)
		goto out_with_event;

	/* setup the connection */
	conn = kmalloc(sizeof(*conn), GFP_KERNEL);
	if (!conn)
		goto out_with_event;
	conn->status = CCIETH_CONNECTION_RECEIVED;
	memcpy(&conn->dest_addr, &hdr->eth.h_source, 6);
	conn->dest_eid = ntohl(hdr->src_ep_id);
	conn->dest_id = ntohl(hdr->src_conn_id);
retry:
	spin_lock(&ep->connection_idr_lock);
	/* check for duplicates */
	err = idr_for_each(&ep->connection_idr, ccieth_recv_connect_idrforeach_cb, conn);
	if (err != -EBUSY)
		/* if no duplicates, try to add new connection */
		err = idr_get_new(&ep->connection_idr, conn, &conn->id);
	spin_unlock(&ep->connection_idr_lock);
	if (err < 0) {
		if (err == -EAGAIN) {
			if (idr_pre_get(&ep->connection_idr, GFP_KERNEL) > 0)
				goto retry;
			err = -ENOMEM;
		}
		goto out_with_conn;
	}

	/* finalize and notify the event */
	event->event.connect_request.conn_id = conn->id;
	spin_lock(&ep->event_list_lock);
	list_add_tail(&event->list, &ep->event_list);
	spin_unlock(&ep->event_list_lock);
	return 0;

out_with_conn:
	kfree(conn);
out_with_event:
	kfree(event);
out:
	return err;
}

static int
ccieth_recv_connect_accept(struct net_device *ifp, struct ccieth_endpoint *ep,
			   struct ccieth_pkt_header_connect_accept *hdr)
{
	struct ccieth_endpoint_event *event;
	struct ccieth_connection *conn;
	__u32 src_conn_id = ntohl(hdr->src_conn_id);
	__u32 src_ep_id = ntohl(hdr->src_ep_id);
	__u32 dst_conn_id = ntohl(hdr->dst_conn_id);
	__u32 dst_ep_id = ntohl(hdr->dst_ep_id);
	__u32 max_send_size = ntohl(hdr->max_send_size);
	int err;

	printk("got conn accept from eid %d conn id %d to %d %d\n",
	       src_ep_id, src_conn_id, dst_ep_id, dst_conn_id);

	/* setup the event */
	err = -ENOMEM;
	event = kmalloc(sizeof(*event), GFP_KERNEL);
	if (!event)
		goto out;
	event->event.type = CCIETH_IOCTL_EVENT_CONNECT_ACCEPTED;
	event->event.connect_accepted.conn_id = dst_conn_id;

	/* find the connection and update it */
	err = -EINVAL;
	rcu_read_lock();
	conn = idr_find(&ep->connection_idr, dst_conn_id);
	/* FIXME: take a reference */
	rcu_read_unlock();
	if (!conn)
		goto out_with_event;

	if (cmpxchg(&conn->status, CCIETH_CONNECTION_REQUESTED, CCIETH_CONNECTION_READY)
	    != CCIETH_CONNECTION_REQUESTED)
		goto out_with_conn;

	conn->dest_id = src_conn_id;
	conn->max_send_size = max_send_size;
	/* FIXME: release ref */

	/* finalize and notify the event */
	event->event.connect_accepted.attribute = conn->attribute;
	event->event.connect_accepted.context = conn->context;
	event->event.connect_accepted.max_send_size = max_send_size;
	spin_lock(&ep->event_list_lock);
	list_add_tail(&event->list, &ep->event_list);
	spin_unlock(&ep->event_list_lock);
	return 0;

out_with_conn:
	/* FIXME: release ref */
out_with_event:
	kfree(event);
out:
	return err;
}

static int
ccieth_recv(struct sk_buff *skb, struct net_device *ifp, struct packet_type *pt,
	    struct net_device *orig_dev)
{
	union ccieth_pkt_header hdr, *hdrp;
	struct ccieth_endpoint *ep;
	int err = -EINVAL;

	skb = skb_share_check(skb, GFP_ATOMIC);
	if (unlikely(skb == NULL))
		return 0;

	/* len doesn't include header */
	skb_push(skb, ETH_HLEN);

	/* get common headers */
	hdrp = skb_header_pointer(skb, 0, sizeof(hdr.generic), &hdr.generic);
	if (!hdrp)
		goto out;

	/* check endpoint is attached to this ifp */
	rcu_read_lock();
	ep = idr_find(&ccieth_ep_idr, ntohl(hdrp->generic.dst_ep_id));
	rcu_read_unlock();
	if (!ep || ep->ifp != ifp) {
		err = -EINVAL;
		goto out;
	}

	printk("got a packet with ep %p type %d\n", ep, hdrp->generic.type);

	/* FIXME: take a ref on the endpoint, and change the destroy code to use kref if we can hot-remove interfaces */

	switch (hdrp->generic.type) {
	case CCIETH_PKT_CONNECT_REQUEST:
		/* copy entire header now */
		hdrp = skb_header_pointer(skb, 0, sizeof(hdr.connect), &hdr.connect);
		if (hdrp)
			err = ccieth_recv_connect_request(ifp, ep, &hdrp->connect, skb);
		break;
	case CCIETH_PKT_CONNECT_ACCEPT:
		/* copy entire header now */
		hdrp = skb_header_pointer(skb, 0, sizeof(hdr.accept), &hdr.accept);
		if (hdrp)
			err = ccieth_recv_connect_accept(ifp, ep, &hdrp->accept);
		break;
	default:
		err = -EINVAL;
		break;
	}

	/* FIXME: release ref on endpoint */

out:
	dev_kfree_skb(skb);
	return err;
}

struct packet_type ccieth_pt = {
	.type = __constant_htons(ETH_P_CCI),
	.func = ccieth_recv,
};

void
ccieth_recv_init(void)
{
	dev_add_pack(&ccieth_pt);
}

void
ccieth_recv_exit(void)
{
	dev_remove_pack(&ccieth_pt);
}
