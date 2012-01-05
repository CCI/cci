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
ccieth_recv_connect_request(struct net_device *ifp, struct sk_buff *skb)
{
	struct ccieth_pkt_header_connect_request _hdr, *hdr;
	struct ccieth_endpoint *ep;
	struct ccieth_endpoint_event *event;
	struct ccieth_connection *conn;
	__u32 src_ep_id;
	__u32 dst_ep_id;
	__u32 src_conn_id;
	__u32 data_len;
	__u32 src_max_send_size;
	int err;

	/* copy the entire header */
	err = -EINVAL;
	hdr = skb_header_pointer(skb, 0, sizeof(_hdr), &_hdr);
	if (!hdr)
		goto out;

	src_ep_id = ntohl(hdr->src_ep_id);
	dst_ep_id = ntohl(hdr->dst_ep_id);
	src_conn_id = ntohl(hdr->src_conn_id);
	data_len = ntohl(hdr->data_len);
	src_max_send_size = ntohl(hdr->max_send_size);

	printk("got conn request from eid %d conn id %d\n",
	       src_ep_id, src_conn_id);

	/* find endpoint and check that it's attached to this ifp */
	rcu_read_lock();
	ep = idr_find(&ccieth_ep_idr, dst_ep_id);
	/* FIXME: keep rcu locked until conn is acquired */
	rcu_read_unlock();
	if (!ep || ep->ifp != ifp)
		goto out;

	/* check msg length */
	if (data_len > ep->max_send_size)
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
	kref_init(&conn->refcount);
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
ccieth_recv_connect_accept(struct net_device *ifp, struct sk_buff *skb)
{
	struct ccieth_pkt_header_connect_accept _hdr, *hdr;
	struct ccieth_endpoint *ep;
	struct ccieth_endpoint_event *event;
	struct ccieth_connection *conn;
	__u32 src_conn_id;
	__u32 src_ep_id;
	__u32 dst_conn_id;
	__u32 dst_ep_id;
	__u32 max_send_size;
	int err;

	/* copy the entire header */
	err = -EINVAL;
	hdr = skb_header_pointer(skb, 0, sizeof(_hdr), &_hdr);
	if (!hdr)
		goto out;

	src_conn_id = ntohl(hdr->src_conn_id);
	src_ep_id = ntohl(hdr->src_ep_id);
	dst_conn_id = ntohl(hdr->dst_conn_id);
	dst_ep_id = ntohl(hdr->dst_ep_id);
	max_send_size = ntohl(hdr->max_send_size);

	printk("got conn accept from eid %d conn id %d to %d %d\n",
	       src_ep_id, src_conn_id, dst_ep_id, dst_conn_id);

	/* find endpoint and check that it's attached to this ifp */
	rcu_read_lock();
	ep = idr_find(&ccieth_ep_idr, dst_ep_id);
	/* FIXME: keep rcu locked until conn is acquired */
	rcu_read_unlock();
	if (!ep || ep->ifp != ifp)
		goto out;

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
	if (!conn) {
		rcu_read_unlock();
                goto out_with_event;
	}
	kref_get(&conn->refcount);
	rcu_read_unlock();

	if (cmpxchg(&conn->status, CCIETH_CONNECTION_REQUESTED, CCIETH_CONNECTION_READY)
	    != CCIETH_CONNECTION_REQUESTED)
		goto out_with_conn;

	/* setup connection */
	conn->dest_id = src_conn_id;
	conn->max_send_size = max_send_size;

	/* finalize and notify the event */
	event->event.connect_accepted.attribute = conn->attribute;
	event->event.connect_accepted.max_send_size = max_send_size;
	event->event.connect_accepted.user_conn_id = conn->user_conn_id;

	kref_put(&conn->refcount, __ccieth_connection_lastkref);

	spin_lock(&ep->event_list_lock);
	list_add_tail(&event->list, &ep->event_list);
	spin_unlock(&ep->event_list_lock);
	return 0;

out_with_conn:
	kref_put(&conn->refcount, __ccieth_connection_lastkref);
out_with_event:
	kfree(event);
out:
	return err;
}

static int
ccieth_recv_msg(struct net_device *ifp, struct sk_buff *skb)
{
	struct ccieth_pkt_header_msg _hdr, *hdr;
	struct ccieth_endpoint *ep;
	struct ccieth_endpoint_event *event;
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

	printk("got msg len %d to eid %d conn id %d\n",
	       msg_len, dst_ep_id, dst_conn_id);

	/* find endpoint and check that it's attached to this ifp */
	rcu_read_lock();
	ep = idr_find(&ccieth_ep_idr, dst_ep_id);
	/* FIXME: keep rcu locked until conn is acquired */
	rcu_read_unlock();
	if (!ep || ep->ifp != ifp)
		goto out;

	/* check msg length */
	if (msg_len > ep->max_send_size)
		goto out;

	/* setup the event */
	err = -ENOMEM;
	event = kmalloc(sizeof(*event) + msg_len, GFP_KERNEL);
	if (!event)
		goto out;
	event->event.type = CCIETH_IOCTL_EVENT_RECV;
	event->event.data_length = msg_len;

	err = -EINVAL;
	err = skb_copy_bits(skb, sizeof(*hdr), event+1, msg_len);
	if (err < 0)
		goto out_with_event;

	/* find the connection and update it */
	err = -EINVAL;
	rcu_read_lock();
	conn = idr_find(&ep->connection_idr, dst_conn_id);
	if (!conn) {
		rcu_read_unlock();
		goto out_with_event;
	}
	kref_get(&conn->refcount);
	rcu_read_unlock();

	/* finalize and notify the event */
	event->event.recv.user_conn_id = conn->user_conn_id;

	kref_put(&conn->refcount, __ccieth_connection_lastkref);

	spin_lock(&ep->event_list_lock);
	list_add_tail(&event->list, &ep->event_list);
	spin_unlock(&ep->event_list_lock);
	return 0;

out_with_event:
	kfree(event);
out:
	return err;
}

static int
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

	printk("got a packet with type %d\n", *typep);

	switch (*typep) {
	case CCIETH_PKT_CONNECT_REQUEST:
		err = ccieth_recv_connect_request(ifp, skb);
		break;
	case CCIETH_PKT_CONNECT_ACCEPT:
		err = ccieth_recv_connect_accept(ifp, skb);
		break;
	case CCIETH_PKT_MSG:
		err = ccieth_recv_msg(ifp, skb);
		break;
	default:
		err = -EINVAL;
		break;
	}

out:
	dev_kfree_skb(skb);
	return err;
}

struct packet_type ccieth_pt = {
	.type = __constant_htons(ETH_P_CCI),
	.func = ccieth_recv,
};

static int
ccieth_netdevice_notifier_cb(struct notifier_block *unused,
			     unsigned long event, void *ptr)
{
	switch (event) {
	case NETDEV_CHANGEMTU:
		/* if ccieth max_send_size becomes smaller, close endpoints and connections? */
	case NETDEV_CHANGEADDR:
	case NETDEV_UNREGISTER:
		/* close endpoints and connections */
		printk("ccieth notifier event %ld\n", event);
	}		

	return NOTIFY_DONE;
}

static struct notifier_block ccieth_netdevice_notifier = {
        .notifier_call = ccieth_netdevice_notifier_cb,
};

int
ccieth_net_init(void)
{
	int ret;

        ret = register_netdevice_notifier(&ccieth_netdevice_notifier);
        if (ret < 0)
                goto out;

	dev_add_pack(&ccieth_pt);

	return 0;

out:
	return ret;
}

void
ccieth_net_exit(void)
{
	dev_remove_pack(&ccieth_pt);
	unregister_netdevice_notifier(&ccieth_netdevice_notifier);
}
