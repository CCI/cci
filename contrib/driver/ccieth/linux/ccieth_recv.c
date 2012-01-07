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
	int id;
	int err;

	printk("processing queued connect request skb %p\n", skb);

	src_ep_id = ntohl(hdr->src_ep_id);
	src_conn_id = ntohl(hdr->src_conn_id);
	data_len = ntohl(hdr->data_len);
	src_max_send_size = ntohl(hdr->max_send_size);

	printk("got conn request from eid %d conn id %d\n",
	       src_ep_id, src_conn_id);

	/* check msg length */
	err = -EINVAL;
	if (data_len > ep->max_send_size)
		goto out;

	/* get an event */
	spin_lock(&ep->free_event_list_lock);
	if (list_empty(&ep->free_event_list)) {
		err = -ENOMEM;
		spin_unlock(&ep->free_event_list_lock);
		printk("ccieth: no event slot for connect request\n");
		goto out;
	}
	event = list_first_entry(&ep->free_event_list, struct ccieth_endpoint_event, list);
	list_del(&event->list);
	spin_unlock(&ep->free_event_list_lock);

	/* get a connection */
	conn = kmalloc(sizeof(*conn), GFP_KERNEL);
	if (!conn)
		goto out_with_event;

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
		}
		goto out_with_conn;
	}

	/* setup the event */
	event->event.type = CCIETH_IOCTL_EVENT_CONNECT_REQUEST;
	event->event.data_length = data_len;
	event->event.connect_request.attribute = hdr->attribute;
	event->event.connect_request.max_send_size = src_max_send_size < ep->max_send_size ? src_max_send_size : ep->max_send_size;
	err = skb_copy_bits(skb, sizeof(*hdr), event+1, data_len);
	if (err < 0)
		goto out_with_conn_id;

	/* things cannot fail anymore now */

	/* setup the connection */
	conn->status = CCIETH_CONNECTION_RECEIVED;
	memcpy(&conn->dest_addr, &hdr->eth.h_source, 6);
	conn->dest_eid = ntohl(hdr->src_ep_id);
	conn->dest_id = ntohl(hdr->src_conn_id);
	conn->id = id;
	idr_replace(&ep->connection_idr, conn, id);

	/* finalize and notify the event */
	event->event.connect_request.conn_id = id;
	spin_lock(&ep->event_list_lock);
	list_add_tail(&event->list, &ep->event_list);
	spin_unlock(&ep->event_list_lock);

	dev_kfree_skb(skb);
	return 0;

out_with_conn_id:
	spin_lock(&ep->connection_idr_lock);
	idr_remove(&ep->connection_idr, id);
	spin_unlock(&ep->connection_idr_lock);	
out_with_conn:
	kfree(conn);
out_with_event:
	spin_lock(&ep->free_event_list_lock);
	list_add_tail(&event->list, &ep->free_event_list);
	spin_unlock(&ep->free_event_list_lock);
out:
	dev_kfree_skb(skb);
	return err;
}

void
ccieth_recv_connect_request_workfunc(struct work_struct *work)
{
	struct ccieth_endpoint *ep = container_of(work, struct ccieth_endpoint, recv_connect_request_work);
	struct sk_buff *skb;

	printk("dequeueing queued connect request skbs\n");

	while ((skb = skb_dequeue(&ep->recv_connect_request_queue)) != NULL) {
		struct ccieth_pkt_header_connect_request _hdr, *hdr;
		int err;

		/* copy the entire header */
		hdr = skb_header_pointer(skb, 0, sizeof(_hdr), &_hdr);
		BUG_ON(!hdr); /* would have faild in ccieth_recv_connect_request() before schedule_work() */

		err = ccieth__recv_connect_request(ep, skb, hdr);
		if (err && err != -EINVAL) {
			/* not enough memory or events, other skbuffs will fail the same, drop everything for now */
			skb_queue_purge(&ep->recv_connect_request_queue);
			return;
		}
	}
}

static int
ccieth_recv_connect_request(struct net_device *ifp, struct sk_buff *skb)
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
	if (!ep || ep->ifp != ifp)
		goto out_with_rculock;

	printk("queueing connect request skb %p\n", skb);
	skb_queue_tail(&ep->recv_connect_request_queue, skb);
	schedule_work(&ep->recv_connect_request_work);

	rcu_read_unlock();
	return 0;

out_with_rculock:
	rcu_read_unlock();
out:
	dev_kfree_skb(skb);
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

	rcu_read_lock();

	/* find endpoint and check that it's attached to this ifp */
	ep = idr_find(&ccieth_ep_idr, dst_ep_id);
	if (!ep || ep->ifp != ifp)
		goto out_with_rculock;

	/* get an event */
	spin_lock(&ep->free_event_list_lock);
	if (list_empty(&ep->free_event_list)) {
		err = -ENOMEM;
		spin_unlock(&ep->free_event_list_lock);
		printk("ccieth: no event slot for connect accepted\n");
		goto out_with_rculock;
	}
	event = list_first_entry(&ep->free_event_list, struct ccieth_endpoint_event, list);
	list_del(&event->list);
	spin_unlock(&ep->free_event_list_lock);

	/* setup the event */
	event->event.type = CCIETH_IOCTL_EVENT_CONNECT_ACCEPTED;
	event->event.connect_accepted.conn_id = dst_conn_id;

	/* find the connection and update it */
	conn = idr_find(&ep->connection_idr, dst_conn_id);
	if (!conn)
                goto out_with_event;

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

	spin_lock(&ep->event_list_lock);
	list_add_tail(&event->list, &ep->event_list);
	spin_unlock(&ep->event_list_lock);

	rcu_read_unlock();

	dev_kfree_skb(skb);
	return 0;

out_with_conn:
	/* nothing */
out_with_event:
	spin_lock(&ep->free_event_list_lock);
	list_add_tail(&event->list, &ep->free_event_list);
	spin_unlock(&ep->free_event_list_lock);
out_with_rculock:
	rcu_read_unlock();
out:
	dev_kfree_skb(skb);
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

	rcu_read_lock();

	/* find endpoint and check that it's attached to this ifp */
	ep = idr_find(&ccieth_ep_idr, dst_ep_id);
	if (!ep || ep->ifp != ifp)
		goto out_with_rculock;

	/* check msg length */
	if (msg_len > ep->max_send_size)
		goto out_with_rculock;

	/* get an event */
	spin_lock(&ep->free_event_list_lock);
	if (list_empty(&ep->free_event_list)) {
		err = -ENOMEM;
		spin_unlock(&ep->free_event_list_lock);
		printk("ccieth: no event slot for msg\n");
		goto out_with_rculock;
	}
	event = list_first_entry(&ep->free_event_list, struct ccieth_endpoint_event, list);
	list_del(&event->list);
	spin_unlock(&ep->free_event_list_lock);

	/* setup the event */
	event->event.type = CCIETH_IOCTL_EVENT_RECV;
	event->event.data_length = msg_len;

	err = skb_copy_bits(skb, sizeof(*hdr), event+1, msg_len);
	if (err < 0)
		goto out_with_event;

	/* find the connection */
	conn = idr_find(&ep->connection_idr, dst_conn_id);
	if (!conn)
		goto out_with_event;

	/* finalize and notify the event */
	event->event.recv.user_conn_id = conn->user_conn_id;

	spin_lock(&ep->event_list_lock);
	list_add_tail(&event->list, &ep->event_list);
	spin_unlock(&ep->event_list_lock);

	rcu_read_unlock();

	dev_kfree_skb(skb);
	return 0;

out_with_event:
	spin_lock(&ep->free_event_list_lock);
	list_add_tail(&event->list, &ep->free_event_list);
	spin_unlock(&ep->free_event_list_lock);
out_with_rculock:
	rcu_read_unlock();
out:
	dev_kfree_skb(skb);
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
		return ccieth_recv_connect_request(ifp, skb);
	case CCIETH_PKT_CONNECT_ACCEPT:
		return ccieth_recv_connect_accept(ifp, skb);
	case CCIETH_PKT_MSG:
		return ccieth_recv_msg(ifp, skb);
	default:
		err = -EINVAL;
		break;
	}

out:
	dev_kfree_skb(skb);
	return err;
}

static struct packet_type ccieth_pt = {
	.type = __constant_htons(ETH_P_CCI),
	.func = ccieth_recv,
};

static void
ccieth_release_ifp_rcu(struct rcu_head *rcu_head)
{
	struct ccieth_endpoint *ep = container_of(rcu_head, struct ccieth_endpoint, release_ifp_rcu_head);
	dev_put(ep->release_ifp);
}

struct ccieth_netdevice_notifier_cbdata {
	struct net_device *ifp;
	unsigned long event;
};

static int ccieth_netdevice_notifier_idrforeach_cb(int id, void *p, void *_data)
{
	struct ccieth_endpoint *ep = p;
	struct ccieth_netdevice_notifier_cbdata *data = _data;
	struct net_device *ifp = data->ifp;
	unsigned long event = data->event;

	if (!ep || ep->ifp != ifp)
		return 0;

	if (event == NETDEV_CHANGEMTU) {
		if (ccieth_max_send_size(ifp->mtu) >= ep->max_send_size)
			return 0;
	} else if (event == NETDEV_CHANGEADDR) {
		if (!memcmp(ifp->dev_addr, ep->addr, 6))
			return 0;
	}

	if (cmpxchg(&ep->ifp, ifp, NULL) == ifp) {
		ep->release_ifp = ifp;
		call_rcu(&ep->release_ifp_rcu_head, ccieth_release_ifp_rcu);
	}

	return 0;
}

static int
ccieth_netdevice_notifier_cb(struct notifier_block *unused,
			     unsigned long event, void *ptr)
{
	struct ccieth_netdevice_notifier_cbdata data;

	switch (event) {
	case NETDEV_CHANGEMTU:
		/* if ccieth max_send_size becomes smaller, ... */
	case NETDEV_CHANGEADDR:
		/* if address changes, ... */
	case NETDEV_UNREGISTER:
		/* close endpoints and connections */
		printk("ccieth notifier event %ld\n", event);
		data.ifp = (struct net_device *) ptr;
		data.event = event;
		rcu_read_lock();
		idr_for_each(&ccieth_ep_idr, ccieth_netdevice_notifier_idrforeach_cb, &data);
		rcu_read_unlock();
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
