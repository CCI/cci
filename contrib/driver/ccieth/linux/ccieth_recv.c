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

/* called under rcu_read_lock() */
int
ccieth__recv_msg(struct ccieth_endpoint *ep, struct ccieth_connection *conn,
		 struct ccieth_pkt_header_msg *hdr, struct sk_buff *skb)
{
	struct ccieth_endpoint_event *event;
	__u32 msg_len = ntohl(hdr->msg_len);
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

	spin_lock_bh(&ep->event_list_lock);
	list_add_tail(&event->list, &ep->event_list);
	spin_unlock_bh(&ep->event_list_lock);

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
	__u32 msg_seqnum;
	__u32 msg_len;
	int err;

	/* copy the entire header */
	err = -EINVAL;
	hdr = skb_header_pointer(skb, 0, sizeof(_hdr), &_hdr);
	if (!hdr)
		goto out;

	dst_ep_id = ntohl(hdr->dst_ep_id);
	dst_conn_id = ntohl(hdr->dst_conn_id);
	msg_seqnum = ntohl(hdr->msg_seqnum);
	msg_len = ntohl(hdr->msg_len);

	dprintk("got msg len %d to eid %d conn id %d seqnum %d\n",
		msg_len, dst_ep_id, dst_conn_id, msg_seqnum);

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
		   && conn->attribute == CCIETH_CONNECT_ATTR_UU) {
		ccieth_conn_uu_defer_recv_msg(conn, skb);
		err = 0;
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

	dprintk("got a packet with type %d\n", *typep);

	switch (*typep) {
	case CCIETH_PKT_CONNECT_REQUEST:
	case CCIETH_PKT_CONNECT_ACCEPT:
	case CCIETH_PKT_CONNECT_REJECT:
	case CCIETH_PKT_CONNECT_ACK:
		return ccieth_defer_connect_recv(ifp, *typep, skb);
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

	if (!ep || rcu_access_pointer(ep->ifp) != ifp)
		return 0;

	if (event == NETDEV_CHANGEMTU) {
		if (ccieth_max_send_size(ifp->mtu) >= ep->max_send_size)
			return 0;
	} else if (event == NETDEV_CHANGEADDR) {
		if (!memcmp(ifp->dev_addr, ep->addr, 6))
			return 0;
	}

	if (cmpxchg((struct net_device __force **)&ep->ifp, ifp, NULL) == ifp) {
		ep->release_ifp = ifp;
		call_rcu(&ep->release_ifp_rcu_head, ccieth_release_ifp_rcu);

		ep->embedded_event.event.type = CCIETH_IOCTL_EVENT_DEVICE_FAILED;
		ep->embedded_event.event.data_length = 0;
		spin_lock_bh(&ep->event_list_lock);
		list_add_tail(&ep->embedded_event.list, &ep->event_list);
		spin_unlock_bh(&ep->event_list_lock);
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
		dprintk("ccieth notifier event %ld\n", event);
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
