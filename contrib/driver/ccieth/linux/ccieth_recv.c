/*
 * CCI over Ethernet
 * Copyright © INRIA 2011
 */

#include <linux/netdevice.h>
#include <linux/rcupdate.h>

#include <ccieth_common.h>
#include <ccieth_wire.h>

static int
ccieth_recv_connect(struct net_device *ifp, struct ccieth_endpoint *ep,
		    struct ccieth_pkt_header_connect *hdr, struct sk_buff *skb)
{
	struct ccieth_endpoint_event *event;
	__u32 src_ep_id = ntohl(hdr->src_ep_id);
	__u32 src_conn_id = ntohl(hdr->src_conn_id);
	__u32 data_len = ntohl(hdr->data_len);
	int err;

	printk("got conn request from eid %d conn id %d\n",
	       src_ep_id, src_conn_id);

	/* FIXME: check data_len <= MTU */

	event = kmalloc(sizeof(*event) + data_len, GFP_KERNEL);
	if (!event)
		return -ENOMEM;

	event->event.type = CCIETH_IOCTL_EVENT_CONNECT_REQUEST;
	event->event.data_length = data_len;

	err = skb_copy_bits(skb, sizeof(*hdr), event+1, data_len);
	if (err < 0) {
		kfree(event);
		return -ENOMEM;
	}

	spin_lock(&ep->event_list_lock);
	list_add_tail(&event->list, &ep->event_list);
	spin_unlock(&ep->event_list_lock);
	return 0;
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
	case CCIETH_PKT_CONNECT:
		/* copy entire header now */
		hdrp = skb_header_pointer(skb, 0, sizeof(hdr.connect), &hdr.connect);
		if (hdrp)
			err = ccieth_recv_connect(ifp, ep, &hdrp->connect, skb);
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
