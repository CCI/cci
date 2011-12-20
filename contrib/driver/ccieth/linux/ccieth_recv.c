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
		    struct ccieth_pkt_header *hdr, struct sk_buff *skb)
{
	struct ccieth_endpoint_event *event;

	event = kmalloc(sizeof(*event), GFP_KERNEL);
	if (!event)
		return -ENOMEM;

	event->event.type = CCIETH_IOCTL_EVENT_CONNECT_REQUEST;

	spin_lock(&ep->event_list_lock);
	list_add_tail(&event->list, &ep->event_list);
	spin_unlock(&ep->event_list_lock);
	return 0;
}

static int
ccieth_recv(struct sk_buff *skb, struct net_device *ifp, struct packet_type *pt,
	    struct net_device *orig_dev)
{
	struct ccieth_pkt_header hdr;
	struct ccieth_endpoint *ep;
	int err;

	skb = skb_share_check(skb, GFP_ATOMIC);
	if (unlikely(skb == NULL))
		return 0;

	/* len doesn't include header */
	skb_push(skb, ETH_HLEN);

	/* extract common headers */
	err = skb_copy_bits(skb, 0, &hdr, sizeof(hdr));
	if (err)
		goto out;

	/* check endpoint is attached to this ifp */
	rcu_read_lock();
	ep = idr_find(&ccieth_ep_idr, hdr.endpoint_id);
	rcu_read_unlock();
	if (!ep || ep->ifp != ifp) {
		err = -EINVAL;
		goto out;
	}

	printk("got a packet with ep %p type %d\n", ep, hdr.type);

	/* FIXME: take a ref on the endpoint, and change the destroy code to use kref if we can hot-remove interfaces */

	switch (hdr.type) {
	case CCIETH_PKT_CONNECT:
		err = ccieth_recv_connect(ifp, ep, &hdr, skb);
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
