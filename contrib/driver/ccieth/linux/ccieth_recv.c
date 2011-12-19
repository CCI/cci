/*
 * CCI over Ethernet
 * Copyright © INRIA 2011
 */

#include <linux/netdevice.h>
#include <linux/rcupdate.h>

#include <ccieth_common.h>

static int
ccieth_recv(struct sk_buff *skb, struct net_device *ifp, struct packet_type *pt,
	    struct net_device *orig_dev)
{
	u32 eid;
	u8 pktype;
	struct ccieth_endpoint *ep;
	int err;

	skb = skb_share_check(skb, GFP_ATOMIC);
	if (unlikely(skb == NULL))
		return 0;

	/* len doesn't include header */
	skb_push(skb, ETH_HLEN);

	/* extract common headers TODO cleanup with an actual struct */
	err = skb_copy_bits(skb, sizeof(struct ethhdr), &eid, sizeof(eid));
	if (err)
		goto out;
	err = skb_copy_bits(skb, sizeof(struct ethhdr)+sizeof(eid), &pktype, sizeof(pktype));
	if (err)
		goto out;

	/* check endpoint is attached to this ifp */
	rcu_read_lock();
	ep = idr_find(&ccieth_ep_idr, eid);
	rcu_read_unlock();
	if (!ep || ep->ifp != ifp) {
		err = -EINVAL;
		goto out;
	}
		
	printk("got a packet\n");

	dev_kfree_skb(skb);
	return 0;

out:
	dev_kfree_skb(skb);
	return err;
}

struct packet_type ccieth_pt = {
	.type = __constant_htons(0x86df),
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
