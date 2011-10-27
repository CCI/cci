/*
 * CCI over Ethernet
 * Copyright © INRIA 2011
 */

#include <linux/netdevice.h>

static int
ccieth_recv(struct sk_buff *skb, struct net_device *ifp, struct packet_type *pt,
	    struct net_device *orig_dev)
{
        skb = skb_share_check(skb, GFP_ATOMIC);
        if (unlikely(skb == NULL))
                return 0;

        /* len doesn't include header */
        skb_push(skb, ETH_HLEN);

	/* FIXME: find endpoint */

	/* FIXME: check endpoint is attached to this ifp ? */

	printk("got a packet\n");

	dev_kfree_skb(skb);
        return 0;
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
