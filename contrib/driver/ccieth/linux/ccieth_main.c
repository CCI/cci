/*
 * CCI over Ethernet
 *
 * Copyright © 2011-2012 Inria.  All rights reserved.
 * $COPYRIGHT$
 */

#include <linux/module.h>
#include <linux/miscdevice.h>
#include <linux/fs.h>
#include <linux/uaccess.h>
#include <linux/types.h>
#include <linux/netdevice.h>
#include <linux/if_arp.h>
#include <linux/pci.h>
#include <linux/spinlock.h>
#include <linux/rcupdate.h>

#include <ccieth_io.h>
#include <ccieth_common.h>
#include <ccieth_wire.h>

struct idr ccieth_ep_idr;
static spinlock_t ccieth_ep_idr_lock;

static void
ccieth_destroy_connection_rcu(struct rcu_head *rcu_head)
{
        struct ccieth_connection *conn = container_of(rcu_head, struct ccieth_connection, destroy_rcu_head);
	printk("destroying connection %p in rcu call\n", conn);
	/* FIXME use kfree_rcu if we don't do anything else here */
	kfree(conn);
}

static int ccieth_destroy_connection_idrforeach_cb(int id, void *p, void *data)
{
	struct ccieth_connection *conn = p;
	enum ccieth_connection_status status = conn->status;
	int *destroyed_conn = data;

	if (cmpxchg(&conn->status, status, CCIETH_CONNECTION_CLOSING) != status)
		/* somebody else is closing it */
		return 0;

	call_rcu(&conn->destroy_rcu_head, ccieth_destroy_connection_rcu);
	(*destroyed_conn)++;
	return 0;
}

static void
ccieth_destroy_endpoint(struct ccieth_endpoint *ep)
{
	struct ccieth_endpoint_event *event, *nevent;
	struct net_device *ifp;
	int destroyed_conn = 0;

	spin_lock(&ccieth_ep_idr_lock);
	idr_remove(&ccieth_ep_idr, ep->id);
	spin_unlock(&ccieth_ep_idr_lock);

	/* the network cannot start new receive handlers now, but some may be running */
	synchronize_net();
	/* all receive handlers are gone now */

	cancel_work_sync(&ep->recv_connect_request_work);
	skb_queue_purge(&ep->recv_connect_request_queue);

	/* release the interface, but make sure a netdevice notifier
	 * isn't already doing it inside a call_rcu */
	rcu_read_lock();
	ifp = rcu_dereference(ep->ifp);
	if (ifp && cmpxchg(&ep->ifp, ifp, NULL) == ifp) {
		rcu_read_unlock();
		dev_put(ifp);
	} else {
		rcu_read_unlock();
		/* wait for the pending rcu_call() to finish */
		rcu_barrier();
	}

	list_for_each_entry_safe(event, nevent, &ep->event_list, list) {
		list_del(&event->list);
		kfree(event);
	}
	list_for_each_entry_safe(event, nevent, &ep->free_event_list, list) {
		list_del(&event->list);
		kfree(event);
	}

	idr_for_each(&ep->connection_idr, ccieth_destroy_connection_idrforeach_cb,
		     &destroyed_conn);
	printk("destroyed %d connections on endpoint destroy\n", destroyed_conn);
	/* new ioctls cannot access connections anymore now */
	idr_remove_all(&ep->connection_idr);
	idr_destroy(&ep->connection_idr);
	/* the last reference will actually destroy each connection */

	/* FIXME: split this for the notifier so that we only free(ep) when the last connection is destroyed */
	kfree(ep);
}

static int
ccieth_create_endpoint(struct file *file, struct ccieth_ioctl_create_endpoint *arg)
{
	struct ccieth_endpoint_event *event, *nevent;
	struct ccieth_endpoint *ep, **epp;
	struct net_device *ifp;
	int id, i;
	int err;

	rcu_read_lock();
	ifp = dev_getbyhwaddr_rcu(&init_net, ARPHRD_ETHER, (const char *)&arg->addr);
	if (!ifp) /* allow loopback to ease development */
		ifp = dev_getbyhwaddr_rcu(&init_net, ARPHRD_LOOPBACK, (const char *)&arg->addr);
	if (!ifp) {
		rcu_read_unlock();
		err = -ENODEV;
		goto out;
	}
	dev_hold(ifp);
	rcu_read_unlock();

	ep = kmalloc(sizeof(struct ccieth_endpoint), GFP_KERNEL);
	if (!ep) {
		err = -ENOMEM;
		goto out_with_ifp;
	}
	rcu_assign_pointer(ep->ifp, ifp);
	memcpy(ep->addr, &ifp->dev_addr, 6);
	ep->max_send_size = ccieth_max_send_size(ifp->mtu);

	INIT_LIST_HEAD(&ep->event_list);
	spin_lock_init(&ep->event_list_lock);
	INIT_LIST_HEAD(&ep->free_event_list);
	spin_lock_init(&ep->free_event_list_lock);
	for(i=0; i<CCIETH_EVENT_SLOT_NR; i++) {
		event = kmalloc(sizeof(*event) + ep->max_send_size, GFP_KERNEL);
		if (!event)
			break;
		list_add_tail(&event->list, &ep->free_event_list);
	}

	idr_init(&ep->connection_idr);
	spin_lock_init(&ep->connection_idr_lock);

	skb_queue_head_init(&ep->recv_connect_request_queue);
	INIT_WORK(&ep->recv_connect_request_work, ccieth_recv_connect_request_workfunc);

retry:
	/* reserve an index without exposing the endpoint there yet
	 * because it's id isn't ready yet */
	spin_lock(&ccieth_ep_idr_lock);
	err = idr_get_new(&ccieth_ep_idr, NULL, &id);
	spin_unlock(&ccieth_ep_idr_lock);
	if (err == -EAGAIN) {
		if (idr_pre_get(&ccieth_ep_idr, GFP_KERNEL) > 0)
			goto retry;
		err = -ENOMEM;
		goto out_with_events;
	}
	ep->id = arg->id = id;

	/* link the endpoint now that everything is ready */
	epp = (struct ccieth_endpoint **)&file->private_data;
	if (cmpxchg(epp, NULL, ep)) {
		err = -EBUSY;
		goto out_with_idr;
	}
	BUG_ON(idr_replace(&ccieth_ep_idr, ep, id) != NULL);

	return 0;

out_with_idr:
	spin_lock(&ccieth_ep_idr_lock);
	idr_remove(&ccieth_ep_idr, id);
	spin_unlock(&ccieth_ep_idr_lock);
out_with_events:
	list_for_each_entry_safe(event, nevent, &ep->free_event_list, list) {
		list_del(&event->list);
		kfree(event);
	}
	kfree(ep);
out_with_ifp:
	dev_put(ifp);
out:
	return err;
}

static struct ccieth_endpoint_event *
ccieth_get_event(struct ccieth_endpoint *ep)
{
	struct ccieth_endpoint_event *event;

	spin_lock(&ep->event_list_lock);
	if (list_empty(&ep->event_list)) {
		spin_unlock(&ep->event_list_lock);
		return NULL;
	}

	event = list_first_entry(&ep->event_list, struct ccieth_endpoint_event, list);
	list_del(&event->list);
	spin_unlock(&ep->event_list_lock);

	return event;
}

static int
ccieth_return_event(struct ccieth_endpoint *ep, const struct ccieth_ioctl_return_event *arg)
{
	/* FIXME: nothing to do for now */
	return 0;
}

static int
ccieth_connect_request(struct ccieth_endpoint *ep, struct ccieth_ioctl_connect_request *arg)
{
	struct sk_buff *skb;
	struct net_device *ifp;
	struct ccieth_pkt_header_connect_request *hdr;
	struct ccieth_connection *conn;
	size_t skblen;
	int id;
	int err;

	err = -EINVAL;
	if (arg->data_len > ep->max_send_size)
		goto out;

	/* get a connection */
	err = -ENOMEM;
	conn = kmalloc(sizeof(*conn), GFP_KERNEL);
	if (!conn)
		goto out;
	/* get a connection id (only reserve it) */
retry:
	spin_lock(&ep->connection_idr_lock);
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

	/* allocate and initialize the skb */
	skblen = sizeof(*hdr) + arg->data_len;
	if (skblen < ETH_ZLEN)
		skblen = ETH_ZLEN;
        skb = alloc_skb(skblen, GFP_KERNEL);
	if (!skb)
		goto out_with_conn_id;
	skb_reset_mac_header(skb);
	skb_reset_network_header(skb);
	skb->protocol = __constant_htons(ETH_P_CCI);
	skb_put(skb, skblen);
	/* setup as much as possible of the skb
	 * so that things don't fail later once the connection is hashed
	 */
	hdr = (struct ccieth_pkt_header_connect_request *) skb_mac_header(skb);
	memcpy(&hdr->eth.h_dest, &arg->dest_addr, 6);
	memcpy(&hdr->eth.h_source, ep->addr, 6);
	hdr->eth.h_proto = __constant_cpu_to_be16(ETH_P_CCI);
	hdr->type = CCIETH_PKT_CONNECT_REQUEST;
	hdr->dst_ep_id = htonl(arg->dest_eid);
	hdr->attribute = arg->attribute;
	hdr->src_ep_id = htonl(ep->id);
	hdr->max_send_size = htonl(ep->max_send_size);
	hdr->data_len = htonl(arg->data_len);
	err = copy_from_user(&hdr->data, (const void __user *)(uintptr_t) arg->data_ptr, arg->data_len);
	if (err) {
		err = -EFAULT;
		goto out_with_skb;
	}

	/* initialize the connection */
	conn->status = CCIETH_CONNECTION_REQUESTED;
	memcpy(&conn->dest_addr, &arg->dest_addr, 6);
	conn->dest_eid = arg->dest_eid;
	conn->attribute = arg->attribute;
	conn->user_conn_id = arg->user_conn_id;
	conn->id = id;
	idr_replace(&ep->connection_idr, conn, id);
	hdr->src_conn_id = htonl(id);

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

	/* FIXME: setup timer to min(timeout, retransmit)
	 * if timeout expired, destroy conn and return timedout event
	 * if retransmit expired, resend skb (cache the above one), reset timer
	 */

	arg->conn_id = conn->id;
	return 0;

out_with_rculock:
	rcu_read_unlock();
out_with_skb:
	kfree_skb(skb);
out_with_conn_id:
	spin_lock(&ep->connection_idr_lock);
	idr_remove(&ep->connection_idr, id);
	spin_unlock(&ep->connection_idr_lock);
out_with_conn:
	kfree(conn);
out:
	return err;
}

static int
ccieth_connect_accept(struct ccieth_endpoint *ep, struct ccieth_ioctl_connect_accept *arg)
{
	struct sk_buff *skb;
	struct net_device *ifp;
	struct ccieth_pkt_header_connect_accept *hdr;
	struct ccieth_connection *conn;
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

	rcu_read_lock();

	/* is the interface still available? */
	ifp = rcu_dereference(ep->ifp);
	if (!ifp) {
		err = -ENODEV;
		goto out_with_rculock;
	}
	skb->dev = ifp;

	/* update the connection now that we can't fail anywhere else */
	err = -EINVAL;
	conn = idr_find(&ep->connection_idr, arg->conn_id);
	if (!conn)
		goto out_with_rculock;

	if (cmpxchg(&conn->status, CCIETH_CONNECTION_RECEIVED, CCIETH_CONNECTION_READY)
	    != CCIETH_CONNECTION_RECEIVED)
		goto out_with_rculock;
	conn->max_send_size = arg->max_send_size;
	conn->user_conn_id = arg->user_conn_id;

	/* fill headers */
	hdr = (struct ccieth_pkt_header_connect_accept *) skb_mac_header(skb);
	memcpy(&hdr->eth.h_dest, &conn->dest_addr, 6);
	memcpy(&hdr->eth.h_source, ep->addr, 6);
	hdr->eth.h_proto = __constant_cpu_to_be16(ETH_P_CCI);
	hdr->type = CCIETH_PKT_CONNECT_ACCEPT;
	hdr->dst_ep_id = htonl(conn->dest_eid);
	hdr->dst_conn_id = htonl(conn->dest_id);
	hdr->src_ep_id = htonl(ep->id);
	hdr->src_conn_id = htonl(conn->id);
	hdr->max_send_size = htonl(conn->max_send_size);

	dev_queue_xmit(skb);

	rcu_read_unlock();
	return 0;

out_with_rculock:
	kfree_skb(skb);
	rcu_read_unlock();
out:
	return err;
}

static int
ccieth_msg(struct ccieth_endpoint *ep, struct ccieth_ioctl_msg *arg)
{
	struct sk_buff *skb;
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
        skb = alloc_skb(skblen, GFP_KERNEL);
	if (!skb)
		goto out;
	skb_reset_mac_header(skb);
	skb_reset_network_header(skb);
	skb->protocol = __constant_htons(ETH_P_CCI);
	skb_put(skb, skblen);

	rcu_read_lock();

	/* is the interface still available? */
	ifp = rcu_dereference(ep->ifp);
	if (!ifp) {
		err = -ENODEV;
		goto out_with_rculock;
	}
	skb->dev = ifp;

	/* find connection */
	conn = idr_find(&ep->connection_idr, arg->conn_id);
	if (!conn || conn->status != CCIETH_CONNECTION_READY)
		goto out_with_rculock;

	/* get an event */
	spin_lock(&ep->free_event_list_lock);
	if (list_empty(&ep->free_event_list)) {
		err = -ENOMEM;
		spin_unlock(&ep->free_event_list_lock);
		printk("ccieth: no event slot for send\n");
		goto out_with_rculock;
	}
	event = list_first_entry(&ep->free_event_list, struct ccieth_endpoint_event, list);
	list_del(&event->list);
	spin_unlock(&ep->free_event_list_lock);

	/* setup the event */
	event->event.type = CCIETH_IOCTL_EVENT_SEND;
	event->event.send.user_conn_id = conn->user_conn_id;
	event->event.send.context = arg->context;

	/* fill headers */
	hdr = (struct ccieth_pkt_header_msg *) skb_mac_header(skb);
	memcpy(&hdr->eth.h_dest, &conn->dest_addr, 6);
	memcpy(&hdr->eth.h_source, ep->addr, 6);
	hdr->eth.h_proto = __constant_cpu_to_be16(ETH_P_CCI);
	hdr->type = CCIETH_PKT_MSG;
	hdr->dst_ep_id = htonl(conn->dest_eid);
	hdr->dst_conn_id = htonl(conn->dest_id);
	hdr->msg_len = htonl(arg->msg_len);
	err = copy_from_user(&hdr->msg, (const void __user *)(uintptr_t) arg->msg_ptr, arg->msg_len);
	if (err) {
		err = -EFAULT;
		goto out_with_event;
	}

	/* FIXME: implement flags */

	dev_queue_xmit(skb);

	/* finalize and notify the event */
	event->event.send.status = 0;
	spin_lock(&ep->event_list_lock);
	list_add_tail(&event->list, &ep->event_list);
	spin_unlock(&ep->event_list_lock);

	rcu_read_unlock();
	return 0;

out_with_event:
	spin_lock(&ep->free_event_list_lock);
	list_add_tail(&event->list, &ep->free_event_list);
	spin_unlock(&ep->free_event_list_lock);
out_with_rculock:
	rcu_read_unlock();
	kfree_skb(skb);
out:
	return err;
}

static int
ccieth_miscdev_open(struct inode *inode, struct file *file)
{
	file->private_data = NULL;
	return 0;
}

static int
ccieth_miscdev_release(struct inode *inode, struct file *file)
{
	struct ccieth_endpoint *ep = file->private_data;
	if (ep) {
		file->private_data = NULL;
		ccieth_destroy_endpoint(ep);
	}
	return 0;
}

static long
ccieth_miscdev_ioctl(struct file *file, unsigned cmd, unsigned long arg)
{
	int ret;

	switch (cmd) {
	case CCIETH_IOCTL_GET_INFO: {
		/* get a sockaddr_ll from userspace */
		struct ccieth_ioctl_get_info gi_arg;
		struct net_device *ifp;

		ret = copy_from_user(&gi_arg, (const __user void *)arg, sizeof(gi_arg));
		if (ret)
			return -EFAULT;

		gi_arg.max_send_size = -1;
		gi_arg.pci_domain = -1;
		gi_arg.pci_bus = -1;
		gi_arg.pci_dev = -1;
		gi_arg.pci_func = -1;
		gi_arg.rate = 0;

		rcu_read_lock();
		ifp = dev_getbyhwaddr_rcu(&init_net, ARPHRD_ETHER, (const char *)&gi_arg.addr);
		if (ifp) {
			struct device *dev = ifp->dev.parent;

			gi_arg.max_send_size = ccieth_max_send_size(ifp->mtu);

			if (dev && dev->bus == &pci_bus_type) {
				struct pci_dev *pdev = to_pci_dev(dev);
				gi_arg.pci_domain = pci_domain_nr(pdev->bus);
				gi_arg.pci_bus = pdev->bus->number;
				gi_arg.pci_dev = PCI_SLOT(pdev->devfn);
				gi_arg.pci_func = PCI_FUNC(pdev->devfn);
			}

			if (ifp->ethtool_ops && ifp->ethtool_ops->get_settings) {
				struct ethtool_cmd cmd;
				if (ifp->ethtool_ops->get_settings(ifp, &cmd) >= 0) {
					u32 speed = ethtool_cmd_speed(&cmd);
					if (speed != -1)
						gi_arg.rate = ((u64) speed) * 1000000;
				}
			}
		} else
			ret = -ENODEV;
		rcu_read_unlock();

		ret = copy_to_user((__user void *)arg, &gi_arg, sizeof(gi_arg));
		if (ret)
			return -EFAULT;


		return 0;
	}

	case CCIETH_IOCTL_CREATE_ENDPOINT: {
		struct ccieth_ioctl_create_endpoint ce_arg;

		ret = copy_from_user(&ce_arg, (const __user void *)arg, sizeof(ce_arg));
		if (ret)
			return -EFAULT;

		ret = ccieth_create_endpoint(file, &ce_arg);
		if (ret < 0)
			return ret;

		ret = copy_to_user((__user void *)arg, &ce_arg, sizeof(ce_arg));
		if (ret)
			return -EFAULT;

		return 0;
	}

	case CCIETH_IOCTL_GET_EVENT: {
		struct ccieth_endpoint_event *event;
		struct ccieth_endpoint *ep = file->private_data;

		if (!ep)
			return -EINVAL;

		event = ccieth_get_event(ep);
		if (!event)
			return -EAGAIN;

		ret = copy_to_user((__user void *)arg, &event->event, sizeof(event->event));
		if (ret)
			return -EFAULT;

		ret = copy_to_user(((__user void *) arg)+sizeof(struct ccieth_ioctl_get_event),
				   event+1, event->event.data_length);

		spin_lock(&ep->free_event_list_lock);
		list_add_tail(&event->list, &ep->free_event_list);
		spin_unlock(&ep->free_event_list_lock);

		if (ret)
			return -EFAULT;

		return 0;
	}

	case CCIETH_IOCTL_RETURN_EVENT: {
		struct ccieth_ioctl_return_event re_arg;
		struct ccieth_endpoint *ep = file->private_data;

		if (!ep)
			return -EINVAL;

		ret = copy_from_user(&re_arg, (__user void *)arg, sizeof(re_arg));
		if (ret)
			return -EFAULT;

		ret = ccieth_return_event(ep, &re_arg);
		if (ret < 0)
			return ret;

		return 0;
	}

	case CCIETH_IOCTL_CONNECT_REQUEST: {
		struct ccieth_ioctl_connect_request sc_arg;
		struct ccieth_endpoint *ep = file->private_data;

		if (!ep)
			return -EINVAL;

		ret = copy_from_user(&sc_arg, (__user void *)arg, sizeof(sc_arg));
		if (ret)
			return -EFAULT;

		ret = ccieth_connect_request(ep, &sc_arg);
		if (ret < 0)
			return ret;

		ret = copy_to_user((__user void *)arg, &sc_arg, sizeof(sc_arg));
		if (ret)
			return -EFAULT;

		return 0;
	}

	case CCIETH_IOCTL_CONNECT_ACCEPT: {
		struct ccieth_ioctl_connect_accept ac_arg;
		struct ccieth_endpoint *ep = file->private_data;

		if (!ep)
			return -EINVAL;

		ret = copy_from_user(&ac_arg, (__user void *)arg, sizeof(ac_arg));
		if (ret)
			return -EFAULT;

		ret = ccieth_connect_accept(ep, &ac_arg);
		if (ret < 0)
			return ret;

		return 0;
	}

	case CCIETH_IOCTL_MSG: {
		struct ccieth_ioctl_msg ms_arg;
		struct ccieth_endpoint *ep = file->private_data;

		if (!ep)
			return -EINVAL;

		ret = copy_from_user(&ms_arg, (__user void *)arg, sizeof(ms_arg));
		if (ret)
			return -EFAULT;

		ret = ccieth_msg(ep, &ms_arg);
		if (ret < 0)
			return ret;

		return 0;
	}

	default:
		return -EINVAL;
	}
}

static struct file_operations
ccieth_miscdev_fops = {
	.owner = THIS_MODULE,
	.open = ccieth_miscdev_open,
	.release = ccieth_miscdev_release,
	.unlocked_ioctl = ccieth_miscdev_ioctl,
};

static struct miscdevice
ccieth_miscdev = {
	.minor = MISC_DYNAMIC_MINOR,
	.name = "ccieth",
	.fops = &ccieth_miscdev_fops,
};

static int
ccieth_init(void)
{
	int ret;

	idr_init(&ccieth_ep_idr);
	spin_lock_init(&ccieth_ep_idr_lock);

	ret = ccieth_net_init();
	if (ret < 0)
		goto out;

	ret = misc_register(&ccieth_miscdev);
	if (ret < 0)
		goto out_with_net;

	return 0;

out_with_net:
	ccieth_net_exit();
out:
	return ret;
}

static void
ccieth_exit(void)
{
	misc_deregister(&ccieth_miscdev);
	ccieth_net_exit();
	idr_destroy(&ccieth_ep_idr);
	rcu_barrier(); /* wait for rcu calls to be done */
}

module_init(ccieth_init);
module_exit(ccieth_exit);

MODULE_LICENSE("Dual BSD/GPL");
MODULE_AUTHOR("Brice Goglin <Brice.Goglin@inria.fr>");
MODULE_VERSION("0.0.1");
MODULE_DESCRIPTION("CCI over Ethernet");
