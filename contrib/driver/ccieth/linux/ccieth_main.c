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
#include <linux/timer.h>
#include <linux/jiffies.h>

#include <ccieth_io.h>
#include <ccieth_common.h>
#include <ccieth_wire.h>

struct idr ccieth_ep_idr;
static spinlock_t ccieth_ep_idr_lock;
#ifdef CONFIG_CCIETH_DEBUGFS
struct dentry *ccieth_debugfs_root;
#endif

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

	cancel_work_sync(&ep->deferred_connect_recv_work);
	skb_queue_purge(&ep->deferred_connect_recv_queue);
	/* pending network work is gone as well now */

	/* release the interface, but make sure a netdevice notifier
	 * isn't already doing it inside a call_rcu */
	rcu_read_lock();
	ifp = rcu_dereference(ep->ifp);
	if (ifp && cmpxchg((struct net_device __force **)&ep->ifp, ifp, NULL) == ifp) {
		rcu_read_unlock();
		dev_put(ifp);
	} else {
		rcu_read_unlock();
		/* wait for the pending rcu_call() to finish */
		rcu_barrier();
	}

	/* we're safe now */

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
	dprintk("destroyed %d connections on endpoint destroy\n", destroyed_conn);
	idr_remove_all(&ep->connection_idr);
	idr_destroy(&ep->connection_idr);
#ifdef CONFIG_CCIETH_DEBUGFS
	/* no that connection debugfs entries are gone, remove the endpoint debugfs dir */
	if (ep->debugfs_dir)
		debugfs_remove(ep->debugfs_dir);
#endif
	kfree(ep);
}

static void
ccieth_event_destructor_recycle(struct ccieth_endpoint *ep,
				struct ccieth_endpoint_event *event)
{
	spin_lock_bh(&ep->free_event_list_lock);
	list_add_tail(&event->list, &ep->free_event_list);
	spin_unlock_bh(&ep->free_event_list_lock);
}

static int
ccieth_create_endpoint(struct file *file, struct ccieth_ioctl_create_endpoint *arg)
{
	struct ccieth_endpoint_event *event, *nevent;
	struct ccieth_endpoint *ep, **epp;
	struct net_device *ifp;
	int id, i;
	int err;

	ccieth_dev_getbyhwaddr_lock();
	ifp = ccieth_dev_getbyhwaddr(&init_net, ARPHRD_ETHER, (const char *)&arg->addr);
	if (!ifp) /* allow loopback to ease development */
		ifp = ccieth_dev_getbyhwaddr(&init_net, ARPHRD_LOOPBACK, (const char *)&arg->addr);
	if (!ifp) {
		ccieth_dev_getbyhwaddr_unlock();
		err = -ENODEV;
		goto out;
	}
	dev_hold(ifp);
	ccieth_dev_getbyhwaddr_unlock();

	ep = kmalloc(sizeof(struct ccieth_endpoint), GFP_KERNEL);
	if (!ep) {
		err = -ENOMEM;
		goto out_with_ifp;
	}
	rcu_assign_pointer(ep->ifp, ifp);
	memcpy(ep->addr, &arg->addr, 6);
	ep->max_send_size = ccieth_max_send_size(ifp->mtu);

	INIT_LIST_HEAD(&ep->event_list);
	spin_lock_init(&ep->event_list_lock);
	INIT_LIST_HEAD(&ep->free_event_list);
	spin_lock_init(&ep->free_event_list_lock);
	for(i=0; i<CCIETH_EVENT_SLOT_NR; i++) {
		event = kmalloc(sizeof(*event) + ep->max_send_size, GFP_KERNEL);
		if (!event)
			break;
		event->destructor = ccieth_event_destructor_recycle;
		list_add_tail(&event->list, &ep->free_event_list);
	}

	ep->embedded_event.destructor = NULL;

	idr_init(&ep->connection_idr);
	spin_lock_init(&ep->connection_idr_lock);
	atomic_set(&ep->connection_req_seqnum, jiffies); /* a bit of random just for fun */
	atomic_set(&ep->connection_received, 0);

	skb_queue_head_init(&ep->deferred_connect_recv_queue);
	INIT_WORK(&ep->deferred_connect_recv_work, ccieth_deferred_connect_recv_workfunc);

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

#ifdef CONFIG_CCIETH_DEBUGFS
	ep->debugfs_dir = NULL;
	if (ccieth_debugfs_root) {
		char * name = kasprintf(GFP_KERNEL, "ep%08x", id);
		if (name) {
			struct dentry *d = debugfs_create_dir(name, ccieth_debugfs_root);
			if (!IS_ERR(d))
				ep->debugfs_dir = d;
			kfree(name);
		}
	}
#endif

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

	spin_lock_bh(&ep->event_list_lock);
	if (list_empty(&ep->event_list)) {
		spin_unlock_bh(&ep->event_list_lock);
		return NULL;
	}

	event = list_first_entry(&ep->event_list, struct ccieth_endpoint_event, list);
	list_del(&event->list);
	spin_unlock_bh(&ep->event_list_lock);

	return event;
}

static int
ccieth_return_event(struct ccieth_endpoint *ep, const struct ccieth_ioctl_return_event *arg)
{
	/* FIXME: nothing to do for now */
	return 0;
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

		ccieth_dev_getbyhwaddr_lock();
		ifp = ccieth_dev_getbyhwaddr(&init_net, ARPHRD_ETHER, (const char *)&gi_arg.addr);
		if (!ifp) /* allow loopback to ease development */
			ifp = ccieth_dev_getbyhwaddr(&init_net, ARPHRD_LOOPBACK, (const char *)&gi_arg.addr);
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
				struct ethtool_cmd ecmd;
				ecmd.cmd = ETHTOOL_GSET;
				memset(&ecmd, 0, sizeof(ecmd));
				if (ifp->ethtool_ops->get_settings(ifp, &ecmd) >= 0) {
					u32 speed = ethtool_cmd_speed(&ecmd);
					if (speed != -1)
						gi_arg.rate = ((u64) speed) * 1000000;
				}
			}
		} else {
			ccieth_dev_getbyhwaddr_unlock();
			return -ENODEV;
		}
		ccieth_dev_getbyhwaddr_unlock();

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
		if (!ret && event->event.data_length > 0)
			ret = copy_to_user(((__user void *) arg)+sizeof(struct ccieth_ioctl_get_event),
					   event+1, event->event.data_length);

		if (event->destructor)
			event->destructor(ep, event);

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

	case CCIETH_IOCTL_CONNECT_REJECT: {
		struct ccieth_ioctl_connect_reject rj_arg;
		struct ccieth_endpoint *ep = file->private_data;

		if (!ep)
			return -EINVAL;

		ret = copy_from_user(&rj_arg, (__user void *)arg, sizeof(rj_arg));
		if (ret)
			return -EFAULT;

		ret = ccieth_connect_reject(ep, &rj_arg);
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

static struct packet_type ccieth_pt = {
	.type = __constant_htons(ETH_P_CCI),
	.func = ccieth_recv,
};

static int
ccieth_init(void)
{
	int ret;

	idr_init(&ccieth_ep_idr);
	spin_lock_init(&ccieth_ep_idr_lock);

#ifdef CONFIG_CCIETH_DEBUGFS
	ccieth_debugfs_root = debugfs_create_dir("ccieth", NULL);
	if (IS_ERR(ccieth_debugfs_root)) {
		ret = PTR_ERR(ccieth_debugfs_root);
		goto out;
	}
#endif

	ret = register_netdevice_notifier(&ccieth_netdevice_notifier);
	if (ret < 0)
		goto out_with_debugfs;

	dev_add_pack(&ccieth_pt);

	ret = misc_register(&ccieth_miscdev);
	if (ret < 0)
		goto out_with_net;

	return 0;

out_with_net:
	dev_remove_pack(&ccieth_pt);
	unregister_netdevice_notifier(&ccieth_netdevice_notifier);
out_with_debugfs:
#ifdef CONFIG_CCIETH_DEBUGFS
	debugfs_remove(ccieth_debugfs_root);
out:
#endif
	return ret;
}

static void
ccieth_exit(void)
{
	misc_deregister(&ccieth_miscdev);
	dev_remove_pack(&ccieth_pt);
	unregister_netdevice_notifier(&ccieth_netdevice_notifier);
#ifdef CONFIG_CCIETH_DEBUGFS
	debugfs_remove(ccieth_debugfs_root);
#endif
	idr_destroy(&ccieth_ep_idr);
	rcu_barrier(); /* wait for rcu calls to be done */
}

module_init(ccieth_init);
module_exit(ccieth_exit);

MODULE_LICENSE("Dual BSD/GPL");
MODULE_AUTHOR("Brice Goglin <Brice.Goglin@inria.fr>");
MODULE_VERSION("0.0.1");
MODULE_DESCRIPTION("CCI over Ethernet");
