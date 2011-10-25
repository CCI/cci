/*
 * CCI over Ethernet
 * Copyright © INRIA 2011
 */

#include <linux/module.h>
#include <linux/miscdevice.h>
#include <linux/fs.h>
#include <linux/uaccess.h>
#include <linux/types.h>
#include <linux/netdevice.h>
#include <linux/if_arp.h>
#include <linux/pci.h>
#include <linux/rcupdate.h>

#include <ccieth_io.h>

static int
ccieth_miscdev_open(struct inode * inode, struct file * file)
{
	return 0;
}

static int
ccieth_miscdev_release(struct inode * inode, struct file * file)
{
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

		ret = copy_from_user(&gi_arg, (const __user void *) arg, sizeof(gi_arg));
		if (ret)
			return -EFAULT;

		gi_arg.max_send_size = -1;
		gi_arg.pci_domain = -1;
		gi_arg.pci_bus = -1;
		gi_arg.pci_dev = -1;
		gi_arg.pci_func = -1;
		gi_arg.rate = 0;

		rcu_read_lock();
		ifp = dev_getbyhwaddr_rcu(&init_net, ARPHRD_ETHER, (const char *) &gi_arg.addr);
		if (ifp) {
			struct device *dev = ifp->dev.parent;

			if (ifp->mtu == 9000)
				gi_arg.max_send_size = 8192;
			else if (ifp->mtu == 1500)
				gi_arg.max_send_size = 1024;

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
		}
		rcu_read_unlock();

		ret = copy_to_user((__user void *) arg, &gi_arg, sizeof(gi_arg));
		if (ret)
			return -EFAULT;


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

int
ccieth_init(void)
{
	int ret;

	ret = misc_register(&ccieth_miscdev);
	if (ret < 0)
		goto out;

	return 0;

out:
	return ret;
}

void
ccieth_exit(void)
{
	misc_deregister(&ccieth_miscdev);
}

module_init(ccieth_init);
module_exit(ccieth_exit);

MODULE_LICENSE("Dual BSD/GPL");
MODULE_AUTHOR("Brice Goglin <Brice.Goglin@inria.fr>");
MODULE_VERSION("0.0.1");
MODULE_DESCRIPTION("CCI over Ethernet");
