/*
 * CCI over Ethernet
 * Copyright © INRIA 2011
 */

#include <linux/module.h>
#include <linux/miscdevice.h>
#include <linux/fs.h>
#include <linux/uaccess.h>
#include <linux/types.h>

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
		
		ret = copy_from_user(&gi_arg, (const __user void *) arg, sizeof(gi_arg));
		if (ret)
			return -EFAULT;

		printk("getting info for mac %02x:%02x:%02x:%02x:%02x:%02x",
		       gi_arg.addr[0],
		       gi_arg.addr[1],
		       gi_arg.addr[2],
		       gi_arg.addr[3],
		       gi_arg.addr[4],
		       gi_arg.addr[5]);

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
