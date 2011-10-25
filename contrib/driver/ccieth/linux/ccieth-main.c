/*
 * CCI over Ethernet
 * Copyright © INRIA 2011
 */

#include <linux/module.h>
#include <linux/miscdevice.h>
#include <linux/fs.h>

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
	return -EINVAL;
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
