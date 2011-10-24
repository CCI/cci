/*
 * CCI over Ethernet
 * Copyright © INRIA 2011
 */

#include <linux/module.h>

int
ccieth_init(void)
{
	return 0;
}

void
ccieth_exit(void)
{
}

module_init(ccieth_init);
module_exit(ccieth_exit);

MODULE_LICENSE("Dual BSD/GPL");
MODULE_AUTHOR("Brice Goglin <Brice.Goglin@inria.fr>");
MODULE_VERSION("0.0.1");
MODULE_DESCRIPTION("CCI over Ethernet");
