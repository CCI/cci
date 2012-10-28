/*
 * CCI over Ethernet
 *
 * Copyright © 2010-2012 Inria.  All rights reserved.
 * $COPYRIGHT$
 */

#ifndef CCIETH_HAL_H
#define CCIETH_HAL_H 1

#include "ccieth_checks.h"

/* dev_getbyhwaddr_rcu() added in 2.6.38 */
#ifdef CCIETH_HAVE_DEV_GETBYHWADDR_RCU
#define ccieth_dev_getbyhwaddr_lock() rcu_read_lock()
#define ccieth_dev_getbyhwaddr(net, type, ha) dev_getbyhwaddr_rcu(net, type, ha)
#define ccieth_dev_getbyhwaddr_unlock() rcu_read_unlock()
#else
#include "linux/rtnetlink.h"
#define ccieth_dev_getbyhwaddr_lock() rtnl_lock()
#define ccieth_dev_getbyhwaddr(net, type, ha) dev_getbyhwaddr(net, type, (char *)ha)
#define ccieth_dev_getbyhwaddr_unlock() rtnl_unlock()
#endif

/* sparse rcu pointer dereferencing check added in 2.6.37 */
#ifndef __rcu
#define __rcu
#endif

/* rcu_access_pointer added in 2.6.34 */
#ifndef rcu_access_pointer
#define rcu_access_pointer(x) (x)
#endif

/* kfree_rcu added in 3.0 */
#ifndef CCIETH_HAVE_KFREE_RCU
static inline void ccieth_kfree_rcu_call(struct rcu_head *rcu_head)
{
	kfree((void *)rcu_head);
}
#define kfree_rcu(ptr, field) do {				\
	BUILD_BUG_ON(offsetof(typeof(*ptr), field) != 0);	\
	call_rcu((void *)ptr, ccieth_kfree_rcu_call);		\
} while (0)
#endif

#endif /* CCIETH_HAL_H */
