/*
 * Copyright (c) 2010 Cisco Systems, Inc.  All rights reserved.
 * Copyright © 2010-2011 UT-Battelle, LLC. All rights reserved.
 * Copyright © 2010-2011 Oak Ridge National Labs.  All rights reserved.
 * Copyright © 2012 inria.  All rights reserved.
 *
 * See COPYING in top-level directory
 *
 * $COPYRIGHT$
 *
 */

#include "cci/private_config.h"

#include <stdio.h>

#include "cci.h"
#include "plugins/ctp/ctp.h"

int cci_arm_os_handle(cci_endpoint_t * endpoint, int flags)
{
	cci__ep_t *ep = container_of(endpoint, cci__ep_t, endpoint);

	if (NULL == endpoint) {
		return CCI_EINVAL;
	}

	return ep->plugin->arm_os_handle(endpoint, flags);
}
