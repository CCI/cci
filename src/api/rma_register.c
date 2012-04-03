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

#include "cci/config.h"

#include <stdio.h>

#include "cci.h"
#include "plugins/core/core.h"

int cci_rma_register(cci_endpoint_t * endpoint,
		     void *start, uint64_t length,
		     int flags, uint64_t * rma_handle)
{
	cci__ep_t *ep = container_of(endpoint, cci__ep_t, endpoint);

	if (NULL == endpoint ||
	    NULL == rma_handle || NULL == start || 0ULL == length) {
		return CCI_EINVAL;
	}

	return ep->plugin->rma_register(endpoint, start, length, flags,
					rma_handle);
}
