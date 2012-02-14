/*
 * Copyright (c) 2010 Cisco Systems, Inc.  All rights reserved.
 * Copyright © 2010-2011 UT-Battelle, LLC. All rights reserved.
 * Copyright © 2010-2011 Oak Ridge National Labs.  All rights reserved.
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

int cci_destroy_endpoint(cci_endpoint_t * endpoint)
{
	int ret = CCI_SUCCESS;
	cci__ep_t *ep = NULL;
	cci__dev_t *dev = NULL;

	if (NULL == endpoint)
		return CCI_EINVAL;

	ep = container_of(endpoint, cci__ep_t, endpoint);
	dev = ep->dev;

	pthread_mutex_lock(&dev->lock);
	ep->closing = 1;
	TAILQ_REMOVE(&dev->eps, ep, entry);
	pthread_mutex_unlock(&dev->lock);

	/* the driver is responsible for cleaning up ep->priv,
	 * the evts list, and any cci__conn_t that it is maintaining.
	 */
	ret = cci_core->destroy_endpoint(endpoint);

	free(ep);

	return ret;
}
