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
#include "cci-api.h"

int cci_free_devices(cci_device_t const **devices)
{
	cci__dev_t *dev = NULL;

	if (NULL == devices || NULL == *devices) {
		return CCI_EINVAL;
	}

	/* for each device
	 *     for each endpoint
	 *         close_endpoint
	 */

	pthread_mutex_lock(&globals->lock);
	TAILQ_FOREACH(dev, &globals->devs, entry) {
		pthread_mutex_lock(&dev->lock);
		while (!TAILQ_EMPTY(&dev->eps)) {
			cci__ep_t *ep = TAILQ_FIRST(&dev->eps);
			pthread_mutex_unlock(&dev->lock);
			cci_destroy_endpoint(&ep->endpoint);
			pthread_mutex_lock(&dev->lock);
		}
		pthread_mutex_unlock(&dev->lock);
	}
	pthread_mutex_unlock(&globals->lock);

	/* let the driver clean up the private device */
	cci_core->free_devices(devices);

	pthread_mutex_lock(&globals->lock);
	while (!TAILQ_EMPTY(&globals->devs)) {
		cci__dev_t *mydev = TAILQ_FIRST(&globals->devs);
		TAILQ_REMOVE(&globals->devs, mydev, entry);
		cci__free_dev(mydev);
	}
	pthread_mutex_unlock(&globals->lock);

	/* free globals */
	free(globals->devices);
	free(globals);

	return CCI_SUCCESS;
}
