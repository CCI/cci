/*
 * Copyright (c) 2010 Cisco Systems, Inc.  All rights reserved.
 * Copyright © 2010-2016 UT-Battelle, LLC. All rights reserved.
 * Copyright © 2010-2016 Oak Ridge National Labs.  All rights reserved.
 * Copyright © 2012 inria.  All rights reserved.
 *
 * See COPYING in top-level directory
 *
 * $COPYRIGHT$
 *
 */

#include "cci/private_config.h"

#include <stdio.h>
#include <stdlib.h>

#include "cci.h"
#include "cci_lib_types.h"
#include "plugins/ctp/ctp.h"

int cci_create_endpoint_at(cci_device_t * device,
			const char *service,
			int flags,
			cci_endpoint_t ** endpoint, cci_os_handle_t * fd)
{
	int ret;
	cci__ep_t *ep;
	cci__dev_t *dev;

	pthread_mutex_lock(&globals->lock);

	if (NULL == device) {
		ret = CCI_EINVAL;
		goto out;
	}

	if (!device->up) {
		ret = CCI_ENETDOWN;
		goto out;
	}
	dev = container_of(device, cci__dev_t, device);

	ep = calloc(1, sizeof(*ep));
	if (!ep) {
		ret = CCI_ENOMEM;
		goto out;
	}

	TAILQ_INIT(&ep->evts);
	pthread_mutex_init(&ep->lock, NULL);
	ep->dev = dev;
	ep->endpoint.device = &dev->device;
	ep->plugin = dev->plugin; /* plugin needs to be set before we call create_endpoint_at() */
	*endpoint = &ep->endpoint;

	ret = dev->plugin->create_endpoint_at(device, service, flags, endpoint, fd);
	if (ret == CCI_SUCCESS) {
		pthread_mutex_unlock(&globals->lock);

		pthread_mutex_lock(&dev->lock);
		/* TODO check dev's state */
		TAILQ_INSERT_TAIL(&dev->eps, ep, entry);
		pthread_mutex_unlock(&dev->lock);
	} else {
		pthread_mutex_unlock(&globals->lock);
		pthread_mutex_destroy(&ep->lock);
		free(ep);
	}

	return ret;

out:
	pthread_mutex_unlock(&globals->lock);
	return ret;
}
