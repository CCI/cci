/*
 * Copyright (c) 2010 Cisco Systems, Inc.  All rights reserved.
 * Copyright © 2010-2012 UT-Battelle, LLC. All rights reserved.
 * Copyright © 2010-2012 Oak Ridge National Labs.  All rights reserved.
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
#include "plugins/base/public.h"
#include "plugins/ctp/base/public.h"
#include "plugins/ctp/ctp.h"
#include "cci-api.h"

int cci_finalize(void)
{
	int ret = CCI_SUCCESS;
	cci__dev_t *dev = NULL;
	int i;

	CCI_LOCK(&init_lock);

	if (!initialized) {
		/* not initialized */
		ret = CCI_ERROR;
		goto out;
	}

	initialized--;
	if (initialized > 0) {
		/* no-op, return SUCCESS */
		goto out;
	}

	/* lock the device list while destroying devices and finalizing CTPs */
	CCI_LOCK(&globals->lock);

	/* for each device
	 *     for each endpoint
	 *         close_endpoint
	 */

	TAILQ_FOREACH(dev, &globals->devs, entry) {
		CCI_LOCK(&dev->lock);
		while (!TAILQ_EMPTY(&dev->eps)) {
			cci__ep_t *ep = TAILQ_FIRST(&dev->eps);
			CCI_UNLOCK(&dev->lock);
			cci_destroy_endpoint(&ep->endpoint);
			CCI_LOCK(&dev->lock);
		}
		CCI_UNLOCK(&dev->lock);
	}

	/* let the transport clean up the private device */
	for (i = 0;
	     cci_all_plugins[i].plugin != NULL;
	     i++) {
		cci_plugin_ctp_t *plugin = (cci_plugin_ctp_t *) cci_all_plugins[i].plugin;
		if (CCI_SUCCESS == cci_all_plugins[i].init_status)
			plugin->finalize(plugin);
	}

	while (!TAILQ_EMPTY(&globals->devs)) {
		cci__dev_t *mydev = TAILQ_FIRST(&globals->devs);
		TAILQ_REMOVE(&globals->devs, mydev, entry);
		cci__free_dev(mydev);
	}

	free(globals->devices);
	globals->devices = NULL;

	CCI_UNLOCK(&globals->lock);

	/* free globals */
	free(globals);

	cci_plugins_ctp_close();
	cci_plugins_finalize();

out:
	CCI_UNLOCK(&init_lock);
	return ret;
}
