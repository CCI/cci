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
#include "plugins/base/public.h"
#include "plugins/core/core.h"

int cci_get_devices(cci_device_t * const ** devices)
{
	int ret;
	int i, j;

	if (NULL == devices)
		return CCI_EINVAL;

	for (i = 0, j = 0;
	     cci_all_plugins[i].plugin != NULL;
	     i++) {
		cci_plugin_core_t *plugin = (cci_plugin_core_t *) cci_all_plugins[i].plugin;
		ret = plugin->get_devices(plugin, devices); /* FIMXE append? */
		if (!ret)
			j++;
	}
	/* return an error if all plugins init failed */
	if (!j) {
		perror("all plugins get_devices failed:");
		return errno;
	}

	return CCI_SUCCESS;
}
