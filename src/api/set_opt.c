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

int cci_set_opt(void * handle, cci_opt_name_t name, cci_opt_t *val)
{
	cci_plugin_core_t *plugin;
	int ret;

	CCI_ENTER;

	if (NULL == handle || NULL == val) {
		return CCI_EINVAL;
	}

	if (CCI_OPT_CONN_SEND_TIMEOUT == name) {
		cci__conn_t *conn =
			container_of((cci_connection_t*)handle, cci__conn_t, connection);
		plugin = conn->plugin;
	} else {
		cci__ep_t *ep = container_of((cci_endpoint_t*)handle, cci__ep_t, endpoint);
		plugin = ep->plugin;
	}

	ret = plugin->set_opt(handle, name, val);

	CCI_EXIT;

	return ret;
}
