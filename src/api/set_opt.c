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

int cci_set_opt(cci_opt_handle_t * handle, cci_opt_level_t level,
		cci_opt_name_t name, const void *val, int len)
{
	cci_plugin_core_t *plugin;
	int ret;

	CCI_ENTER;

	if (NULL == handle || NULL == val || len == 0) {
		return CCI_EINVAL;
	}

	if (CCI_OPT_LEVEL_ENDPOINT == level) {
		cci__ep_t *ep = container_of(handle->endpoint, cci__ep_t, endpoint);
		if (handle->endpoint == NULL
		    || name == CCI_OPT_CONN_SEND_TIMEOUT)
			return CCI_EINVAL;
		plugin = ep->plugin;
	} else {
		cci__conn_t *conn = container_of(handle->connection, cci__conn_t, connection);
		if (handle->connection == NULL
		    || name != CCI_OPT_CONN_SEND_TIMEOUT)
			return CCI_EINVAL;
		plugin = conn->plugin;
	}

	ret = plugin->set_opt(handle, level, name, val, len);

	CCI_EXIT;

	return ret;
}
