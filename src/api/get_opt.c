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

int cci_get_opt(cci_opt_handle_t * handle, cci_opt_level_t level,
		cci_opt_name_t name, void **val, int *len)
{
	cci_plugin_core_t * plugin;
	int ret = CCI_SUCCESS;
	cci__ep_t *ep = NULL;
	cci__conn_t *conn = NULL;

	if (NULL == handle || NULL == val || NULL == len) {
		return CCI_EINVAL;
	}

	CCI_ENTER;

	if (CCI_OPT_LEVEL_ENDPOINT == level) {
		if (handle->endpoint == NULL
		    || name == CCI_OPT_CONN_SEND_TIMEOUT)
			return CCI_EINVAL;
		ep = container_of(handle->endpoint, cci__ep_t, endpoint);
		plugin = ep->plugin;
	} else {
		if (handle->connection == NULL
		    || name != CCI_OPT_CONN_SEND_TIMEOUT)
			return CCI_EINVAL;
		conn =
		    container_of(handle->connection, cci__conn_t, connection);
		plugin = conn->plugin;
	}

	switch (name) {
	case CCI_OPT_ENDPT_SEND_TIMEOUT:
		{
			uint32_t *timeout = calloc(1, sizeof(*timeout));
			if (!timeout)
				return CCI_ENOMEM;

			*timeout = ep->tx_timeout;
			*len = sizeof(*timeout);
			*val = timeout;
			break;
		}
	case CCI_OPT_ENDPT_RECV_BUF_COUNT:
		{
			uint32_t *count = calloc(1, sizeof(*count));
			if (!count)
				return CCI_ENOMEM;

			*count = ep->rx_buf_cnt;
			*len = sizeof(*count);
			*val = count;
			break;
		}
	case CCI_OPT_ENDPT_SEND_BUF_COUNT:
		{
			uint32_t *count = calloc(1, sizeof(*count));
			if (!count)
				return CCI_ENOMEM;

			*count = ep->tx_buf_cnt;
			*len = sizeof(*count);
			*val = count;
			break;
		}
	case CCI_OPT_ENDPT_KEEPALIVE_TIMEOUT:
		{
			uint32_t *timeout = calloc(1, sizeof(*timeout));
			if (!timeout)
				return CCI_ENOMEM;

			*timeout = ep->keepalive_timeout;
			*len = sizeof(*timeout);
			*val = timeout;
			break;
		}
	case CCI_OPT_CONN_SEND_TIMEOUT:
		{
			uint32_t *timeout = calloc(1, sizeof(*timeout));
			if (!timeout)
				return CCI_ENOMEM;

			*timeout = conn->tx_timeout;
			*len = sizeof(*timeout);
			*val = timeout;
			break;
		}
	default:
		ret = plugin->get_opt(handle, level, name, val, len);
	}

	CCI_EXIT;

	return ret;
}
