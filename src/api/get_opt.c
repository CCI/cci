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
#include "plugins/ctp/ctp.h"

int cci_get_opt(cci_opt_handle_t * handle, cci_opt_level_t level,
		cci_opt_name_t name, void *val)
{
	cci_plugin_ctp_t * plugin;
	int ret = CCI_SUCCESS;
	cci__ep_t *ep = NULL;
	cci__conn_t *conn = NULL;

	if (NULL == handle || NULL == val) {
		return CCI_EINVAL;
	}

	CCI_ENTER;

	if (CCI_OPT_LEVEL_ENDPOINT == level) {
		if (handle == NULL
		    || name == CCI_OPT_CONN_SEND_TIMEOUT)
			return CCI_EINVAL;
		ep = container_of(handle, cci__ep_t, endpoint);
		plugin = ep->plugin;
	} else {
		if (handle == NULL
		    || name != CCI_OPT_CONN_SEND_TIMEOUT)
			return CCI_EINVAL;
		conn =
		    container_of(handle, cci__conn_t, connection);
		plugin = conn->plugin;
	}

	switch (name) {
	case CCI_OPT_ENDPT_SEND_TIMEOUT:
		{
			uint32_t *timeout = val;
			*timeout = ep->tx_timeout;
			break;
		}
	case CCI_OPT_ENDPT_RECV_BUF_COUNT:
		{
			uint32_t *count = val;
			*count = ep->rx_buf_cnt;
			break;
		}
	case CCI_OPT_ENDPT_SEND_BUF_COUNT:
		{
			uint32_t *count = val;
			*count = ep->tx_buf_cnt;
			break;
		}
	case CCI_OPT_ENDPT_KEEPALIVE_TIMEOUT:
		{
			uint32_t *timeout = val;
			*timeout = ep->keepalive_timeout;
			break;
		}
	case CCI_OPT_ENDPT_URI:
		{
			char **urip = val;
			char *uri = strdup(ep->uri);
			if (!uri)
				return CCI_ENOMEM;

			*urip = uri;
			break;
		}
	case CCI_OPT_ENDPT_RMA_ALIGN:
		{
			int l = sizeof(cci_alignment_t);
			cci_alignment_t *align = val;
			memcpy(align, &ep->dev->align, l);
			break;
		}
	case CCI_OPT_CONN_SEND_TIMEOUT:
		{
			uint32_t *timeout = val;
			*timeout = conn->tx_timeout;
			break;
		}
	default:
		ret = plugin->get_opt(handle, level, name, val);
	}

	CCI_EXIT;

	return ret;
}
