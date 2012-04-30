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

int cci_get_opt(void * handle, cci_opt_name_t name, cci_opt_t *val)
{
	cci_plugin_core_t * plugin;
	int ret = CCI_SUCCESS;
	cci__ep_t *ep = NULL;
	cci__conn_t *conn = NULL;

	if (NULL == handle || NULL == val) {
		return CCI_EINVAL;
	}

	CCI_ENTER;

	if (CCI_OPT_CONN_SEND_TIMEOUT == name) {
		conn =
		    container_of((cci_connection_t*)handle, cci__conn_t, connection);
		plugin = conn->plugin;
	} else {
		ep = container_of((cci_endpoint_t *)handle, cci__ep_t, endpoint);
		plugin = ep->plugin;
	}

	switch (name) {
	case CCI_OPT_ENDPT_SEND_TIMEOUT:
		{
			val->endpt_send_timeout = ep->tx_timeout;
			break;
		}
	case CCI_OPT_ENDPT_RECV_BUF_COUNT:
		{
			val->endpt_recv_buf_count = ep->rx_buf_cnt;
			break;
		}
	case CCI_OPT_ENDPT_SEND_BUF_COUNT:
		{
			val->endpt_send_buf_count = ep->tx_buf_cnt;
			break;
		}
	case CCI_OPT_ENDPT_KEEPALIVE_TIMEOUT:
		{
			val->endpt_keepalive_timeout = ep->keepalive_timeout;
			break;
		}
	case CCI_OPT_ENDPT_URI:
		{
			val->endpt_uri = ep->uri;
			break;
		}
	case CCI_OPT_ENDPT_RMA_ALIGN:
		{
			memcpy((void *)&val->endpt_rma_align,
					(void*)&ep->dev->align, sizeof(ep->dev->align));
			break;
		}
	case CCI_OPT_CONN_SEND_TIMEOUT:
		{
			val->conn_send_timeout = conn->tx_timeout;
			break;
		}
	}

	CCI_EXIT;

	return ret;
}
