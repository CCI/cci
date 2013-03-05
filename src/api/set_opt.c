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

#include "cci/private_config.h"

#include <stdio.h>

#include "cci.h"
#include "plugins/ctp/ctp.h"

int cci_set_opt(cci_opt_handle_t * handle,
		cci_opt_name_t name, const void *val)
{
	cci_plugin_ctp_t *plugin;
	int ret;

	CCI_ENTER;

	if (NULL == handle || NULL == val) {
		return CCI_EINVAL;
	}

	switch (name) {
	case CCI_OPT_ENDPT_SEND_TIMEOUT:
	case CCI_OPT_ENDPT_RECV_BUF_COUNT:
	case CCI_OPT_ENDPT_SEND_BUF_COUNT:
	case CCI_OPT_ENDPT_KEEPALIVE_TIMEOUT:
	case CCI_OPT_ENDPT_URI:
	case CCI_OPT_ENDPT_RMA_ALIGN: {
		cci__ep_t *ep = container_of(handle, cci__ep_t, endpoint);
		plugin = ep->plugin;
		break;
	}
	case CCI_OPT_CONN_SEND_TIMEOUT: {
		cci__conn_t *conn = container_of(handle, cci__conn_t, connection);
		plugin = conn->plugin;
		break;
	}
	}

	ret = plugin->set_opt(handle, name, val);

	CCI_EXIT;

	return ret;
}
