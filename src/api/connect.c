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

#include "cci/config.h"

#include <stdio.h>

#include "cci.h"
#include "plugins/core/core.h"

int cci_connect(cci_endpoint_t * endpoint, const char *server_uri,
		const void *data_ptr, uint32_t data_len,
		cci_conn_attribute_t attribute,
		const void *context, int flags, const struct timeval *timeout)
{
	if (data_len > CCI_CONN_REQ_LEN)
		return CCI_EINVAL;

	/* NOTE the driver does all of the connection management
	 * It allocates whatever it needs in addition to the cci__conn_t
	 */
	cci__ep_t *ep = container_of(endpoint, cci__ep_t, endpoint);
	return ep->plugin->connect(endpoint, server_uri, data_ptr, data_len,
				   attribute, context, flags, timeout);
}
