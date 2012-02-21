/*
 * Copyright (c) 2010 Cisco Systems, Inc.  All rights reserved.
 * Copyright © 2010-2012 UT-Battelle, LLC. All rights reserved.
 * Copyright © 2010-2012 Oak Ridge National Labs.  All rights reserved.
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

int cci_connect(cci_endpoint_t * endpoint, char *server_uri,
		void *data_ptr, uint32_t data_len,
		cci_conn_attribute_t attribute,
		void *context, int flags, struct timeval *timeout)
{
	/* NOTE the driver does all of the connection management
	 * It allocates whatever it needs in addition to the cci__conn_t
	 */
	return cci_core->connect(endpoint, server_uri, data_ptr, data_len,
				 attribute, context, flags, timeout);
}
