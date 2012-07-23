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

int cci_sendv(cci_connection_t * connection,
	      const struct iovec *data, uint32_t iovcnt, const void *context, int flags)
{
	cci__conn_t *conn = container_of(connection, cci__conn_t, connection);

	if (NULL == connection)
		return CCI_EINVAL;

	return conn->plugin->sendv(connection, data, iovcnt, context, flags);
}
