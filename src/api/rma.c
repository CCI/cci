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

int cci_rma(cci_connection_t * connection,
	    const void *header_ptr, uint32_t header_len,
	    uint64_t local_handle, uint64_t local_offset,
	    uint64_t remote_handle, uint64_t remote_offset,
	    uint64_t data_len, const void *context, int flags)
{
	cci__conn_t *conn = NULL;

	if (NULL == connection || 0 == data_len) {
		if (NULL == connection)
			debug(CCI_DB_INFO, "%s: NULL connection", __func__);
		if (data_len == 0)
			debug(CCI_DB_INFO, "%s: data_len is 0", __func__);
		return CCI_EINVAL;
	}

	conn = container_of(connection, cci__conn_t, connection);
	if (!cci_conn_is_reliable(conn)) {
		debug(CCI_DB_INFO, "%s: RMA requires a reliable connection",
		      __func__);
		return CCI_EINVAL;
	}

	if (flags & CCI_FLAG_READ && flags & CCI_FLAG_WRITE) {
		debug(CCI_DB_INFO,
		      "%s: RMA requires either CCI_FLAG_READ or CCI_FLAG_WRITE,"
		      " but not both", __func__);
		return CCI_EINVAL;
	}

	if (!(flags & CCI_FLAG_READ || flags & CCI_FLAG_WRITE)) {
		debug(CCI_DB_INFO,
		      "%s: RMA requires either CCI_FLAG_READ or CCI_FLAG_WRITE",
		      __func__);
		return CCI_EINVAL;
	}

	return conn->plugin->rma(connection, header_ptr, header_len,
				 local_handle, local_offset,
				 remote_handle, remote_offset,
				 data_len, context, flags);
}
