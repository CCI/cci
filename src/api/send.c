/*
 * Copyright (c) 2010 Cisco Systems, Inc.  All rights reserved.
 * Copyright © 2010-2011 UT-Battelle, LLC. All rights reserved.
 * Copyright © 2010-2011 Oak Ridge National Labs.  All rights reserved.
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

int cci_send(cci_connection_t * connection,
	     void *msg_ptr, uint32_t msg_len, void *context, int flags)
{
	if (NULL == connection)
		return CCI_EINVAL;

	return cci_core->send(connection, msg_ptr, msg_len, context, flags);
}
