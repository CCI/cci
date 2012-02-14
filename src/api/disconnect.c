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

int cci_disconnect(cci_connection_t * connection)
{
	if (NULL == connection) {
		return CCI_EINVAL;
	}

	/* NOTE the driver does all connection cleanup */
	return cci_core->disconnect(connection);
}
