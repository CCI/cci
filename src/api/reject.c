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

int cci_reject(cci_event_t *conn_req)
{
	cci__evt_t *ev = container_of(conn_req, cci__evt_t, event);
	return ev->ep->plugin->reject(conn_req);
}
