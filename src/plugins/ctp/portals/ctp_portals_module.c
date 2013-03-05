/*
 * Copyright (c) 2011 Cisco Systems, Inc.  All rights reserved.
 * Copyright (c) 2011 UT-Battelle, LLC.  All rights reserved.
 * $COPYRIGHT$
 */

#include "cci/private_config.h"

#include <stdio.h>

#include "cci.h"
#include "plugins/ctp/ctp.h"

#include "ctp_portals.h"

int cci_ctp_portals_post_load(cci_plugin_t * me)
{
	assert(me);
	debug(CCI_DB_CTP, "%s", "In portals post_load");
	return CCI_SUCCESS;
}

int cci_ctp_portals_pre_unload(cci_plugin_t * me)
{
	assert(me);
	debug(CCI_DB_CTP, "%s", "In portals pre_unload");
	return CCI_SUCCESS;
}
