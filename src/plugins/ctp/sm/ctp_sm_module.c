/*
 * Copyright (c) 2010 Cisco Systems, Inc.  All rights reserved.
 * $COPYRIGHT$
 */

#include "cci/private_config.h"

#include <stdio.h>

#include "cci.h"
#include "plugins/ctp/ctp.h"

#include "ctp_sm.h"

int cci_ctp_sm_post_load(cci_plugin_t * me)
{
	debug(CCI_DB_CTP, "%s", "In sm post_load");
	return CCI_SUCCESS;
}

int cci_ctp_sm_pre_unload(cci_plugin_t * me)
{
	debug(CCI_DB_CTP, "%s", "In sm pre_unload");
	return CCI_SUCCESS;
}
