/*
 * Copyright (c) 2010 Cisco Systems, Inc.  All rights reserved.
 * Copyright (c) 2013 UT-Battelle, LLC.  All rights reserved.
 * $COPYRIGHT$
 */

#include "cci/private_config.h"

#include "cci.h"
#include "plugins/ctp/ctp.h"

#include "ctp_e2e.h"

int cci_ctp_e2e_post_load(cci_plugin_t * me)
{
	debug(CCI_DB_CTP, "%s", "In e2e post_load");
	return CCI_SUCCESS;
}

int cci_ctp_e2e_pre_unload(cci_plugin_t * me)
{
	debug(CCI_DB_CTP, "%s", "In e2e pre_unload");
	return CCI_SUCCESS;
}
