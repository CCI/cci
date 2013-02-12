/*
 * Copyright (c) 2010 Cisco Systems, Inc.  All rights reserved.
 * $COPYRIGHT$
 */

#include "cci/config.h"

#include <stdio.h>

#include "cci.h"
#include "plugins/ctp/ctp.h"

#include "ctp_verbs.h"

int cci_ctp_verbs_post_load(cci_plugin_t * me)
{
	debug(CCI_DB_CTP, "%s", "In verbs post_load");
	return CCI_SUCCESS;
}

int cci_ctp_verbs_pre_unload(cci_plugin_t * me)
{
	debug(CCI_DB_CTP, "%s", "In verbs pre_unload");
	return CCI_SUCCESS;
}
