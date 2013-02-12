/*
 * Copyright (c) 2010 Cisco Systems, Inc.  All rights reserved.
 * $COPYRIGHT$
 */

#include "cci/private_config.h"
#include "cci.h"
#include "plugins/ctp/ctp.h"
#include "ctp_gni.h"

int cci_ctp_gni_post_load(cci_plugin_t * me)
{

	assert(me);
	debug(CCI_DB_CTP, "%s", "In gni post_load");
	return CCI_SUCCESS;
}

int cci_ctp_gni_pre_unload(cci_plugin_t * me)
{

	assert(me);
	debug(CCI_DB_CTP, "%s", "In gni pre_unload");
	return CCI_SUCCESS;
}
