/*
 * Copyright (c) 2010 Cisco Systems, Inc.  All rights reserved.
 * Copyright © 2011 Inria.  All rights reserved.
 * $COPYRIGHT$
 */

#include "cci/config.h"

#include <stdio.h>

#include "cci.h"
#include "plugins/ctp/ctp.h"

#include "ctp_eth.h"

int cci_ctp_eth_post_load(cci_plugin_t * me)
{
	debug(CCI_DB_DRVR, "In eth post_load");
	return CCI_SUCCESS;
}

int cci_ctp_eth_pre_unload(cci_plugin_t * me)
{
	debug(CCI_DB_DRVR, "In eth pre_unload");
	return CCI_SUCCESS;
}
