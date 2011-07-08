/*
 * Copyright (c) 2011 Cisco Systems, Inc.  All rights reserved.
 * Copyright (c) 2011 UT-Battelle, LLC.  All rights reserved.
 * $COPYRIGHT$
 */

#include "cci/config.h"

#include <stdio.h>

#include "cci.h"
#include "plugins/core/core.h"

#include "core_portals.h"


int cci_core_portals_post_load(cci_plugin_t *me)
{
    debug( CCI_DB_DRVR, "In portals post_load");
    return CCI_SUCCESS;
}

int cci_core_portals_pre_unload(cci_plugin_t *me)
{
    debug( CCI_DB_DRVR, "In portals pre_unload");
    return CCI_SUCCESS;
}
