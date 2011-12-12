/*
 * Copyright (c) 2010 Cisco Systems, Inc.  All rights reserved.
 * $COPYRIGHT$
 */

#include "cci/config.h"

#include <stdio.h>

#include "cci.h"
#include "plugins/core/core.h"

#include "core_verbs.h"


int cci_core_verbs_post_load(cci_plugin_t *me)
{
    debug( CCI_DB_DRVR, "In verbs post_load");
    return CCI_SUCCESS;
}

int cci_core_verbs_pre_unload(cci_plugin_t *me)
{
    debug( CCI_DB_DRVR, "In verbs pre_unload");
    return CCI_SUCCESS;
}
