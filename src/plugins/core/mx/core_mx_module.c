/*
 * Copyright (c) 2010 Cisco Systems, Inc.  All rights reserved.
 * $COPYRIGHT$
 */

#include "cci/config.h"

#include <stdio.h>

#include "cci.h"
#include "plugins/core/core.h"

#include "core_mx.h"


int cci_core_mx_post_load(cci_plugin_t *me)
{
    debug( CCI_DB_DRVR, "In mx post_load");
    return CCI_SUCCESS;
}

int cci_core_mx_pre_unload(cci_plugin_t *me)
{
    debug( CCI_DB_DRVR, "In mx pre_unload");
    return CCI_SUCCESS;
}
