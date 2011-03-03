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
    printf("In portals post_load\n");
    return CCI_SUCCESS;
}

int cci_core_portals_pre_unload(cci_plugin_t *me)
{
    printf("In portals pre_unload\n");
    return CCI_SUCCESS;
}
