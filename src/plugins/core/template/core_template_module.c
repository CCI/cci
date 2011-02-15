/*
 * Copyright (c) 2010 Cisco Systems, Inc.  All rights reserved.
 * $COPYRIGHT$
 */

#include "cci/config.h"

#include <stdio.h>

#include "cci.h"
#include "plugins/core/core.h"

#include "core_template.h"


int cci_core_template_post_load(cci_plugin_t *me)
{
    printf("In template post_load\n");
    return CCI_SUCCESS;
}

int cci_core_template_pre_unload(cci_plugin_t *me)
{
    printf("In template pre_unload\n");
    return CCI_SUCCESS;
}
