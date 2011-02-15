/*
 * Copyright (c) 2010 Cisco Systems, Inc.  All rights reserved.
 * $COPYRIGHT$
 */

#include "cci.h"

#include "plugins/base/public.h"
#include "plugins/core/core.h"
#include "plugins/core/base/public.h"

/*
 * Public variables
 */
cci_plugin_core_t *cci_core = NULL;
lt_dlhandle cci_plugins_core_handle;


int cci_plugins_core_open(void)
{
    int rc;

    /* This framework only needs 1 plugin */
    rc = cci_plugins_open_one("core", cci_plugins_core_verify,
                              (cci_plugin_t**) &cci_core, 
                              &cci_plugins_core_handle);
    if (CCI_SUCCESS != rc) {
        return rc;
    }

    return CCI_SUCCESS;
}
