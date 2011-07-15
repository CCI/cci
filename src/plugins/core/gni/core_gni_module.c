/*
 * Copyright (c) 2010 Cisco Systems, Inc.  All rights reserved.
 * $COPYRIGHT$
 */


#include <stdio.h>
#include "cci/config.h"
#include "cci.h"
#include "plugins/core/core.h"
#include "core_gni.h"


int cci_core_gni_post_load(       cci_plugin_t *         me ) {

    assert(me);
    debug( CCI_DB_DRVR, "In gni post_load");
    return CCI_SUCCESS;
}

int cci_core_gni_pre_unload(      cci_plugin_t *         me ) {

    assert(me);
    debug( CCI_DB_DRVR, "In gni pre_unload");
    return CCI_SUCCESS;
}
