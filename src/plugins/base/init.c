/*
 * Copyright (c) 2010 Cisco Systems, Inc.  All rights reserved.
 * $COPYRIGHT$
 */

#include "cci.h"

#include <stdio.h>
#include <string.h>

#include "ltdl.h"
#include "util/argv.h"
#include "plugins/core/core.h"
#include "plugins/base/public.h"
#include "plugins/base/private.h"


/* Global variables */
int cci_plugins_initialized = 0;
lt_dladvise cci_plugins_dladvise;


int cci_plugins_init(void)
{
    if (cci_plugins_initialized) {
        return CCI_SUCCESS;
    }

    if (0 != lt_dlinit()) {
        fprintf(stderr, "Failed to initialize libltdl: %s\n", lt_dlerror());
        return CCI_ERROR;
    }

    /* Setup the DL advice */
    if (lt_dladvise_init(&cci_plugins_dladvise) ||
        lt_dladvise_ext(&cci_plugins_dladvise) ||
        lt_dladvise_local(&cci_plugins_dladvise)) {
        fprintf(stderr, "Failed to initialize libltdl advise: %s\n", 
                lt_dlerror());
        return CCI_ERROR;
    }

    cci_plugins_recache_files(CCI_PKGLIBDIR, 1);

    cci_plugins_initialized = 1;
    return CCI_SUCCESS;
}
