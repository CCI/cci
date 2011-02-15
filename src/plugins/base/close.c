/*
 * Copyright (c) 2010 Cisco Systems, Inc.  All rights reserved.
 * $COPYRIGHT$
 */

#include "cci.h"

#include "ltdl.h"
#include "plugins/base/public.h"
#include "plugins/base/private.h"
#include "util/argv.h"


/* This is currently never called, but might as well have it to track
   what things would need to be released if we ever do want to shut
   down. */
int cci_plugins_finalize(void)
{
    if (cci_plugins_initialized) {
        lt_dladvise_destroy(&cci_plugins_dladvise);

        if (NULL != cci_plugins_filename_cache) {
            cci_argv_free(cci_plugins_filename_cache);
            cci_plugins_filename_cache = NULL;
        }
    }
    cci_plugins_initialized = 0;

    return CCI_SUCCESS;
}
