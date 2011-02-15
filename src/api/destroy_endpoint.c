/*
 * Copyright (c) 2010 Cisco Systems, Inc.  All rights reserved.
 * $COPYRIGHT$
 */

#include "cci/config.h"

#include <stdio.h>

#include "cci.h"
#include "plugins/core/core.h"


int cci_destroy_endpoint(cci_endpoint_t *endpoint)
{
    if (NULL == endpoint) {
        return CCI_EINVAL;
    }

    return cci_core->destroy_endpoint(endpoint);
}
