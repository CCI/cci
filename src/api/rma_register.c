/*
 * Copyright (c) 2010 Cisco Systems, Inc.  All rights reserved.
 * $COPYRIGHT$
 */

#include "cci/config.h"

#include <stdio.h>

#include "cci.h"
#include "plugins/core/core.h"


int cci_rma_register(cci_endpoint_t *endpoint, void *start, 
                     uint64_t length, uint64_t *rma_handle)
{
    if (NULL == endpoint ||
        NULL == rma_handle) {
        return CCI_EINVAL;
    }

    return cci_core->rma_register(endpoint, start, length, rma_handle);
}
