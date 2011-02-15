/*
 * Copyright (c) 2010 Cisco Systems, Inc.  All rights reserved.
 * $COPYRIGHT$
 */

#include "cci/config.h"

#include "cci.h"
#include "plugins/core/core.h"


int cci_rma_deregister(uint64_t rma_handle)
{
    return cci_core->rma_deregister(rma_handle);
}
