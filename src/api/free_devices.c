/*
 * Copyright (c) 2010 Cisco Systems, Inc.  All rights reserved.
 * $COPYRIGHT$
 */

#include "cci/config.h"

#include <stdio.h>

#include "cci.h"
#include "plugins/core/core.h"


int cci_free_devices(cci_device_t const **devices)
{
    if (NULL == devices || NULL == *devices) {
        return CCI_EINVAL;
    }

    cci_core->free_devices(devices);

    /* TODO */
    /* for each device
     *     for each endpoint
     *         free it
     *     for each listening endpoint
     *         free it
     *     free it
     */             

    return CCI_SUCCESS;
}
