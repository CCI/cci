/*
 * Copyright (c) 2010 Cisco Systems, Inc.  All rights reserved.
 * Copyright © 2010-2011 UT-Battelle, LLC. All rights reserved.
 * Copyright © 2010-2011 Oak Ridge National Labs.  All rights reserved.
 *
 * See COPYING in top-level directory
 *
 * $COPYRIGHT$
 *
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
