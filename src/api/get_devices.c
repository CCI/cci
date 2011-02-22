/*
 * Copyright (c) 2010 Cisco Systems, Inc.  All rights reserved.
 * $COPYRIGHT$
 */

#include "cci/config.h"

#include <stdio.h>

#include "cci.h"
#include "plugins/core/core.h"


int cci_get_devices(cci_device_t const ***devices)
{
    if (NULL == devices)
        return CCI_EINVAL;

    return cci_core->get_devices(devices);
}
