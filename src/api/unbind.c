/*
 * Copyright (c) 2010 Cisco Systems, Inc.  All rights reserved.
 * $COPYRIGHT$
 */

#include "cci/config.h"

#include <stdio.h>

#include "cci.h"
#include "plugins/core/core.h"


int cci_unbind(cci_service_t *service, cci_device_t *device)
{
    if (NULL == service ||
        NULL == device) {
        return CCI_EINVAL;
    }

    return cci_core->unbind(service, device);
}
