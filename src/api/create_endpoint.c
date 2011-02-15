/*
 * Copyright (c) 2010 Cisco Systems, Inc.  All rights reserved.
 * $COPYRIGHT$
 */

#include "cci/config.h"

#include <stdio.h>

#include "cci.h"
#include "plugins/core/core.h"


int cci_create_endpoint(cci_device_t *device, 
                        int flags, 
                        cci_endpoint_t **endpoint, 
                        cci_os_handle_t *fd)
{
    if (NULL == device ||
        NULL == endpoint || NULL == *endpoint ||
        NULL == fd) {
        return CCI_EINVAL;
    }

    return cci_core->create_endpoint(device, flags, endpoint, fd);
}
