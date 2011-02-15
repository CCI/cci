/*
 * Copyright (c) 2010 Cisco Systems, Inc.  All rights reserved.
 * $COPYRIGHT$
 */

#include "cci/config.h"

#include <stdio.h>

#include "cci.h"
#include "plugins/core/core.h"


int cci_bind(cci_device_t *device, int backlog, uint32_t *port, 
             cci_service_t **service, cci_os_handle_t *fd)
{
    if (NULL == device ||
        NULL == port ||
        NULL == service || NULL == *service ||
        NULL == fd) {
        return CCI_EINVAL;
    }

    return cci_core->bind(device, backlog, port, service, fd);
}
