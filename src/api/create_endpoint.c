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
    if (NULL == endpoint ||
        NULL == fd) {
        return CCI_EINVAL;
    }

    if (NULL == device) {
        cci__dev_t *dev;

        /* walk list of devs to find default device */
        TAILQ_FOREACH(dev, &globals->devs, entry) {
            if (dev->is_default) {
                device = &dev->device;
                break;
            }
        }
        if (!device) {
            /* no default found, use first (highest priority) device? */
            dev = TAILQ_FIRST(&globals->devs);
            device = &dev->device;
        }
    }
    if (!device)
        return CCI_ENODEV;

    return cci_core->create_endpoint(device, flags, endpoint, fd);
}
