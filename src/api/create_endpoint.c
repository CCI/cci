/*
 * Copyright (c) 2010 Cisco Systems, Inc.  All rights reserved.
 * $COPYRIGHT$
 */

#include "cci/config.h"

#include <stdio.h>
#include <stdlib.h>

#include "cci.h"
#include "cci_lib_types.h"
#include "plugins/core/core.h"

int cci_create_endpoint(cci_device_t *device, 
                        int flags, 
                        cci_endpoint_t **endpoint, 
                        cci_os_handle_t *fd)
{
    int ret;
    cci__ep_t *ep;
    cci__dev_t *dev;

    if (NULL == endpoint ||
        NULL == fd) {
        return CCI_EINVAL;
    }

    if (NULL == device) {
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

    dev = container_of(device, cci__dev_t, device);
    if (dev->is_up == 0)
        return CCI_ENODEV;

    ep = calloc(1, sizeof(*ep));
    if (!ep)
        return CCI_ENOMEM;

    TAILQ_INIT(&ep->evts);
    pthread_mutex_init(&ep->lock, NULL);
    ep->dev = dev;
    *endpoint = &ep->endpoint;

    ret = cci_core->create_endpoint(device, flags, endpoint, fd);

    pthread_mutex_lock(&dev->lock);
    /* TODO check dev's state */
    TAILQ_INSERT_TAIL(&dev->eps, ep, entry);
    pthread_mutex_unlock(&dev->lock);

    return ret;
}
