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


int cci_unbind(cci_service_t *service, cci_device_t *device)
{
    int         ret     = CCI_SUCCESS;
    int         found   = 0;
    cci__dev_t  *dev    = NULL;
    cci__lep_t  *lep    = NULL;
    cci__svc_t  *svc    = NULL;

    if (NULL == service ||
        NULL == device) {
        return CCI_EINVAL;
    }

    /* does this device have a listening endpoint bound to this service? */
    dev = container_of(device, cci__dev_t, device);
    svc = container_of(service, cci__svc_t, service);

    pthread_mutex_lock(&svc->lock);
    TAILQ_FOREACH(lep, &svc->leps, sentry) {
        if (lep->dev == dev) {
            found = 1;
            lep->state = CCI_LEP_CLOSING;
            break;
        }
    }
    pthread_mutex_unlock(&svc->lock);

    if (!found)
        return CCI_ENODEV;

    /* let the driver cleanup up its private svc, lep and crqs */
    ret = cci_core->unbind(service, device);

    /* unlink listening endpoint */
    pthread_mutex_lock(&dev->lock);
    TAILQ_REMOVE(&dev->leps, lep, dentry);
    pthread_mutex_unlock(&dev->lock);

    pthread_mutex_lock(&svc->lock);
    TAILQ_REMOVE(&svc->leps, lep, sentry);
    pthread_mutex_unlock(&svc->lock);

    while (!TAILQ_EMPTY(&lep->all_crqs)) {
        cci__crq_t *crq = TAILQ_FIRST(&lep->all_crqs);
        TAILQ_REMOVE(&lep->all_crqs, crq, lentry);
        free(crq);
    }
    free(lep);

    /* if the svc has no more leps, do we free it? */
    pthread_mutex_lock(&globals->lock);
    pthread_mutex_lock(&svc->lock);
    if (TAILQ_EMPTY(&svc->leps)) {
        TAILQ_REMOVE(&globals->svcs, svc, entry);
        pthread_mutex_unlock(&svc->lock);
        free(svc);
    }
    pthread_mutex_unlock(&globals->lock);

    return ret;
}
