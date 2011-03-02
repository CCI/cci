/*
 * Copyright (c) 2010 Cisco Systems, Inc.  All rights reserved.
 * $COPYRIGHT$
 */

#include "cci/config.h"

#include <stdio.h>
#include <stdlib.h>

#include "cci.h"
#include "plugins/core/core.h"


int cci_bind(cci_device_t *device, int backlog, uint32_t *port, 
             cci_service_t **service, cci_os_handle_t *fd)
{
    int i, ret;
    cci__dev_t *dev;
    cci__svc_t *svc;
    cci__lep_t *lep;

    if (NULL == device ||
        NULL == port ||
        NULL == service ||
        NULL == fd ||
        0 == backlog) {
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

    /* do we have a service for this port? */
    if (*port) {
        TAILQ_FOREACH(svc, &globals->svcs, entry) {
            if (svc->port == *port) {
                *service = &svc->service;
                break;
            }
        }
    }

    /* if no service, create one */
    if (NULL == *service) {
        svc = calloc(1, sizeof(*svc));
        if (!svc) {
            return CCI_ENOMEM;
        }
        svc->service.bogus = -1; /* why not? */
        TAILQ_INIT(&svc->leps);
        TAILQ_INIT(&svc->crqs);
        pthread_mutex_init(&svc->lock, NULL);

        /* create a listening port */
        lep = calloc(1, sizeof(*lep));
        if (!lep) {
            ret = CCI_ENOMEM;
            goto out;
        }
        TAILQ_INIT(&lep->crqs);
        pthread_mutex_init(&lep->lock, NULL);
        lep->backlog = backlog;

        /* alloc connection requests */
        for (i = 0; i < backlog; i++) {
            cci__crq_t *crq;

            crq = calloc(1, sizeof(*crq));
            if (!crq) {
                ret = CCI_ENOMEM;
                goto out;
            }
            crq->lep = lep;
            /* the driver fills in the cci_conn_req_t */
            TAILQ_INSERT_TAIL(&lep->crqs, crq, entry);
        }

        /* add endpoint to dev and svc */
        lep->svc = svc;
        pthread_mutex_lock(&svc->lock);
        TAILQ_INSERT_TAIL(&svc->leps, lep, sentry);
        pthread_mutex_unlock(&svc->lock);
        lep->dev = dev;
        pthread_mutex_lock(&dev->lock);
        TAILQ_INSERT_TAIL(&dev->leps, lep, dentry);
        pthread_mutex_unlock(&dev->lock);

        /* find port & add to globals->svcs */
        if (*port)
            svc->port = *port;
        pthread_mutex_lock(&globals->lock);
        ret = cci__get_svc_port(&svc->port);
        if (ret) {
            pthread_mutex_unlock(&globals->lock);
            goto out;
        }
        TAILQ_INSERT_TAIL(&globals->svcs, svc, entry);
        pthread_mutex_unlock(&globals->lock);
        *service = &svc->service;
        *port = svc->port;
    }

    ret =  cci_core->bind(device, backlog, port, service, fd);
    if (ret)
        goto out_w_remove;

    return CCI_SUCCESS;

out_w_remove:
    pthread_mutex_lock(&globals->lock);
    TAILQ_REMOVE(&globals->svcs, svc, entry);
    pthread_mutex_unlock(&globals->lock);
out:
    if (lep) {
        cci__crq_t *crq;

        if (lep->dev)
            TAILQ_REMOVE(&dev->leps, lep, dentry);

        while (!TAILQ_EMPTY(&lep->crqs)) {
            crq = TAILQ_FIRST(&lep->crqs);
            TAILQ_REMOVE(&lep->crqs, crq, entry);
            free(crq);
        }
        free(lep);
    }
    if (svc)
        free(svc);

    return ret;
}
