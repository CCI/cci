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


int cci_accept(cci_conn_req_t *conn_req, cci_endpoint_t *endpoint, 
               cci_connection_t **connection)
{
    int ret, found = 0;
    cci__ep_t *ep;
    cci__crq_t *crq;
    cci__lep_t *lep;
    cci__dev_t *dev;
    cci_device_t **device;

    if (NULL == conn_req ||
        NULL == endpoint ||
        NULL == connection) {
        return CCI_EINVAL;
    }

    ep = container_of(endpoint, cci__ep_t, endpoint);
    dev = ep->dev;

    /* Check that endpoint is bound to one of the devices in conn_req */
    for (device = (cci_device_t **) conn_req->devices; *device != NULL; device++) {
        cci__dev_t *d = container_of(*device, cci__dev_t, device);
        if (d == dev) {
            found = 1;
            break;
        }
    }
    if (!found)
        return CCI_EINVAL;

    crq = container_of(conn_req, cci__crq_t, conn_req);
    lep = crq->lep;

    ret = cci_core->accept(conn_req, endpoint, connection);
    /* FIXME check return value */

    /* queue crq */
    pthread_mutex_lock(&lep->lock);
    TAILQ_INSERT_HEAD(&lep->crqs, crq, entry);
    pthread_mutex_unlock(&lep->lock);

    return ret;
}
