/*
 * Copyright (c) 2010 Cisco Systems, Inc.  All rights reserved.
 * $COPYRIGHT$
 */

#include "cci/config.h"

#include <stdio.h>

#include "cci.h"
#include "plugins/core/core.h"


int cci_accept(cci_conn_req_t *conn_req, cci_endpoint_t *endpoint, 
               cci_connection_t **connection)
{
    int ret;
    cci__crq_t *crq;
    cci__lep_t *lep;

    if (NULL == conn_req ||
        NULL == endpoint ||
        NULL == connection) {
        return CCI_EINVAL;
    }

    ret = cci_core->accept(conn_req, endpoint, connection);

    /* queue crq */
    crq = container_of(conn_req, cci__crq_t, conn_req);
    lep = crq->lep;
    pthread_mutex_lock(&lep->lock);
    TAILQ_INSERT_HEAD(&lep->crqs, crq, entry);
    pthread_mutex_unlock(&lep->lock);

    return ret;
}
