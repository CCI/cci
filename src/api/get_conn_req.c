/*
 * Copyright (c) 2010 Cisco Systems, Inc.  All rights reserved.
 * $COPYRIGHT$
 */

#include "cci/config.h"

#include <stdio.h>

#include "cci.h"
#include "plugins/core/core.h"


 int cci_get_conn_req(cci_service_t *service, 
                      cci_conn_req_t **conn_req)
{
    cci__svc_t *svc     = NULL;
    cci__crq_t *crq     = NULL;

    if (NULL == service ||
        NULL == conn_req) {
        return CCI_EINVAL;
    }

    svc = container_of(service, cci__svc_t, service);

    pthread_mutex_lock(&svc->lock);
    if (!TAILQ_EMPTY(&svc->crqs)) {
        crq = TAILQ_FIRST(&svc->crqs);
        TAILQ_REMOVE(&svc->crqs, crq, entry);
    }
    pthread_mutex_unlock(&svc->lock);

    if (crq) {
        *conn_req = &crq->conn_req;
        return CCI_SUCCESS;
    } else
        return CCI_EAGAIN;

#if 0
    return cci_core->get_conn_req(service, conn_req);
#endif
}
