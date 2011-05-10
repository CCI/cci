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


 int cci_get_conn_req(cci_service_t *service, 
                      cci_conn_req_t **conn_req)
{
    int ret;
    cci__svc_t *svc     = NULL;
    cci__crq_t *crq     = NULL;

    CCI_ENTER;

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
        ret = CCI_SUCCESS;
    } else
        ret = CCI_EAGAIN;

    CCI_EXIT;

    return ret;

    //fprintf( stderr, "Inside cci_get_conn_req\n" );
    //return cci_core->get_conn_req(service, conn_req);
}
