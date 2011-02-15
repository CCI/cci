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
    if (NULL == service ||
        NULL == conn_req || NULL == *conn_req) {
        return CCI_EINVAL;
    }

    return cci_core->get_conn_req(service, conn_req);
}
