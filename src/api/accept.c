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
    if (NULL == conn_req ||
        NULL == endpoint ||
        NULL == connection || NULL == *connection) {
        return CCI_EINVAL;
    }

    return cci_core->accept(conn_req, endpoint, connection);
}
