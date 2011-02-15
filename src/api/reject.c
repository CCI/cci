/*
 * Copyright (c) 2010 Cisco Systems, Inc.  All rights reserved.
 * $COPYRIGHT$
 */

#include "cci/config.h"

#include <stdio.h>

#include "cci.h"
#include "plugins/core/core.h"


int cci_reject(cci_conn_req_t *conn_req)
{
    if (NULL == conn_req) {
        return CCI_EINVAL;
    }

    return cci_core->reject(conn_req);
}
