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


int cci_connect(cci_endpoint_t *endpoint, char *server_uri, 
                uint32_t port,
                void *data_ptr, uint32_t data_len, 
                cci_conn_attribute_t attribute,
                void *context, int flags, struct timeval *timeout)
{
    if (NULL == endpoint ||
        NULL == server_uri ||
        (NULL == data_ptr && data_len > 0)) {
        return CCI_EINVAL;
    }

    return cci_core->connect(endpoint, server_uri, port, data_ptr, data_len,
                             attribute, context, flags, timeout);
}
