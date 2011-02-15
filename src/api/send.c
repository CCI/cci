/*
 * Copyright (c) 2010 Cisco Systems, Inc.  All rights reserved.
 * $COPYRIGHT$
 */

#include "cci/config.h"

#include <stdio.h>

#include "cci.h"
#include "plugins/core/core.h"


int cci_send(cci_connection_t *connection, 
             void *header_ptr, uint32_t header_len, 
             void *data_ptr, uint32_t data_len, 
             void *context, int flags)
{
    if (NULL == connection ||
        (NULL == header_ptr && header_len > 0) ||
        (NULL == data_ptr && data_len > 0)) {
        return CCI_EINVAL;
    }

    return cci_core->send(connection, header_ptr, header_len, 
                          data_ptr, data_len,
                          context, flags);
}
