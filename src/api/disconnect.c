/*
 * Copyright (c) 2010 Cisco Systems, Inc.  All rights reserved.
 * $COPYRIGHT$
 */

#include "cci/config.h"

#include <stdio.h>

#include "cci.h"
#include "plugins/core/core.h"


int cci_disconnect(cci_connection_t *connection)
{
    if (NULL == connection) {
        return CCI_EINVAL;
    }

    return cci_core->disconnect(connection);
}
