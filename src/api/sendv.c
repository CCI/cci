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


int cci_sendv(cci_connection_t *connection,
              struct iovec *data, uint8_t iovcnt,
              void *context, int flags)
{
    if (NULL == connection)
        return CCI_EINVAL;

    return cci_core->sendv(connection, data, iovcnt, context, flags);
}
