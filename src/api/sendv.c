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
    int i = 0;

    if (NULL == connection ||
        (NULL == data && iovcnt > 0)) {
        return CCI_EINVAL;
    }

    for (i = 0; i < iovcnt; i++) {
        if (data[i].iov_base && data[i].iov_len == 0) {
            debug(CCI_DB_INFO, "%s: data[%d] has a pointer but no length",
                               __func__, i);
            return CCI_EINVAL;
        }
        if (!data[i].iov_base && data[i].iov_len > 0) {
            debug(CCI_DB_INFO, "%s: data[%d] has a length but no pointer",
                               __func__, i);
            return CCI_EINVAL;
        }
        if (!data[i].iov_base && data[i].iov_len == 0) {
            debug(CCI_DB_INFO, "%s: data[%d] has no pointer or length",
                               __func__, i);
            return CCI_EINVAL;
        }
    }

    return cci_core->sendv(connection, data, iovcnt, context, flags);
}
