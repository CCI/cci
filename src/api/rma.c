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


int cci_rma(cci_connection_t *connection, 
            void *header_ptr, uint32_t header_len, 
            uint64_t local_handle, uint64_t local_offset, 
            uint64_t remote_handle, uint64_t remote_offset,
            uint64_t data_len, void *context, int flags)
{
    if (NULL == connection ||
        (NULL == header_ptr && header_len > 0)) {
        return CCI_EINVAL;
    }

    return cci_core->rma(connection, header_ptr, header_len,
                         local_handle, local_offset,
                         remote_handle, remote_offset,
                         data_len, context, flags);
}
