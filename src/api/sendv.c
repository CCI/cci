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
              void *header_ptr, uint32_t header_len, 
              char **data_ptrs, int *data_lens,
              uint8_t segment_cnt, void *context, int flags)
{
    if (NULL == connection ||
        (NULL == header_ptr && header_len > 0) ||
        ((NULL == data_ptrs || NULL == data_lens) && segment_cnt > 0)) {
        return CCI_EINVAL;
    }

    return cci_core->sendv(connection, header_ptr, header_len, 
                           data_ptrs, data_lens,
                           segment_cnt, context, flags);
}
