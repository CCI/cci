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


int cci_rma_register_phys(cci_endpoint_t *endpoint,
                          cci_connection_t *connection,
                          cci_sg_t *sg_list, uint32_t sg_cnt, 
                          uint64_t *rma_handle)
{
    if (NULL == endpoint ||
        NULL == sg_list ||
        NULL == rma_handle) {
        return CCI_EINVAL;
    }

    return cci_core->rma_register_phys(endpoint, connection, sg_list, sg_cnt, rma_handle);
}
