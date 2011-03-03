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


int cci_arm_os_handle(cci_endpoint_t *endpoint, int flags)
{
    if (NULL == endpoint) {
        return CCI_EINVAL;
    }

    return cci_core->arm_os_handle(endpoint, flags);
}
