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


int cci_get_event(cci_endpoint_t *endpoint, 
                  cci_event_t ** const event,
                  uint32_t flags)
{
    if (NULL == endpoint ||
        NULL == event) {
        return CCI_EINVAL;
    }

    return cci_core->get_event(endpoint, event, flags);
}
