/*
 * Copyright (c) 2010 Cisco Systems, Inc.  All rights reserved.
 * $COPYRIGHT$
 */

#include "cci/config.h"

#include <stdio.h>

#include "cci.h"
#include "plugins/core/core.h"


int cci_return_event(cci_endpoint_t *endpoint, cci_event_t *event)
{
    if (NULL == endpoint ||
        NULL == event) {
        return CCI_EINVAL;
    }

    return cci_core->return_event(endpoint, event);
}
