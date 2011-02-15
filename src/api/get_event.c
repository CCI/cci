/*
 * Copyright (c) 2010 Cisco Systems, Inc.  All rights reserved.
 * $COPYRIGHT$
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
        NULL == event || NULL == *event) {
        return CCI_EINVAL;
    }

    return cci_core->get_event(endpoint, event, flags);
}
