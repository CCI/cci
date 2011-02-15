/*
 * Copyright (c) 2010 Cisco Systems, Inc.  All rights reserved.
 * $COPYRIGHT$
 */

#include "cci/config.h"

#include <stdio.h>

#include "cci.h"
#include "plugins/core/core.h"


int cci_set_opt(cci_opt_handle_t *handle, cci_opt_level_t level, 
                cci_opt_name_t name, const void* val, int len)
{
    if (NULL == handle ||
        (NULL == val && len > 0)) {
        return CCI_EINVAL;
    }

    return cci_core->set_opt(handle, level, name, val, len);
}
