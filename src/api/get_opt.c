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


int cci_get_opt(cci_opt_handle_t *handle, cci_opt_level_t level, 
                cci_opt_name_t name, void** val, int *len)
{
    if (NULL == handle ||
        NULL == val || NULL == *val ||
        NULL == len) {
        return CCI_EINVAL;
    }

    return cci_core->get_opt(handle, level, name, val, len);
}
