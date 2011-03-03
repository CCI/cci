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


const char *cci_strerror(enum cci_status status)
{
    switch (status) {
    case CCI_SUCCESS:
        return "CCI_SUCCESS";

    case CCI_ERROR:
        return "CCI_ERROR";

    case CCI_ERR_DISCONNECTED:
        return "CCI_ERR_DISCONNECTED";

    case CCI_ERR_RNR:
        return "CCI_ERR_RNR";

    case CCI_ERR_DEVICE_DEAD:
        return "CCI_ERR_DEVICE_DEAD";

    case CCI_ERR_RMA_HANDLE:
        return "CCI_ERR_RMA_HANDLE";

    case CCI_ERR_RMA_OP:
        return "CCI_ERR_RMA_OP";

    case CCI_ERR_NOT_IMPLEMENTED:
        return "CCI_ERR_NOT_IMPLEMENTED";

    case CCI_ERR_NOT_FOUND:
        return "CCI_ERR_NOT_FOUND";

    case CCI_EINVAL:
        return "CCI_EINVAL";

    case CCI_ETIMEDOUT:
        return "CCI_ETIMEDOUT";

    case CCI_ENOMEM:
        return "CCI_ENOMEM";

    default:
        return cci_core->strerror(status);
    }
}
