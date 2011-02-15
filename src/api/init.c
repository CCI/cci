/*
 * Copyright (c) 2010 Cisco Systems, Inc.  All rights reserved.
 * $COPYRIGHT$
 */

#include "cci/config.h"

#include <stdio.h>

#include "cci.h"
#include "plugins/base/public.h"
#include "plugins/core/core.h"
#include "plugins/core/base/public.h"


int cci_init(uint32_t abi_ver, uint32_t flags, uint32_t *caps)
{
    int ret;

    if (abi_ver != CCI_ABI_VERSION) {
        fprintf(stderr, "cci_init: got ABI version %d, but expected %d\n",
                abi_ver, CCI_ABI_VERSION);
        return CCI_EINVAL;
    }

    if (CCI_SUCCESS != (ret = cci_plugins_init())) {
        return ret;
    }
    if (CCI_SUCCESS != (ret = cci_plugins_core_open())) {
        return ret;
    }
    if (NULL == cci_core) {
        return CCI_ERR_NOT_FOUND;
    }

    return cci_core->init(abi_ver, flags, caps);
}

