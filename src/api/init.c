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

cci__globals_t *globals = NULL;

int cci_init(uint32_t abi_ver, uint32_t flags, uint32_t *caps)
{
    int ret;
    static int once = 0;

    if (abi_ver != CCI_ABI_VERSION) {
        fprintf(stderr, "cci_init: got ABI version %d, but expected %d\n",
                abi_ver, CCI_ABI_VERSION);
        return CCI_EINVAL;
    }

    if (0 == once) {
        once++;

        if (CCI_SUCCESS != (ret = cci_plugins_init())) {
            return ret;
        }
        if (CCI_SUCCESS != (ret = cci_plugins_core_open())) {
            return ret;
        }
        if (NULL == cci_core) {
            return CCI_ERR_NOT_FOUND;
        }
    } else {
        /* TODO */
        /* check parameters */
        /* if same, this is a no-op and return SUCCESS */
        /* if different, can we accomodate new params?
         *    if yes, do so and return SUCCESS
         *    if not, ignore and return CCI_ERROR
         */
        return CCI_ERR_NOT_IMPLEMENTED;
    }

    return cci_core->init(abi_ver, flags, caps);
}

