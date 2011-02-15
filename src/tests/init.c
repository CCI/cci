/*
 * Copyright (c) 2010 Cisco Systems, Inc.  All rights reserved.
 * $COPYRIGHT$
 */

#include <stdio.h>

#include "cci.h"


int main(int argc, char* argv[])
{
    int rc;

    if (CCI_SUCCESS != (rc = cci_init(CCI_ABI_VERSION, 0, 0))) {
        fprintf(stderr, "Got error back from cci:init: %d\n", rc);
        return -1;
    }

    return 0;
}
