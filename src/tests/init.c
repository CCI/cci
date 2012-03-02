/*
 * Copyright (c) 2010 Cisco Systems, Inc.  All rights reserved.
 * $COPYRIGHT$
 */

#include <stdio.h>

#include "cci.h"

int main(int argc, char *argv[])
{
	int rc;

/*  This is supposed to fail because we will pass value instead of address. */
	if (CCI_SUCCESS != (rc = cci_init(CCI_ABI_VERSION, 0, 0))) {
		fprintf(stderr, "Got error back from cci:init: %s\n",
			cci_strerror(NULL, rc));
		return -1;
	}

	return 0;
}
