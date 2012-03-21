/*
 * Copyright © 2012 inria.  All rights reserved.
 *
 * See COPYING in top-level directory
 *
 * $COPYRIGHT$
 *
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>

#include "cci.h"

int main(int argc, char *argv[])
{
        int ret, i;
        uint32_t caps = 0;
        cci_device_t * const *devices;

        ret = cci_init(CCI_ABI_VERSION, 0, &caps);
        if (ret) {
                fprintf(stderr, "cci_init() failed with %s\n",
                        cci_strerror(NULL, ret));
                exit(EXIT_FAILURE);
        }

	ret = cci_get_devices(&devices);
        if (ret) {
                fprintf(stderr, "cci_get_devices() failed with %s\n",
                        cci_strerror(NULL, ret));
                exit(EXIT_FAILURE);
        }

	for(i=0; ; i++)
		if (!devices[i])
			break;
	printf("Found %d CCI devices%s\n", i, i?":":".");
	for(i=0; ; i++) {
		if (!devices[i])
			break;
		printf("% 2d: %s%s%s\n",
		       i, devices[i]->name,
		       i ? "" : " (default)",
		       devices[i]->up ? "" : " (not up)");
	}

	cci_finalize();
	return 0;
}
