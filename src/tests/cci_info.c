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
#include <inttypes.h>

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
		char pcibusid[64] = "", rate[64] = "";
		cci_device_t *device = devices[i];

		if (!device)
			break;

		if (device->pci.domain != -1
		    && device->pci.bus != -1
		    && device->pci.dev != -1
		    && device->pci.func != -1)
			snprintf(pcibusid, sizeof(pcibusid), " %04x:%02x:%02x.%01x",
				 device->pci.domain, device->pci.bus,
				 device->pci.dev, device->pci.func);

		if (device->rate)
			snprintf(rate, sizeof(rate), " %"PRIu64" MBit/s", device->rate / 1000000);

		printf("% 2d: %s%s%s MSS=%u%s%s\n",
		       i, device->name, pcibusid, rate, device->max_send_size,
		       i ? "" : " (default)",
		       device->up ? "" : " (not up)");
	}

	cci_finalize();
	return 0;
}
