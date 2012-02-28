#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>

#include "cci.h"

int main(int argc, char *argv[])
{
	int ret, i = 0;
	uint32_t caps;
	cci_device_t const **const devices, **d;

	ret = cci_init(CCI_ABI_VERSION, 0, &caps);
	if (ret != CCI_SUCCESS) {
		fprintf(stderr, "cci_init() returned %s\n", cci_strerror(ret));
		exit(EXIT_FAILURE);
	}

	ret = cci_get_devices((cci_device_t const ***const)&devices);
	if (ret != CCI_SUCCESS) {
		fprintf(stderr, "cci_get_devices() returned %s\n",
			cci_strerror(ret));
		exit(EXIT_FAILURE);
	}

	for (d = devices; *d != NULL; d++) {
		char **keyval;

		printf("device %d is %s\n", i, (*d)->name);
		i++;
		for (keyval = (char **)(*d)->conf_argv; *keyval != NULL;
		     keyval++)
			printf("\t%s\n", *keyval);
	}

	/* Add cci_finalize() here */

	return 0;
}
