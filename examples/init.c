#include <stdio.h>
#include <stdint.h>

#include "cci.h"

int main(int argc, char *argv[])
{
	int ret;
	uint32_t caps;

	ret = cci_init(CCI_ABI_VERSION, 0, &caps);
	if (ret != CCI_SUCCESS)
		fprintf(stderr, "cci_init() returned %s\n", cci_strerror(ret));

	return 0;
}
